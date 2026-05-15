library(data.table)

UNIFIED_FLOW_COLUMNS <- c(
  "event_id",
  "ingest_run_id",
  "source_dataset",
  "source_key",
  "source_file_name",
  "source_format",
  "handler_name",
  "source_record_index",
  "flow_id",
  "flow_start",
  "flow_end",
  "duration_sec",
  "src_ip",
  "src_port",
  "dst_ip",
  "dst_port",
  "ip_version",
  "transport_proto",
  "app_proto",
  "flow_state",
  "direction",
  "packets_total",
  "packets_src",
  "packets_dst",
  "bytes_total",
  "bytes_src",
  "bytes_dst",
  "src_ttl",
  "dst_ttl",
  "rtt_sec",
  "synack_sec",
  "ackdat_sec",
  "source_label",
  "attack_category",
  "is_malicious",
  "attributes_json"
)

empty_network_flows <- function() {
  data.frame(
    event_id = character(),
    ingest_run_id = character(),
    source_dataset = character(),
    source_key = character(),
    source_file_name = character(),
    source_format = character(),
    handler_name = character(),
    source_record_index = integer(),
    flow_id = character(),
    flow_start = as.POSIXct(character(), tz = "UTC"),
    flow_end = as.POSIXct(character(), tz = "UTC"),
    duration_sec = numeric(),
    src_ip = character(),
    src_port = integer(),
    dst_ip = character(),
    dst_port = integer(),
    ip_version = character(),
    transport_proto = character(),
    app_proto = character(),
    flow_state = character(),
    direction = character(),
    packets_total = numeric(),
    packets_src = numeric(),
    packets_dst = numeric(),
    bytes_total = numeric(),
    bytes_src = numeric(),
    bytes_dst = numeric(),
    src_ttl = integer(),
    dst_ttl = integer(),
    rtt_sec = numeric(),
    synack_sec = numeric(),
    ackdat_sec = numeric(),
    source_label = character(),
    attack_category = character(),
    is_malicious = logical(),
    attributes_json = character(),
    stringsAsFactors = FALSE
  )
}

make_event_ids <- function(source_key, source_file_name, source_record_index) {
  key_part <- gsub("[^A-Za-z0-9_./-]", "_", safe_character(source_key))
  file_part <- gsub("[^A-Za-z0-9_./-]", "_", safe_character(source_file_name))
  index_part <- safe_integer(source_record_index)
  index_part[is.na(index_part) | index_part <= 0L] <- seq_along(index_part)[is.na(index_part) | index_part <= 0L]

  paste0(key_part, "::", file_part, "#", index_part)
}

base_unified_frame <- function(n, source_object, ingest_run_id, handler_name, source_format = NULL) {
  if (n == 0) {
    return(empty_network_flows())
  }

  source_file_name <- if ("source_file_name" %in% names(source_object) &&
    nzchar(safe_character(source_object$source_file_name[[1]]))) {
    safe_character(source_object$source_file_name[[1]])
  } else {
    basename(source_object$key[[1]])
  }

  source_record_index <- seq_len(n)

  frame <- data.frame(
    event_id = make_event_ids(source_object$key[[1]], rep(source_file_name, n), source_record_index),
    ingest_run_id = rep(ingest_run_id, n),
    source_dataset = rep(source_object$dataset_name, n),
    source_key = rep(source_object$key, n),
    source_file_name = rep(source_file_name, n),
    source_format = rep(source_format %||% source_object$extension, n),
    handler_name = rep(handler_name, n),
    source_record_index = source_record_index,
    flow_id = rep("", n),
    flow_start = as.POSIXct(rep(NA_real_, n), origin = "1970-01-01", tz = "UTC"),
    flow_end = as.POSIXct(rep(NA_real_, n), origin = "1970-01-01", tz = "UTC"),
    duration_sec = rep(NA_real_, n),
    src_ip = rep("", n),
    src_port = rep(NA_integer_, n),
    dst_ip = rep("", n),
    dst_port = rep(NA_integer_, n),
    ip_version = rep("", n),
    transport_proto = rep("", n),
    app_proto = rep("", n),
    flow_state = rep("", n),
    direction = rep("", n),
    packets_total = rep(NA_real_, n),
    packets_src = rep(NA_real_, n),
    packets_dst = rep(NA_real_, n),
    bytes_total = rep(NA_real_, n),
    bytes_src = rep(NA_real_, n),
    bytes_dst = rep(NA_real_, n),
    src_ttl = rep(NA_integer_, n),
    dst_ttl = rep(NA_integer_, n),
    rtt_sec = rep(NA_real_, n),
    synack_sec = rep(NA_real_, n),
    ackdat_sec = rep(NA_real_, n),
    source_label = rep("", n),
    attack_category = rep("", n),
    is_malicious = rep(NA, n),
    attributes_json = rep("{}", n),
    stringsAsFactors = FALSE
  )

  frame
}

infer_attack_category <- function(labels) {
  labels_chr <- tolower(trimws(safe_character(labels)))
  result <- rep("", length(labels_chr))
  result[grepl("botnet|malware|attack|exploit", labels_chr)] <- "malicious"
  result[grepl("background|normal|benign", labels_chr)] <- "benign"
  result
}

infer_malicious_flag <- function(labels) {
  labels_chr <- tolower(trimws(safe_character(labels)))
  result <- rep(NA, length(labels_chr))
  result[grepl("botnet|malware|attack|exploit", labels_chr)] <- TRUE
  result[grepl("background|normal|benign", labels_chr)] <- FALSE
  as.logical(result)
}

finalize_network_flows <- function(df) {
  if (nrow(df) == 0) {
    return(empty_network_flows())
  }

  missing_cols <- setdiff(UNIFIED_FLOW_COLUMNS, names(df))
  for (col in missing_cols) {
    df[[col]] <- empty_network_flows()[[col]]
  }

  df <- df[, UNIFIED_FLOW_COLUMNS, drop = FALSE]

  df$source_record_index <- safe_integer(df$source_record_index)
  df$src_port <- safe_port(df$src_port)
  df$dst_port <- safe_port(df$dst_port)
  df$duration_sec <- safe_numeric(df$duration_sec)
  df$packets_total <- safe_uint64(df$packets_total)
  df$packets_src <- safe_uint64(df$packets_src)
  df$packets_dst <- safe_uint64(df$packets_dst)
  df$bytes_total <- safe_uint64(df$bytes_total)
  df$bytes_src <- safe_uint64(df$bytes_src)
  df$bytes_dst <- safe_uint64(df$bytes_dst)
  df$src_ttl <- safe_integer(df$src_ttl)
  df$dst_ttl <- safe_integer(df$dst_ttl)
  df$rtt_sec <- safe_numeric(df$rtt_sec)
  df$synack_sec <- safe_numeric(df$synack_sec)
  df$ackdat_sec <- safe_numeric(df$ackdat_sec)
  df$is_malicious <- safe_bool(df$is_malicious)

  df$src_ip <- safe_character(df$src_ip)
  df$dst_ip <- safe_character(df$dst_ip)
  df$flow_id <- safe_character(df$flow_id)
  df$event_id <- safe_character(df$event_id)
  df$ingest_run_id <- safe_character(df$ingest_run_id)
  df$source_dataset <- safe_character(df$source_dataset)
  df$source_key <- safe_character(df$source_key)
  df$source_file_name <- safe_character(df$source_file_name)
  df$source_format <- safe_character(df$source_format)
  df$handler_name <- safe_character(df$handler_name)
  df$transport_proto <- normalize_transport_proto(df$transport_proto)
  df$app_proto <- safe_character(df$app_proto)
  df$flow_state <- safe_character(df$flow_state)
  df$direction <- safe_character(df$direction)
  df$source_label <- safe_character(df$source_label)
  df$attack_category <- safe_character(df$attack_category)
  df$attributes_json <- safe_character(df$attributes_json)

  empty_ip_version <- !nzchar(df$ip_version)
  df$ip_version <- safe_character(df$ip_version)
  df$ip_version[empty_ip_version] <- detect_ip_version(df$src_ip[empty_ip_version], df$dst_ip[empty_ip_version])

  end_missing <- is.na(df$flow_end) & !is.na(df$flow_start) & !is.na(df$duration_sec)
  df$flow_end[end_missing] <- df$flow_start[end_missing] + df$duration_sec[end_missing]

  df$event_id <- make_event_ids(df$source_key, df$source_file_name, df$source_record_index)

  df
}

get_runtime_config <- function() {
  list(
    s3_endpoint = Sys.getenv("S3_ENDPOINT_URL", ""),
    s3_bucket = Sys.getenv("S3_BUCKET", ""),
    s3_prefix = Sys.getenv("S3_PREFIX", ""),
    staging_dir = Sys.getenv("STAGING_DIR", "/tmp/r-etl-staging")
  )
}
