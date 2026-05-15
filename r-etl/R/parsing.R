library(data.table)

UNSW_NB15_COLUMNS <- c(
  "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
  "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload",
  "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
  "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
  "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
  "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
  "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
  "ct_dst_src_ltm", "attack_cat", "label"
)

KYOTO_COLUMNS <- c(
  "duration", "service", "src_bytes", "dst_bytes", "count",
  "same_srv_rate", "serror_rate", "srv_serror_rate", "dst_host_count",
  "dst_host_srv_count", "dst_host_same_src_port_rate", "dst_host_serror_rate",
  "dst_host_srv_serror_rate", "flag", "ids_detection", "malware_detection",
  "ashula_detection", "label", "src_ip", "src_port", "dst_ip", "dst_port",
  "start_time", "protocol"
)

read_delimited_sample <- function(path, n = 5L, sep = ",", header = TRUE) {
  data.table::fread(
    path,
    nrows = n,
    sep = sep,
    header = header,
    showProgress = FALSE
  )
}

parse_csv_file <- function(path, source_object, ingest_run_id) {
  first_line <- readLines(path, n = 1L, warn = FALSE)
  first_tokens <- strsplit(first_line, ",", fixed = TRUE)[[1]]
  first_tokens_trim <- tolower(trimws(first_tokens))

  if (all(first_tokens_trim %in% tolower(UNSW_NB15_COLUMNS))) {
    return(parse_unsw_nb15_csv(path, source_object, ingest_run_id, header = TRUE))
  }

  if (length(first_tokens_trim) == length(UNSW_NB15_COLUMNS) &&
      !all(first_tokens_trim %in% tolower(UNSW_NB15_COLUMNS))) {
    return(parse_unsw_nb15_csv(path, source_object, ingest_run_id, header = FALSE))
  }

  parse_generic_csv(path, source_object, ingest_run_id)
}

parse_unsw_nb15_csv <- function(path, source_object, ingest_run_id, header = FALSE) {
  info(sprintf("Parsing UNSW-NB15 CSV: %s", source_object$key))

  dt <- data.table::fread(path, header = header, showProgress = FALSE)
  if (!header) {
    setnames(dt, UNSW_NB15_COLUMNS)
  }

  extras <- dt[, c(
    "sloss", "dloss", "Sload", "Dload", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit",
    "Sintpkt", "Dintpkt", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm"
  ), with = FALSE]

  frame <- base_unified_frame(nrow(dt), source_object, ingest_run_id, "csv_unsw_nb15", "csv")
  frame$flow_start <- as.POSIXct(safe_numeric(dt$Stime), origin = "1970-01-01", tz = "UTC")
  frame$flow_end <- as.POSIXct(safe_numeric(dt$Ltime), origin = "1970-01-01", tz = "UTC")
  frame$duration_sec <- safe_numeric(dt$dur)
  frame$src_ip <- safe_character(dt$srcip)
  frame$src_port <- safe_port(dt$sport)
  frame$dst_ip <- safe_character(dt$dstip)
  frame$dst_port <- safe_port(dt$dsport)
  frame$transport_proto <- safe_character(dt$proto)
  frame$app_proto <- safe_character(dt$service)
  frame$flow_state <- safe_character(dt$state)
  frame$packets_src <- safe_uint64(dt$Spkts)
  frame$packets_dst <- safe_uint64(dt$Dpkts)
  frame$packets_total <- safe_uint64(safe_numeric(dt$Spkts) + safe_numeric(dt$Dpkts))
  frame$bytes_src <- safe_uint64(dt$sbytes)
  frame$bytes_dst <- safe_uint64(dt$dbytes)
  frame$bytes_total <- safe_uint64(safe_numeric(dt$sbytes) + safe_numeric(dt$dbytes))
  frame$src_ttl <- safe_integer(dt$sttl)
  frame$dst_ttl <- safe_integer(dt$dttl)
  frame$rtt_sec <- safe_numeric(dt$tcprtt)
  frame$synack_sec <- safe_numeric(dt$synack)
  frame$ackdat_sec <- safe_numeric(dt$ackdat)
  frame$source_label <- safe_character(dt$label)
  frame$attack_category <- safe_character(dt$attack_cat)
  frame$is_malicious <- safe_bool(dt$label)
  frame$attributes_json <- rep("{}", nrow(frame))

  finalize_network_flows(frame)
}

parse_generic_csv <- function(path, source_object, ingest_run_id) {
  info(sprintf("Parsing generic CSV: %s", source_object$key))

  dt <- data.table::fread(path, header = TRUE, showProgress = FALSE)
  lowered <- tolower(names(dt))

  find_col <- function(candidates) {
    match_idx <- match(candidates, lowered)
    match_idx <- match_idx[!is.na(match_idx)][1]
    if (is.na(match_idx)) {
      return(NULL)
    }
    names(dt)[match_idx]
  }

  src_ip_col <- find_col(c("src_ip", "srcip", "source_ip"))
  dst_ip_col <- find_col(c("dst_ip", "dstip", "dest_ip", "destination_ip"))
  proto_col <- find_col(c("proto", "protocol"))

  if (is.null(src_ip_col) || is.null(dst_ip_col) || is.null(proto_col)) {
    stop(sprintf("Unsupported generic CSV schema for %s", source_object$key))
  }

  src_port_col <- find_col(c("src_port", "sport", "source_port"))
  dst_port_col <- find_col(c("dst_port", "dport", "dest_port", "destination_port"))
  duration_col <- find_col(c("duration", "dur"))
  bytes_src_col <- find_col(c("src_bytes", "sbytes"))
  bytes_dst_col <- find_col(c("dst_bytes", "dbytes"))
  label_col <- find_col(c("label", "source_label"))

  frame <- base_unified_frame(nrow(dt), source_object, ingest_run_id, "csv_generic", "csv")
  frame$src_ip <- safe_character(dt[[src_ip_col]])
  frame$dst_ip <- safe_character(dt[[dst_ip_col]])
  frame$src_port <- safe_port(if (!is.null(src_port_col)) dt[[src_port_col]] else NA)
  frame$dst_port <- safe_port(if (!is.null(dst_port_col)) dt[[dst_port_col]] else NA)
  frame$transport_proto <- safe_character(dt[[proto_col]])
  frame$duration_sec <- safe_numeric(if (!is.null(duration_col)) dt[[duration_col]] else NA)
  frame$bytes_src <- safe_uint64(if (!is.null(bytes_src_col)) dt[[bytes_src_col]] else NA)
  frame$bytes_dst <- safe_uint64(if (!is.null(bytes_dst_col)) dt[[bytes_dst_col]] else NA)
  frame$bytes_total <- safe_uint64(frame$bytes_src + frame$bytes_dst)
  frame$source_label <- safe_character(if (!is.null(label_col)) dt[[label_col]] else "")
  frame$attack_category <- infer_attack_category(frame$source_label)
  frame$is_malicious <- infer_malicious_flag(frame$source_label)
  frame$attributes_json <- rep("{}", nrow(frame))

  finalize_network_flows(frame)
}

parse_binetflow_file <- function(path, source_object, ingest_run_id) {
  info(sprintf("Parsing BinetFlow: %s", source_object$key))

  dt <- data.table::fread(path, header = TRUE, showProgress = FALSE)
  bytes_dst <- safe_numeric(dt$TotBytes) - safe_numeric(dt$SrcBytes)
  bytes_dst[bytes_dst < 0] <- NA_real_

  extras <- dt[, c("sTos", "dTos"), with = FALSE]

  frame <- base_unified_frame(nrow(dt), source_object, ingest_run_id, "binetflow", "binetflow")
  frame$flow_start <- parse_datetime_vec(dt$StartTime, formats = c("%Y/%m/%d %H:%M:%OS", "%Y/%m/%d %H:%M:%S"))
  frame$duration_sec <- safe_numeric(dt$Dur)
  frame$flow_end <- frame$flow_start + frame$duration_sec
  frame$src_ip <- safe_character(dt$SrcAddr)
  frame$src_port <- safe_port(dt$Sport)
  frame$dst_ip <- safe_character(dt$DstAddr)
  frame$dst_port <- safe_port(dt$Dport)
  frame$transport_proto <- safe_character(dt$Proto)
  frame$flow_state <- safe_character(dt$State)
  frame$direction <- safe_character(dt$Dir)
  frame$packets_total <- safe_uint64(dt$TotPkts)
  frame$bytes_total <- safe_uint64(dt$TotBytes)
  frame$bytes_src <- safe_uint64(dt$SrcBytes)
  frame$bytes_dst <- safe_uint64(bytes_dst)
  frame$source_label <- safe_character(dt$Label)
  frame$attack_category <- infer_attack_category(frame$source_label)
  frame$is_malicious <- infer_malicious_flag(frame$source_label)
  frame$attributes_json <- rep("{}", nrow(frame))

  finalize_network_flows(frame)
}

parse_zip_archive <- function(path, source_object, ingest_run_id) {
  info(sprintf("Parsing ZIP archive: %s", source_object$key))

  members <- utils::unzip(path, list = TRUE)
  if (nrow(members) == 0) {
    return(empty_network_flows())
  }

  parsed_parts <- list()

  for (member_idx in seq_len(nrow(members))) {
    member <- members$Name[member_idx]
    member_extension <- infer_extension(member)

    if (member_extension == "txt") {
      parsed_parts[[length(parsed_parts) + 1L]] <- parse_kyoto_member(path, member, source_object, ingest_run_id)
    } else if (member_extension == "csv") {
      parsed_parts[[length(parsed_parts) + 1L]] <- parse_zip_csv_member(path, member, source_object, ingest_run_id)
    } else if (member_extension == "binetflow") {
      parsed_parts[[length(parsed_parts) + 1L]] <- parse_zip_binetflow_member(path, member, source_object, ingest_run_id)
    }
  }

  if (length(parsed_parts) == 0) {
    warning_log(sprintf("No supported members found in archive %s", source_object$key))
    return(empty_network_flows())
  }

  finalize_network_flows(rbindlist(parsed_parts, fill = TRUE))
}

process_zip_archive_into_clickhouse <- function(conn, path, source_object, ingest_run_id) {
  info(sprintf("Streaming ZIP archive into ClickHouse: %s", source_object$key))

  members <- utils::unzip(path, list = TRUE)
  if (nrow(members) == 0) {
    return(0L)
  }

  total_rows <- 0L

  for (member_idx in seq_len(nrow(members))) {
    member <- members$Name[member_idx]
    member_extension <- infer_extension(member)

    flows <- if (member_extension == "txt") {
      parse_kyoto_member(path, member, source_object, ingest_run_id)
    } else if (member_extension == "csv") {
      parse_zip_csv_member(path, member, source_object, ingest_run_id)
    } else if (member_extension == "binetflow") {
      parse_zip_binetflow_member(path, member, source_object, ingest_run_id)
    } else {
      NULL
    }

    if (!is.null(flows) && nrow(flows) > 0) {
      insert_network_flows(conn, flows)
      total_rows <- total_rows + nrow(flows)
    }
  }

  total_rows
}

parse_zip_csv_member <- function(zip_path, member, source_object, ingest_run_id) {
  cmd <- sprintf("unzip -p %s %s", shQuote(zip_path), shQuote(member))
  temp_path <- tempfile(fileext = ".csv")
  on.exit(unlink(temp_path), add = TRUE)
  run_command("sh", c("-lc", sprintf("%s > %s", cmd, shQuote(temp_path))))
  member_object <- source_object
  member_object$source_file_name <- member
  parse_csv_file(temp_path, member_object, ingest_run_id)
}

parse_zip_binetflow_member <- function(zip_path, member, source_object, ingest_run_id) {
  cmd <- sprintf("unzip -p %s %s", shQuote(zip_path), shQuote(member))
  temp_path <- tempfile(fileext = ".binetflow")
  on.exit(unlink(temp_path), add = TRUE)
  run_command("sh", c("-lc", sprintf("%s > %s", cmd, shQuote(temp_path))))
  member_object <- source_object
  member_object$source_file_name <- member
  parse_binetflow_file(temp_path, member_object, ingest_run_id)
}

parse_kyoto_member <- function(zip_path, member, source_object, ingest_run_id) {
  cmd <- sprintf("unzip -p %s %s", shQuote(zip_path), shQuote(member))
  dt <- data.table::fread(
    cmd = cmd,
    sep = "\t",
    header = FALSE,
    showProgress = FALSE
  )

  setnames(dt, KYOTO_COLUMNS)

  date_token <- gsub("[^0-9]", "", basename(member))
  day_date <- as.Date(date_token, format = "%Y%m%d")

  flow_start <- as.POSIXct(paste(day_date, dt$start_time), tz = "UTC", format = "%Y-%m-%d %H:%M:%S")

  extras <- dt[, c(
    "count", "same_srv_rate", "serror_rate", "srv_serror_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_src_port_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "ids_detection", "malware_detection", "ashula_detection"
  ), with = FALSE]

  labels_num <- safe_numeric(dt$label)
  malicious <- rep(NA, length(labels_num))
  malicious[!is.na(labels_num) & labels_num < 0] <- TRUE
  malicious[!is.na(labels_num) & labels_num > 0] <- FALSE

  member_object <- source_object
  member_object$source_file_name <- member
  frame <- base_unified_frame(nrow(dt), member_object, ingest_run_id, "zip_kyoto", "zip")
  frame$flow_start <- flow_start
  frame$duration_sec <- safe_numeric(dt$duration)
  frame$flow_end <- frame$flow_start + frame$duration_sec
  frame$src_ip <- safe_character(dt$src_ip)
  frame$src_port <- safe_port(dt$src_port)
  frame$dst_ip <- safe_character(dt$dst_ip)
  frame$dst_port <- safe_port(dt$dst_port)
  frame$transport_proto <- safe_character(dt$protocol)
  frame$app_proto <- safe_character(dt$service)
  frame$flow_state <- safe_character(dt$flag)
  frame$bytes_src <- safe_uint64(dt$src_bytes)
  frame$bytes_dst <- safe_uint64(dt$dst_bytes)
  frame$bytes_total <- safe_uint64(safe_numeric(dt$src_bytes) + safe_numeric(dt$dst_bytes))
  frame$source_label <- safe_character(dt$label)
  frame$attack_category <- ifelse(
    !is.na(malicious) & malicious,
    "malicious",
    ifelse(!is.na(malicious) & !malicious, "benign", "")
  )
  frame$is_malicious <- malicious
  frame$attributes_json <- rep("{}", nrow(frame))

  finalize_network_flows(frame)
}
