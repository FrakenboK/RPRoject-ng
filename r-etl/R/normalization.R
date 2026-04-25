library(yaml)
library(stringr)

load_schema <- function(schema_path = "config/schema.yml") {
  tryCatch({
    yaml::read_yaml(schema_path)
  }, error = function(e) {
    stop(sprintf("Failed to load schema: %s", e$message))
  })
}

normalize_ipv4 <- function(ip) {
  if (is.null(ip) || is.na(ip) || nchar(as.character(ip)) == 0) {
    return(NA_character_)
  }

  ip <- as.character(ip)
  ip <- trimws(ip)

  if (!grepl("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip)) {
    return(NA_character_)
  }

  return(ip)
}

normalize_port <- function(port) {
  if (is.null(port)) return(NA_integer_)
  port_num <- suppressWarnings(as.integer(port))
  port_num[is.na(port_num) | port_num < 0L | port_num > 65535L] <- NA_integer_
  port_num
}

normalize_protocol <- function(protocol) {
  if (is.null(protocol) || is.na(protocol) || nchar(as.character(protocol)) == 0) {
    return(NA_character_)
  }

  protocol <- toupper(trimws(as.character(protocol)))
  valid_protocols <- c("TCP", "UDP", "ICMP")

  if (!protocol %in% valid_protocols) {
    return(NA_character_)
  }

  return(protocol)
}

normalize_direction <- function(direction) {
  if (is.null(direction) || is.na(direction) || nchar(as.character(direction)) == 0) {
    return(NA_character_)
  }

  direction <- toupper(trimws(as.character(direction)))
  valid_directions <- c("IN", "OUT", "INTERNAL")

  if (!direction %in% valid_directions) {
    return(NA_character_)
  }

  return(direction)
}

normalize_application <- function(app) {
  if (is.null(app) || is.na(app) || nchar(as.character(app)) == 0) {
    return(NA_character_)
  }

  app <- toupper(trimws(as.character(app)))
  valid_apps <- c("HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "IMAP", "POP3", "RDP", "SMB", "UNKNOWN")

  if (!app %in% valid_apps) {
    return("UNKNOWN")
  }

  return(app)
}

normalize_timestamp_single <- function(timestamp) {
  if (is.null(timestamp) || length(timestamp) == 0) return(as.POSIXct(NA, tz = "UTC"))
  if (length(timestamp) > 1) timestamp <- timestamp[[1]]
  if (is.na(timestamp)) return(as.POSIXct(NA, tz = "UTC"))

  ts_str <- trimws(as.character(timestamp))
  if (nchar(ts_str) == 0 || ts_str == "NA") return(as.POSIXct(NA, tz = "UTC"))

  if (inherits(timestamp, "POSIXct")) return(as.POSIXct(timestamp, tz = "UTC"))

  formats <- c(
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%OS", "%Y-%m-%dT%H:%M:%OS",
    "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z",
    "%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%d/%m/%y %H:%M:%S", "%d/%m/%Y %H:%M:%S"
  )

  for (fmt in formats) {
    parsed <- tryCatch(
      as.POSIXct(strptime(ts_str, fmt, tz = "UTC"), tz = "UTC"),
      error = function(e) as.POSIXct(NA, tz = "UTC")
    )
    if (!is.na(parsed)) return(parsed)
  }

  as.POSIXct(NA, tz = "UTC")
}

# Векторизованная обёртка — работает и с одним значением, и с вектором
normalize_timestamp <- function(timestamp) {
  if (is.null(timestamp)) return(as.POSIXct(NA, tz = "UTC"))
  if (length(timestamp) == 1) return(normalize_timestamp_single(timestamp))
  result <- as.POSIXct(sapply(timestamp, function(x) {
    as.numeric(normalize_timestamp_single(x))
  }), origin = "1970-01-01", tz = "UTC")
  result
}

normalize_uint16 <- function(value) {
  if (is.null(value)) return(NA_integer_)
  val <- suppressWarnings(as.integer(value))
  val[is.na(val) | val < 0L | val > 65535L] <- NA_integer_
  val
}

normalize_uint32 <- function(value) {
  if (is.null(value)) return(NA_integer_)
  val <- suppressWarnings(as.integer(value))
  # R integer макс 2^31-1, для uint32 допускаем отрицательные только если overflow
  val[is.na(val) | val < 0L] <- NA_integer_
  val
}

normalize_uint64 <- function(value) {
  if (is.null(value)) return(NA_real_)
  val <- suppressWarnings(as.numeric(value))
  val[is.na(val) | val < 0] <- NA_real_
  val
}

normalize_float32 <- function(value) {
  if (is.null(value)) return(NA_real_)
  val <- suppressWarnings(as.numeric(value))
  val[is.na(val) | is.infinite(val)] <- NA_real_
  val
}

normalize_boolean <- function(value) {
  if (is.null(value)) return(NA)
  if (is.logical(value)) return(value)
  if (is.numeric(value)) return(as.logical(value))
  val_str <- tolower(trimws(as.character(value)))
  result <- rep(NA, length(val_str))
  result[val_str %in% c("true",  "1", "yes", "on")]  <- TRUE
  result[val_str %in% c("false", "0", "no",  "off")] <- FALSE
  as.logical(result)
}

normalize_threat_score <- function(score) {
  if (is.null(score) || is.na(score)) {
    return(NA_real_)
  }

  val <- suppressWarnings(as.numeric(score))
  if (is.na(val) || val < 0 || val > 1) {
    return(NA_real_)
  }

  return(val)
}

normalize_severity <- function(severity) {
  if (is.null(severity) || is.na(severity) || nchar(as.character(severity)) == 0) {
    return(NA_character_)
  }

  severity <- toupper(trimws(as.character(severity)))
  valid_severities <- c("LOW", "MEDIUM", "HIGH", "CRITICAL")

  if (!severity %in% valid_severities) {
    return(NA_character_)
  }

  return(severity)
}

normalize_string <- function(value, max_length = NULL) {
  # Векторизованная версия: работает и с одиночными значениями, и с векторами
  if (is.null(value)) return(NA_character_)

  str_val <- as.character(value)
  str_val <- trimws(str_val)
  str_val[is.na(value)] <- NA_character_

  if (!is.null(max_length)) {
    too_long <- !is.na(str_val) & nchar(str_val) > max_length
    str_val[too_long] <- substr(str_val[too_long], 1, max_length)
  }

  return(str_val)
}

normalize_dataset_info <- function(dataset_info) {
  if (nrow(dataset_info) == 0) {
    return(dataset_info)
  }

  dataset_info$pcap_file <- normalize_string(dataset_info$pcap_file)
  dataset_info$analysis_time <- normalize_timestamp(dataset_info$analysis_time)
  dataset_info$captipper_version <- normalize_string(dataset_info$captipper_version)
  dataset_info$traffic_time <- normalize_timestamp(dataset_info$traffic_time)

  return(dataset_info)
}

normalize_client_attributes <- function(client_attributes) {
  if (nrow(client_attributes) == 0) {
    return(client_attributes)
  }

  client_attributes$attribute_name <- normalize_string(client_attributes$attribute_name)
  client_attributes$attribute_value <- normalize_string(client_attributes$attribute_value, max_length = 10000)

  return(client_attributes)
}

normalize_flow_edges <- function(flow_edges) {
  if (nrow(flow_edges) == 0) {
    return(flow_edges)
  }

  flow_edges$parent_name <- normalize_string(flow_edges$parent_name)
  flow_edges$child_name <- normalize_string(flow_edges$child_name)
  flow_edges$depth <- normalize_uint32(flow_edges$depth)
  flow_edges$root_name <- normalize_string(flow_edges$root_name)
  flow_edges$path <- normalize_string(flow_edges$path, max_length = 1000)

  return(flow_edges)
}

normalize_conversation_artifacts <- function(artifacts) {
  if (nrow(artifacts) == 0) {
    return(artifacts)
  }

  artifacts$conversation_idx <- normalize_uint32(artifacts$conversation_idx)
  artifacts$uri_idx <- normalize_uint32(artifacts$uri_idx)
  artifacts$conversation_name <- normalize_string(artifacts$conversation_name)
  artifacts$conversation_ip_raw <- normalize_string(artifacts$conversation_ip_raw)
  artifacts$conversation_host <- normalize_string(artifacts$conversation_host)
  artifacts$conversation_port <- normalize_port(artifacts$conversation_port)
  artifacts$artifact_id <- normalize_uint32(artifacts$artifact_id)
  artifacts$event_time_raw <- normalize_string(artifacts$event_time_raw)
  artifacts$event_time_parsed <- normalize_timestamp(artifacts$event_time_parsed)
  artifacts$host <- normalize_string(artifacts$host)
  artifacts$server_ip_raw <- normalize_string(artifacts$server_ip_raw)
  artifacts$server_host <- normalize_string(artifacts$server_host)
  artifacts$server_port <- normalize_port(artifacts$server_port)
  artifacts$uri <- normalize_string(artifacts$uri, max_length = 10000)
  artifacts$short_uri <- normalize_string(artifacts$short_uri, max_length = 1000)
  artifacts$method <- normalize_string(artifacts$method)
  artifacts$filename <- normalize_string(artifacts$filename, max_length = 1000)
  artifacts$referer <- normalize_string(artifacts$referer, max_length = 10000)
  artifacts$request_headers_raw <- normalize_string(artifacts$request_headers_raw, max_length = 50000)
  artifacts$response_headers_raw <- normalize_string(artifacts$response_headers_raw, max_length = 50000)
  artifacts$response_status_raw <- normalize_string(artifacts$response_status_raw)
  artifacts$response_status_code <- normalize_uint16(artifacts$response_status_code)
  artifacts$response_content_type <- normalize_string(artifacts$response_content_type)
  artifacts$response_length_raw <- normalize_string(artifacts$response_length_raw)
  artifacts$response_length_bytes <- normalize_uint64(artifacts$response_length_bytes)
  artifacts$response_body_raw <- normalize_string(artifacts$response_body_raw, max_length = 100000)
  artifacts$response_body_base64 <- normalize_string(artifacts$response_body_base64, max_length = 100000)
  artifacts$response_peek <- normalize_string(artifacts$response_peek, max_length = 1000)
  artifacts$md5 <- normalize_string(artifacts$md5)
  artifacts$sha256 <- normalize_string(artifacts$sha256)
  artifacts$magic_ext <- normalize_string(artifacts$magic_ext)
  artifacts$magic_name <- normalize_string(artifacts$magic_name)
  artifacts$is_binary <- normalize_boolean(artifacts$is_binary)
  artifacts$is_executable <- normalize_boolean(artifacts$is_executable)
  artifacts$hexpeek <- normalize_string(artifacts$hexpeek, max_length = 50000)
  artifacts$peinfo_raw <- normalize_string(artifacts$peinfo_raw, max_length = 100000)

  return(artifacts)
}

normalize_parsed_data <- function(parsed_data) {
  normalized <- list(
    dataset_info = normalize_dataset_info(parsed_data$dataset_info),
    client_attributes = normalize_client_attributes(parsed_data$client_attributes),
    flow_edges = normalize_flow_edges(parsed_data$flow_edges),
    conversation_artifacts = normalize_conversation_artifacts(parsed_data$conversation_artifacts)
  )

  return(normalized)
}

validate_normalized_data <- function(normalized_data) {
  errors <- list()

  if (nrow(normalized_data$dataset_info) == 0) {
    errors <- c(errors, "dataset_info is empty")
  }

  if (nrow(normalized_data$client_attributes) == 0) {
    errors <- c(errors, "client_attributes is empty")
  }

  if (nrow(normalized_data$conversation_artifacts) == 0) {
    errors <- c(errors, "conversation_artifacts is empty")
  }

  if (length(errors) > 0) {
    warning(sprintf("Validation warnings: %s", paste(errors, collapse = "; ")))
  }

  return(length(errors) == 0)
}
