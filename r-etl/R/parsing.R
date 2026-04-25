library(jsonlite)
library(stringr)

parse_info <- function(data) {
  info <- data$info
  data.frame(
    pcap_file = ifelse(is.null(info$pcap_file), NA, info$pcap_file),
    analysis_time = ifelse(is.null(info$analysis_time), NA, info$analysis_time),
    captipper_version = ifelse(is.null(info$captipper_version), NA, info$captipper_version),
    traffic_time = ifelse(is.null(info$traffic_time), NA, info$traffic_time),
    stringsAsFactors = FALSE
  )
}

parse_client <- function(data) {
  client <- data$client
  if (is.null(client) || length(client) == 0) {
    return(data.frame(
      attribute_name = character(0),
      attribute_value = character(0),
      stringsAsFactors = FALSE
    ))
  }

  keys <- names(client)
  values <- sapply(keys, function(k) {
    val <- client[[k]]
    if (is.null(val)) NA
    else if (is.list(val)) paste(val, collapse = ", ")
    else as.character(val)
  })

  data.frame(
    attribute_name = keys,
    attribute_value = values,
    stringsAsFactors = FALSE
  )
}

parse_flow_tree_recursive <- function(node, parent_name = NULL, depth = 0, root_name = NULL, path = "", edges = list()) {
  node_name <- ifelse(is.null(node$name), NA, as.character(node$name))

  if (is.null(root_name)) {
    root_name <- node_name
  }

  if (nchar(path) == 0) {
    current_path <- node_name
  } else {
    current_path <- paste(path, node_name, sep = "/")
  }

  if (!is.null(parent_name)) {
    edges <- c(edges, list(list(
      parent_name = parent_name,
      child_name = node_name,
      depth = depth,
      root_name = root_name,
      path = current_path
    )))
  }

  if (!is.null(node$children) && length(node$children) > 0) {
    for (child in node$children) {
      edges <- parse_flow_tree_recursive(child, node_name, depth + 1, root_name, current_path, edges)
    }
  }

  return(edges)
}

parse_flow_tree <- function(data) {
  flow <- data$flow
  if (is.null(flow) || is.null(flow$hosts)) {
    return(data.frame(
      parent_name = character(0),
      child_name = character(0),
      depth = integer(0),
      root_name = character(0),
      path = character(0),
      stringsAsFactors = FALSE
    ))
  }

  edges <- parse_flow_tree_recursive(flow$hosts)

  if (length(edges) == 0) {
    return(data.frame(
      parent_name = character(0),
      child_name = character(0),
      depth = integer(0),
      root_name = character(0),
      path = character(0),
      stringsAsFactors = FALSE
    ))
  }

  do.call(rbind, lapply(edges, as.data.frame, stringsAsFactors = FALSE))
}

parse_conversation_ip <- function(ip_raw) {
  if (is.null(ip_raw) || nchar(ip_raw) == 0) {
    return(list(host = NA, port = NA))
  }

  colon_count <- str_count(ip_raw, ":")

  if (colon_count >= 2) {
    last_colon <- str_locate(ip_raw, ":") %>% as.data.frame() %>% tail(1) %>% pull(end)
    if (!is.na(last_colon)) {
      port_part <- substr(ip_raw, last_colon + 1, nchar(ip_raw))
      host_part <- substr(ip_raw, 1, last_colon - 1)
      port <- suppressWarnings(as.integer(port_part))
      if (is.na(port)) {
        return(list(host = ip_raw, port = NA))
      }
      return(list(host = host_part, port = port))
    }
  }

  parts <- strsplit(ip_raw, ":")[[1]]
  if (length(parts) >= 2) {
    port <- suppressWarnings(as.integer(parts[length(parts)]))
    host <- paste(parts[-length(parts)], collapse = ":")
    if (is.na(port)) {
      return(list(host = ip_raw, port = NA))
    }
    return(list(host = host, port = port))
  }

  return(list(host = ip_raw, port = NA))
}

parse_event_time <- function(time_raw) {
  if (is.null(time_raw) || nchar(time_raw) == 0) {
    return(NA)
  }

  tryCatch({
    parsed <- strptime(time_raw, "%m/%d/%y %H:%M:%S", tz = "UTC")
    if (is.na(parsed)) {
      parsed <- strptime(time_raw, "%m/%d/%Y %H:%M:%S", tz = "UTC")
    }
    if (is.na(parsed)) {
      return(NA)
    }
    as.POSIXct(parsed, tz = "UTC")
  }, error = function(e) {
    NA
  })
}

parse_response_status_code <- function(res_num) {
  if (is.null(res_num) || nchar(res_num) == 0) {
    return(NA_integer_)
  }

  match <- str_match(res_num, "^\\s*(\\d+)")
  if (!is.na(match[1, 2])) {
    return(as.integer(match[1, 2]))
  }

  NA_integer_
}

parse_response_length_bytes <- function(res_len) {
  if (is.null(res_len) || nchar(res_len) == 0) {
    return(NA_real_)
  }

  match <- str_match(tolower(res_len), "^\\s*([\\d.]+)\\s*(b|kb|mb|gb)?")
  if (is.na(match[1, 1])) {
    return(NA_real_)
  }

  value <- as.numeric(match[1, 2])
  unit <- ifelse(is.na(match[1, 3]), "b", tolower(match[1, 3]))

  multiplier <- switch(unit,
    "b" = 1,
    "kb" = 1024,
    "mb" = 1024 * 1024,
    "gb" = 1024 * 1024 * 1024,
    1
  )

  value * multiplier
}

parse_uri_artifact <- function(uri, conversation_idx, uri_idx, conversation_name, conversation_ip_raw, conversation_host, conversation_port) {
  data.frame(
    conversation_idx = conversation_idx,
    uri_idx = uri_idx,
    conversation_name = conversation_name,
    conversation_ip_raw = conversation_ip_raw,
    conversation_host = conversation_host,
    conversation_port = conversation_port,
    artifact_id = ifelse(is.null(uri$id), NA_integer_, as.integer(uri$id)),
    event_time_raw = ifelse(is.null(uri$epochtime), NA, as.character(uri$epochtime)),
    event_time_parsed = parse_event_time(uri$epochtime),
    host = ifelse(is.null(uri$host), NA, as.character(uri$host)),
    server_ip_raw = ifelse(is.null(uri$server_ip), NA, as.character(uri$server_ip)),
    server_host = ifelse(is.null(uri$host), NA, as.character(uri$host)),
    server_port = NA_integer_,
    uri = ifelse(is.null(uri$uri), NA, as.character(uri$uri)),
    short_uri = ifelse(is.null(uri$short_uri), NA, as.character(uri$short_uri)),
    method = ifelse(is.null(uri$method), NA, as.character(uri$method)),
    filename = ifelse(is.null(uri$filename), NA, as.character(uri$filename)),
    referer = ifelse(is.null(uri$referer), NA, as.character(uri$referer)),
    request_headers_raw = ifelse(is.null(uri$req_head), NA, as.character(uri$req_head)),
    response_headers_raw = ifelse(is.null(uri$res_head), NA, as.character(uri$res_head)),
    response_status_raw = ifelse(is.null(uri$res_num), NA, as.character(uri$res_num)),
    response_status_code = parse_response_status_code(uri$res_num),
    response_content_type = ifelse(is.null(uri$res_type), NA, as.character(uri$res_type)),
    response_length_raw = ifelse(is.null(uri$res_len), NA, as.character(uri$res_len)),
    response_length_bytes = parse_response_length_bytes(uri$res_len),
    response_body_raw = ifelse(is.null(uri$res_body), NA, as.character(uri$res_body)),
    response_body_base64 = ifelse(is.null(uri$res_base64), NA, as.character(uri$res_base64)),
    response_peek = ifelse(is.null(uri$respeek), NA, as.character(uri$respeek)),
    md5 = ifelse(is.null(uri$md5), NA, as.character(uri$md5)),
    sha256 = ifelse(is.null(uri$sha256), NA, as.character(uri$sha256)),
    magic_ext = ifelse(is.null(uri$magic_ext), NA, as.character(uri$magic_ext)),
    magic_name = ifelse(is.null(uri$magic_name), NA, as.character(uri$magic_name)),
    is_binary = ifelse(is.null(uri$binary), FALSE, as.logical(uri$binary)),
    is_executable = ifelse(is.null(uri$exe), FALSE, as.logical(uri$exe)),
    hexpeek = ifelse(is.null(uri$hexpeek), NA, as.character(uri$hexpeek)),
    peinfo_raw = ifelse(is.null(uri$peinfo), NA, as.character(uri$peinfo)),
    stringsAsFactors = FALSE
  )
}

parse_conversations <- function(data) {
  conversations <- data$conversations

  if (is.null(conversations) || length(conversations) == 0) {
    return(data.frame(
      conversation_idx = integer(0),
      uri_idx = integer(0),
      conversation_name = character(0),
      conversation_ip_raw = character(0),
      conversation_host = character(0),
      conversation_port = integer(0),
      artifact_id = integer(0),
      event_time_raw = character(0),
      event_time_parsed = as.POSIXct(character(0), tz = "UTC"),
      host = character(0),
      server_ip_raw = character(0),
      server_host = character(0),
      server_port = integer(0),
      uri = character(0),
      short_uri = character(0),
      method = character(0),
      filename = character(0),
      referer = character(0),
      request_headers_raw = character(0),
      response_headers_raw = character(0),
      response_status_raw = character(0),
      response_status_code = integer(0),
      response_content_type = character(0),
      response_length_raw = character(0),
      response_length_bytes = numeric(0),
      response_body_raw = character(0),
      response_body_base64 = character(0),
      response_peek = character(0),
      md5 = character(0),
      sha256 = character(0),
      magic_ext = character(0),
      magic_name = character(0),
      is_binary = logical(0),
      is_executable = logical(0),
      hexpeek = character(0),
      peinfo_raw = character(0),
      stringsAsFactors = FALSE
    ))
  }

  all_artifacts <- list()

  for (conv_idx in seq_along(conversations)) {
    conv <- conversations[[conv_idx]]

    conversation_name <- ifelse(is.null(conv$name), NA, as.character(conv$name))
    conversation_ip_raw <- ifelse(is.null(conv$ip), NA, as.character(conv$ip))

    ip_parsed <- parse_conversation_ip(conversation_ip_raw)
    conversation_host <- ip_parsed$host
    conversation_port <- ifelse(is.null(ip_parsed$port), NA_integer_, ip_parsed$port)

    uris <- conv$uris
    if (is.null(uris) || length(uris) == 0) {
      next
    }

    for (uri_idx in seq_along(uris)) {
      uri <- uris[[uri_idx]]
      artifact <- parse_uri_artifact(
        uri = uri,
        conversation_idx = conv_idx,
        uri_idx = uri_idx,
        conversation_name = conversation_name,
        conversation_ip_raw = conversation_ip_raw,
        conversation_host = conversation_host,
        conversation_port = conversation_port
      )
      all_artifacts <- c(all_artifacts, list(artifact))
    }
  }

  if (length(all_artifacts) == 0) {
    return(data.frame(
      conversation_idx = integer(0),
      uri_idx = integer(0),
      conversation_name = character(0),
      conversation_ip_raw = character(0),
      conversation_host = character(0),
      conversation_port = integer(0),
      artifact_id = integer(0),
      event_time_raw = character(0),
      event_time_parsed = as.POSIXct(character(0), tz = "UTC"),
      host = character(0),
      server_ip_raw = character(0),
      server_host = character(0),
      server_port = integer(0),
      uri = character(0),
      short_uri = character(0),
      method = character(0),
      filename = character(0),
      referer = character(0),
      request_headers_raw = character(0),
      response_headers_raw = character(0),
      response_status_raw = character(0),
      response_status_code = integer(0),
      response_content_type = character(0),
      response_length_raw = character(0),
      response_length_bytes = numeric(0),
      response_body_raw = character(0),
      response_body_base64 = character(0),
      response_peek = character(0),
      md5 = character(0),
      sha256 = character(0),
      magic_ext = character(0),
      magic_name = character(0),
      is_binary = logical(0),
      is_executable = logical(0),
      hexpeek = character(0),
      peinfo_raw = character(0),
      stringsAsFactors = FALSE
    ))
  }

  do.call(rbind, all_artifacts)
}

validate_json_structure <- function(data) {
  required_keys <- c("flow", "info", "client", "conversations")
  missing_keys <- required_keys[!required_keys %in% names(data)]

  if (length(missing_keys) > 0) {
    stop(sprintf("Missing required keys: %s", paste(missing_keys, collapse = ", ")))
  }

  if (!is.list(data$conversations)) {
    stop("'conversations' must be an array")
  }
}

parse_captipper_json <- function(json_data) {
  validate_json_structure(json_data)

  dataset_info <- parse_info(json_data)
  client_attributes <- parse_client(json_data)
  flow_edges <- parse_flow_tree(json_data)
  conversation_artifacts <- parse_conversations(json_data)

  list(
    dataset_info = dataset_info,
    client_attributes = client_attributes,
    flow_edges = flow_edges,
    conversation_artifacts = conversation_artifacts
  )
}

parse_captipper_file <- function(filepath) {
  tryCatch({
    content <- readLines(filepath, warn = FALSE)
    json_str <- paste(content, collapse = "\n")
    data <- fromJSON(json_str, simplifyVector = FALSE)
    parse_captipper_json(data)
  }, error = function(e) {
    tryCatch({
      content <- readLines(filepath, warn = FALSE, encoding = "latin1")
      json_str <- paste(content, collapse = "\n")
      data <- fromJSON(json_str, simplifyVector = FALSE)
      parse_captipper_json(data)
    }, error = function(e2) {
      stop(sprintf("Failed to parse JSON file: %s", e2$message))
    })
  })
}

to_clickhouse_rows <- function(parsed_data) {
  list(
    dataset_info = parsed_data$dataset_info,
    client_attributes = parsed_data$client_attributes,
    flow_edges = parsed_data$flow_edges,
    conversation_artifacts = parsed_data$conversation_artifacts
  )
}
