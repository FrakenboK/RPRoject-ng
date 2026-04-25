library(RClickhouse)

get_clickhouse_connection <- function() {
  host <- Sys.getenv("CLICKHOUSE_HOST", "localhost")
  port <- as.integer(Sys.getenv("CLICKHOUSE_PORT", "8123"))
  user <- Sys.getenv("CLICKHOUSE_USER", "default")
  password <- Sys.getenv("CLICKHOUSE_PASSWORD", "")
  database <- Sys.getenv("CLICKHOUSE_DATABASE", "default")

  tryCatch({
    conn <- DBI::dbConnect(
      RClickhouse::clickhouse(),
      host = host,
      port = port,
      user = user,
      password = password,
      db = database
    )
    return(conn)
  }, error = function(e) {
    stop(sprintf("Failed to connect to ClickHouse: %s", e$message))
  })
}

create_dataset_info_table <- function(conn) {
  query <- "
    CREATE TABLE IF NOT EXISTS dataset_info (
      pcap_file String,
      analysis_time DateTime,
      captipper_version String,
      traffic_time DateTime
    ) ENGINE = MergeTree()
    ORDER BY (pcap_file)
  "

  tryCatch({
    DBI::dbExecute(conn, query)
    info("Table dataset_info created or already exists")
  }, error = function(e) {
    stop(sprintf("Failed to create dataset_info table: %s", e$message))
  })
}

create_client_attributes_table <- function(conn) {
  query <- "
    CREATE TABLE IF NOT EXISTS client_attributes (
      attribute_name String,
      attribute_value String
    ) ENGINE = MergeTree()
    ORDER BY (attribute_name)
  "

  tryCatch({
    DBI::dbExecute(conn, query)
    info("Table client_attributes created or already exists")
  }, error = function(e) {
    stop(sprintf("Failed to create client_attributes table: %s", e$message))
  })
}

create_flow_edges_table <- function(conn) {
  query <- "
    CREATE TABLE IF NOT EXISTS flow_edges (
      parent_name String,
      child_name String,
      depth UInt32,
      root_name String,
      path String
    ) ENGINE = MergeTree()
    ORDER BY (parent_name, child_name)
  "

  tryCatch({
    DBI::dbExecute(conn, query)
    info("Table flow_edges created or already exists")
  }, error = function(e) {
    stop(sprintf("Failed to create flow_edges table: %s", e$message))
  })
}

create_conversation_artifacts_table <- function(conn) {
  query <- "
    CREATE TABLE IF NOT EXISTS conversation_artifacts (
      conversation_idx UInt32,
      uri_idx UInt32,
      conversation_name String,
      conversation_ip_raw String,
      conversation_host String,
      conversation_port Nullable(UInt16),
      artifact_id Nullable(UInt32),
      event_time_raw String,
      event_time_parsed Nullable(DateTime),
      host String,
      server_ip_raw String,
      server_host String,
      server_port Nullable(UInt16),
      uri String,
      short_uri String,
      method String,
      filename String,
      referer String,
      request_headers_raw String,
      response_headers_raw String,
      response_status_raw String,
      response_status_code Nullable(UInt16),
      response_content_type String,
      response_length_raw String,
      response_length_bytes Nullable(UInt64),
      response_body_raw String,
      response_body_base64 String,
      response_peek String,
      md5 String,
      sha256 String,
      magic_ext String,
      magic_name String,
      is_binary Nullable(UInt8),
      is_executable Nullable(UInt8),
      hexpeek String,
      peinfo_raw String
    ) ENGINE = MergeTree()
    ORDER BY (conversation_idx, uri_idx)
  "

  tryCatch({
    DBI::dbExecute(conn, query)
    info("Table conversation_artifacts created or already exists")
  }, error = function(e) {
    stop(sprintf("Failed to create conversation_artifacts table: %s", e$message))
  })
}

create_tcp_sessions_table <- function(conn) {
  query <- "
    CREATE TABLE IF NOT EXISTS tcp_sessions (
      uid           String,
      ts            DateTime,
      orig_h        String,
      orig_p        Nullable(UInt16),
      resp_h        String,
      resp_p        Nullable(UInt16),
      proto         LowCardinality(String),
      service       String,
      duration_sec  Nullable(Float64),
      orig_bytes    Nullable(UInt64),
      resp_bytes    Nullable(UInt64),
      conn_state    LowCardinality(String),
      missed_bytes  Nullable(UInt64),
      history       String,
      orig_pkts     Nullable(UInt64),
      orig_ip_bytes Nullable(UInt64),
      resp_pkts     Nullable(UInt64),
      resp_ip_bytes Nullable(UInt64),
      local_orig    Nullable(UInt8),
      local_resp    Nullable(UInt8)
    ) ENGINE = MergeTree()
    ORDER BY (ts, uid)
  "

  tryCatch({
    DBI::dbExecute(conn, query)
    info("Table tcp_sessions created or already exists")
  }, error = function(e) {
    stop(sprintf("Failed to create tcp_sessions table: %s", e$message))
  })
}

create_all_tables <- function(conn) {
  create_dataset_info_table(conn)
  create_client_attributes_table(conn)
  create_flow_edges_table(conn)
  create_conversation_artifacts_table(conn)
  create_tcp_sessions_table(conn)
}

insert_dataset_info <- function(conn, dataset_info) {
  if (nrow(dataset_info) == 0) {
    warning("No dataset_info to insert")
    return(invisible(NULL))
  }

  tryCatch({
    DBI::dbWriteTable(conn, "dataset_info", dataset_info, append = TRUE, row.names = FALSE)
    info(sprintf("Inserted %d row(s) into dataset_info", nrow(dataset_info)))
  }, error = function(e) {
    stop(sprintf("Failed to insert dataset_info: %s", e$message))
  })
}

insert_client_attributes <- function(conn, client_attributes) {
  if (nrow(client_attributes) == 0) {
    warning("No client_attributes to insert")
    return(invisible(NULL))
  }

  tryCatch({
    DBI::dbWriteTable(conn, "client_attributes", client_attributes, append = TRUE, row.names = FALSE)
    info(sprintf("Inserted %d row(s) into client_attributes", nrow(client_attributes)))
  }, error = function(e) {
    stop(sprintf("Failed to insert client_attributes: %s", e$message))
  })
}

insert_flow_edges <- function(conn, flow_edges) {
  if (nrow(flow_edges) == 0) {
    warning("No flow_edges to insert")
    return(invisible(NULL))
  }

  tryCatch({
    DBI::dbWriteTable(conn, "flow_edges", flow_edges, append = TRUE, row.names = FALSE)
    info(sprintf("Inserted %d row(s) into flow_edges", nrow(flow_edges)))
  }, error = function(e) {
    stop(sprintf("Failed to insert flow_edges: %s", e$message))
  })
}

insert_conversation_artifacts <- function(conn, artifacts) {
  if (nrow(artifacts) == 0) {
    warning("No conversation_artifacts to insert")
    return(invisible(NULL))
  }

  # RClickhouse не поддерживает R logical -> Nullable(UInt8) автоматически
  artifacts$is_binary    <- as.integer(artifacts$is_binary)
  artifacts$is_executable <- as.integer(artifacts$is_executable)

  # Заменяем NULL/NA в String-колонках на пустую строку (так семантически вернее для String в CH)
  string_cols <- c('conversation_name','conversation_ip_raw','conversation_host',
    'event_time_raw','host','server_ip_raw','server_host','uri','short_uri',
    'method','filename','referer','request_headers_raw','response_headers_raw',
    'response_status_raw','response_content_type','response_length_raw',
    'response_body_raw','response_body_base64','response_peek',
    'md5','sha256','magic_ext','magic_name','hexpeek','peinfo_raw')
  for (col in string_cols) {
    if (col %in% names(artifacts)) {
      artifacts[[col]][is.na(artifacts[[col]])] <- ""
    }
  }

  tryCatch({
    DBI::dbWriteTable(conn, "conversation_artifacts", artifacts, append = TRUE, row.names = FALSE)
    info(sprintf("Inserted %d row(s) into conversation_artifacts", nrow(artifacts)))
  }, error = function(e) {
    stop(sprintf("Failed to insert conversation_artifacts: %s", e$message))
  })
}

insert_tcp_sessions <- function(conn, tcp_sessions) {
  if (nrow(tcp_sessions) == 0) {
    warning_log("No tcp_sessions to insert")
    return(invisible(NULL))
  }

  string_cols <- c("uid", "orig_h", "resp_h", "proto", "service", "conn_state", "history")
  for (col in string_cols) {
    if (col %in% names(tcp_sessions)) {
      tcp_sessions[[col]][is.na(tcp_sessions[[col]])] <- ""
    }
  }

  tryCatch({
    DBI::dbWriteTable(conn, "tcp_sessions", tcp_sessions, append = TRUE, row.names = FALSE)
    info(sprintf("Inserted %d row(s) into tcp_sessions", nrow(tcp_sessions)))
  }, error = function(e) {
    stop(sprintf("Failed to insert tcp_sessions: %s", e$message))
  })
}

insert_normalized_data <- function(conn, normalized_data) {
  insert_dataset_info(conn, normalized_data$dataset_info)
  insert_client_attributes(conn, normalized_data$client_attributes)
  insert_flow_edges(conn, normalized_data$flow_edges)
  insert_conversation_artifacts(conn, normalized_data$conversation_artifacts)
  if (!is.null(normalized_data$tcp_sessions)) {
    insert_tcp_sessions(conn, normalized_data$tcp_sessions)
  }
}

test_connection <- function(conn) {
  tryCatch({
    result <- DBI::dbGetQuery(conn, "SELECT 1 as test")
    if (nrow(result) > 0 && result$test[1] == 1) {
      info("ClickHouse connection test successful")
      return(TRUE)
    }
    return(FALSE)
  }, error = function(e) {
    error_log(sprintf("ClickHouse connection test failed: %s", e$message))
    return(FALSE)
  })
}

close_connection <- function(conn) {
  tryCatch({
    DBI::dbDisconnect(conn)
    info("ClickHouse connection closed")
  }, error = function(e) {
    warning_log(sprintf("Failed to close ClickHouse connection: %s", e$message))
  })
}
