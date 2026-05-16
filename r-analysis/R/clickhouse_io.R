library(DBI)
library(RClickhouse)

get_clickhouse_connection <- function() {
  DBI::dbConnect(
    RClickhouse::clickhouse(),
    host = Sys.getenv("CLICKHOUSE_HOST", "localhost"),
    port = as.integer(Sys.getenv("CLICKHOUSE_PORT", "9000")),
    user = Sys.getenv("CLICKHOUSE_USER", "default"),
    password = Sys.getenv("CLICKHOUSE_PASSWORD", ""),
    db = Sys.getenv("CLICKHOUSE_DATABASE", "default")
  )
}

test_connection <- function(conn) {
  result <- DBI::dbGetQuery(conn, "SELECT 1 AS ok")
  nrow(result) == 1 && !is.na(suppressWarnings(as.numeric(result$ok[[1]]))) &&
    suppressWarnings(as.numeric(result$ok[[1]])) == 1
}

create_analysis_runs_table <- function(conn) {
  DBI::dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS analysis_runs (
      analysis_run_id   String,
      started_at        DateTime,
      finished_at       Nullable(DateTime),
      status            LowCardinality(String),
      source_table      LowCardinality(String),
      flow_rows_scanned Nullable(UInt64),
      detections_total  Nullable(UInt64),
      signature_total   Nullable(UInt64),
      behavioral_total  Nullable(UInt64),
      message           String
    ) ENGINE = MergeTree()
    ORDER BY (started_at, analysis_run_id)
  ")
}

create_analysis_detections_table <- function(conn) {
  DBI::dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS analysis_detections (
      detection_id       String,
      analysis_run_id    String,
      detector_type      LowCardinality(String),
      detector_name      LowCardinality(String),
      rule_id            String,
      rule_name          String,
      severity           LowCardinality(String),
      confidence_score   Nullable(Float64),
      entity_type        LowCardinality(String),
      entity_value       String,
      src_ip             String,
      src_port           Nullable(UInt16),
      dst_ip             String,
      dst_port           Nullable(UInt16),
      transport_proto    LowCardinality(String),
      app_proto          LowCardinality(String),
      first_seen         Nullable(DateTime),
      last_seen          Nullable(DateTime),
      flow_count         Nullable(UInt64),
      aggregation_key    String,
      title              String,
      description        String,
      tags_json          String,
      detail_json        String,
      created_at         DateTime
    ) ENGINE = MergeTree()
    ORDER BY (created_at, detector_type, rule_id, detection_id)
  ")
}

create_analysis_detection_events_table <- function(conn) {
  DBI::dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS analysis_detection_events (
      analysis_run_id String,
      detection_id    String,
      detector_type   LowCardinality(String),
      rule_id         String,
      event_id        String,
      flow_id         String,
      flow_start      Nullable(DateTime),
      src_ip          String,
      src_port        Nullable(UInt16),
      dst_ip          String,
      dst_port        Nullable(UInt16),
      transport_proto LowCardinality(String),
      app_proto       LowCardinality(String),
      source_dataset  LowCardinality(String),
      source_key      String
    ) ENGINE = MergeTree()
    ORDER BY (analysis_run_id, detection_id, event_id)
  ")
}

create_all_analysis_tables <- function(conn) {
  create_analysis_runs_table(conn)
  create_analysis_detections_table(conn)
  create_analysis_detection_events_table(conn)
}

quote_sql_string_list <- function(values) {
  if (length(values) == 0) {
    return("")
  }

  paste(vapply(values, quote_sql_string, character(1)), collapse = ", ")
}

build_source_key_clause <- function(source_keys, column_name = "source_key") {
  if (is.null(source_keys)) {
    return("1 = 1")
  }

  source_keys <- unique(safe_character(source_keys))
  source_keys <- source_keys[nzchar(source_keys)]
  if (length(source_keys) == 0) {
    return("1 = 0")
  }

  sprintf("%s IN (%s)", column_name, quote_sql_string_list(source_keys))
}

mark_stale_analysis_runs_failed <- function(conn) {
  DBI::dbExecute(conn, sprintf("
    ALTER TABLE analysis_runs
    UPDATE
      finished_at = ifNull(finished_at, now()),
      status = 'failed',
      message = if(message = '', 'analysis run interrupted', message)
    WHERE status = 'running'
  "))
}

insert_analysis_run <- function(conn, run_row) {
  DBI::dbWriteTable(conn, "analysis_runs", run_row, append = TRUE, row.names = FALSE)
}

build_sql_literal <- function(value) {
  if (is.null(value) || length(value) == 0 || all(is.na(value))) {
    return("NULL")
  }

  scalar <- value[[1]]

  if (inherits(scalar, "POSIXt")) {
    return(sprintf(
      "toDateTime(%s)",
      quote_sql_string(format(as.POSIXct(scalar, tz = "UTC"), "%Y-%m-%d %H:%M:%S"))
    ))
  }

  if (is.numeric(scalar)) {
    if (!is.finite(scalar)) {
      return("NULL")
    }
    return(as.character(scalar))
  }

  if (is.logical(scalar)) {
    return(if (isTRUE(scalar)) "1" else "0")
  }

  quote_sql_string(scalar)
}

insert_rows_with_values_sql <- function(conn, table_name, rows, chunk_size = 500L) {
  if (nrow(rows) == 0) {
    return(invisible(NULL))
  }

  rows <- as.data.frame(rows, stringsAsFactors = FALSE)
  column_names <- colnames(rows)
  chunk_ids <- split(seq_len(nrow(rows)), ceiling(seq_len(nrow(rows)) / max(1L, as.integer(chunk_size))))

  for (idxs in chunk_ids) {
    value_rows <- vapply(idxs, function(row_idx) {
      literals <- vapply(column_names, function(col_name) {
        build_sql_literal(rows[[col_name]][[row_idx]])
      }, character(1))
      sprintf("(%s)", paste(literals, collapse = ", "))
    }, character(1))

    sql <- sprintf(
      "INSERT INTO %s (%s) VALUES %s",
      table_name,
      paste(column_names, collapse = ", "),
      paste(value_rows, collapse = ", ")
    )
    DBI::dbExecute(conn, sql)
  }

  invisible(NULL)
}

insert_analysis_detections <- function(conn, rows) {
  if (nrow(rows) == 0) {
    return(invisible(NULL))
  }

  insert_rows_with_values_sql(conn, "analysis_detections", rows)
  info(sprintf("Inserted %d detection summary row(s)", nrow(rows)))
}

insert_analysis_detection_events <- function(conn, rows) {
  if (nrow(rows) == 0) {
    return(invisible(NULL))
  }

  DBI::dbWriteTable(conn, "analysis_detection_events", rows, append = TRUE, row.names = FALSE)
  info(sprintf("Inserted %d detection event row(s)", nrow(rows)))
}

fetch_scalar_count <- function(conn, sql) {
  result <- DBI::dbGetQuery(conn, sql)
  if (nrow(result) == 0) {
    return(0)
  }
  safe_numeric(result[[1]][[1]])
}

fetch_latest_completed_analysis_time <- function(conn) {
  result <- DBI::dbGetQuery(conn, "
    SELECT max(finished_at) AS finished_at
    FROM analysis_runs
    WHERE status = 'completed'
  ")

  if (nrow(result) == 0 || is.null(result$finished_at[[1]]) || is.na(result$finished_at[[1]])) {
    return(NULL)
  }

  as.POSIXct(result$finished_at[[1]], tz = "UTC")
}

fetch_pending_source_keys <- function(conn) {
  latest_finished <- fetch_latest_completed_analysis_time(conn)

  sql <- if (is.null(latest_finished)) {
    "
      SELECT DISTINCT source_key
      FROM etl_objects
      WHERE status = 'loaded'
      ORDER BY source_key
    "
  } else {
    sprintf("
      SELECT DISTINCT source_key
      FROM etl_objects
      WHERE status = 'loaded'
        AND processed_at > toDateTime(%s)
      ORDER BY source_key
    ", quote_sql_string(format(latest_finished, "%Y-%m-%d %H:%M:%S")))
  }

  result <- DBI::dbGetQuery(conn, sql)
  if (nrow(result) == 0) {
    return(character())
  }

  safe_character(result$source_key)
}

fetch_flow_count_for_source_keys <- function(conn, source_keys = NULL) {
  fetch_scalar_count(conn, sprintf("
    SELECT count() AS cnt
    FROM network_flows
    WHERE %s
  ", build_source_key_clause(source_keys)))
}

fetch_src_window_features <- function(conn, window_minutes = 5L, source_keys = NULL) {
  sql <- sprintf("
    SELECT
      toStartOfInterval(flow_start, toIntervalMinute(%d)) AS window_start,
      src_ip,
      transport_proto,
      count() AS flow_count,
      uniqExact(dst_ip) AS uniq_dst_ips,
      uniqExact(dst_port) AS uniq_dst_ports,
      avg(ifNull(duration_sec, 0)) AS avg_duration_sec,
      max(ifNull(duration_sec, 0)) AS max_duration_sec,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_total_sum,
      sum(toFloat64(ifNull(packets_total, 0))) AS packets_total_sum,
      avg(if(flow_state IN ('S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'INT', 'REQ', 'RST', 'CLO'), 1, 0)) AS failure_ratio,
      avg(if(dst_port IN (80, 443, 8000, 8080, 8443), 1, 0)) AS web_ratio,
      avg(if(dst_port = 445, 1, 0)) AS smb_ratio,
      avg(if(dst_port IN (22, 23, 3389, 5900, 2323), 1, 0)) AS remote_admin_ratio,
      count(CASE WHEN transport_proto = 'UDP' THEN 1 END) AS udp_flow_count,
      count(CASE WHEN transport_proto = 'ICMP' THEN 1 END) AS icmp_flow_count,
      avg(CASE WHEN transport_proto = 'UDP' THEN toFloat64(ifNull(bytes_total, 0)) ELSE NULL END) AS avg_udp_bytes,
      avg(if(dst_port = 21, 1, 0)) AS ftp_ratio,
      avg(if(dst_port = 22, 1, 0)) AS ssh_ratio,
      avg(if(dst_port IN (25, 465, 587), 1, 0)) AS smtp_ratio,
      avg(if(dst_port IN (3306, 5432, 1433, 27017, 6379), 1, 0)) AS db_ratio,
      dateDiff('minute', min(flow_start), max(flow_start)) AS span_minutes
    FROM network_flows
    WHERE flow_start IS NOT NULL
      AND src_ip != ''
      AND transport_proto = 'TCP'
      AND %s
    GROUP BY window_start, src_ip, transport_proto
  ", as.integer(window_minutes), build_source_key_clause(source_keys))

  DBI::dbGetQuery(conn, sql)
}

fetch_pair_features <- function(conn, source_keys = NULL) {
  sql <- "
    SELECT
      src_ip,
      dst_ip,
      dst_port,
      transport_proto,
      any(app_proto) AS app_proto,
      min(flow_start) AS first_seen,
      max(flow_end) AS last_seen,
      dateDiff('second', min(flow_start), max(flow_end)) AS span_sec,
      count() AS flow_count,
      avg(ifNull(duration_sec, 0)) AS avg_duration_sec,
      max(ifNull(duration_sec, 0)) AS max_duration_sec,
      stddevPop(ifNull(duration_sec, 0)) AS duration_stddev,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_total_sum,
      avg(toFloat64(ifNull(bytes_total, 0))) AS avg_bytes_total,
      stddevPop(ifNull(bytes_total, 0)) AS bytes_stddev,
      sum(toFloat64(ifNull(packets_total, 0))) AS packets_total_sum,
      avg(toFloat64(ifNull(packets_total, 0))) AS avg_packets_total,
      avg(if(flow_state IN ('S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'INT', 'REQ', 'RST', 'CLO'), 1, 0)) AS failure_ratio,
      sum(toFloat64(ifNull(bytes_src, 0))) AS bytes_src_sum,
      sum(toFloat64(ifNull(bytes_dst, 0))) AS bytes_dst_sum,
      if(sum(bytes_dst) > 0, sum(bytes_src) / sum(bytes_dst), 0) AS src_dst_byte_ratio,
      uniqExact(src_port) AS uniq_src_ports
    FROM network_flows
    WHERE flow_start IS NOT NULL
      AND src_ip != ''
      AND dst_ip != ''
      AND transport_proto = 'TCP'
      AND %s
    GROUP BY src_ip, dst_ip, dst_port, transport_proto
    HAVING count() >= 3
  "

  DBI::dbGetQuery(conn, sprintf(sql, build_source_key_clause(source_keys)))
}

fetch_signature_matches <- function(conn, sql_where, source_keys = NULL) {
  sql <- sprintf("
    SELECT
      event_id,
      flow_id,
      flow_start,
      flow_end,
      src_ip,
      src_port,
      dst_ip,
      dst_port,
      transport_proto,
      app_proto,
      source_dataset,
      source_key
    FROM network_flows
    WHERE %s
      AND %s
  ", sql_where, build_source_key_clause(source_keys))

  DBI::dbGetQuery(conn, sql)
}

fetch_events_for_window_detection <- function(conn, src_ip, window_start, window_minutes, source_keys = NULL) {
  start_sql <- format(as.POSIXct(window_start, tz = "UTC"), "%Y-%m-%d %H:%M:%S")
  end_sql <- format(as.POSIXct(window_start, tz = "UTC") + as.difftime(window_minutes, units = "mins"), "%Y-%m-%d %H:%M:%S")

  sql <- sprintf("
    SELECT
      event_id,
      flow_id,
      flow_start,
      src_ip,
      src_port,
      dst_ip,
      dst_port,
      transport_proto,
      app_proto,
      source_dataset,
      source_key
    FROM network_flows
    WHERE src_ip = %s
      AND flow_start >= toDateTime(%s)
      AND flow_start < toDateTime(%s)
      AND %s
  ",
    quote_sql_string(src_ip),
    quote_sql_string(start_sql),
    quote_sql_string(end_sql),
    build_source_key_clause(source_keys)
  )

  DBI::dbGetQuery(conn, sql)
}

fetch_events_for_pair_detection <- function(conn, src_ip, dst_ip, dst_port, transport_proto, source_keys = NULL) {
  sql <- sprintf("
    SELECT
      event_id,
      flow_id,
      flow_start,
      src_ip,
      src_port,
      dst_ip,
      dst_port,
      transport_proto,
      app_proto,
      source_dataset,
      source_key
    FROM network_flows
    WHERE src_ip = %s
      AND dst_ip = %s
      AND dst_port = %s
      AND transport_proto = %s
      AND %s
  ",
    quote_sql_string(src_ip),
    quote_sql_string(dst_ip),
    ifelse(is.na(dst_port), "NULL", as.character(as.integer(dst_port))),
    quote_sql_string(transport_proto),
    build_source_key_clause(source_keys)
  )

  DBI::dbGetQuery(conn, sql)
}

close_connection <- function(conn) {
  tryCatch(DBI::dbDisconnect(conn), error = function(e) invisible(NULL))
}

fetch_exfil_candidates <- function(conn) {
  sql <- "
    SELECT
      src_ip,
      dst_ip,
      dst_port,
      transport_proto,
      any(app_proto) AS app_proto,
      count() AS flow_count,
      sum(toFloat64(ifNull(bytes_src, 0))) AS bytes_src_sum,
      sum(toFloat64(ifNull(bytes_dst, 0))) AS bytes_dst_sum,
      min(flow_start) AS first_seen,
      max(flow_end) AS last_seen,
      if(sum(bytes_dst) > 0, sum(bytes_src) / sum(bytes_dst), 99999) AS src_dst_ratio
    FROM network_flows
    WHERE flow_start IS NOT NULL
      AND src_ip != ''
      AND dst_ip != ''
    GROUP BY src_ip, dst_ip, dst_port, transport_proto
    HAVING sum(bytes_src) > 1048576
      AND (sum(bytes_dst) = 0 OR sum(bytes_src) / sum(bytes_dst) > 5)
      AND count() >= 3
    ORDER BY bytes_src_sum DESC
    LIMIT 10000
  "

  DBI::dbGetQuery(conn, sql)
}
