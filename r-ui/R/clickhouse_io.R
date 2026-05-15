library(DBI)
library(RClickhouse)

get_clickhouse_connection <- function() {
  DBI::dbConnect(
    RClickhouse::clickhouse(),
    host = Sys.getenv("CLICKHOUSE_HOST", "clickhouse"),
    port = as.integer(Sys.getenv("CLICKHOUSE_PORT", "9000")),
    user = Sys.getenv("CLICKHOUSE_USER", "default"),
    password = Sys.getenv("CLICKHOUSE_PASSWORD", ""),
    db = Sys.getenv("CLICKHOUSE_DATABASE", "default")
  )
}

with_conn <- function(action) {
  conn <- tryCatch(get_clickhouse_connection(), error = function(e) NULL)
  if (is.null(conn)) {
    return(NULL)
  }
  on.exit(tryCatch(DBI::dbDisconnect(conn), error = function(e) invisible(NULL)))
  tryCatch(action(conn), error = function(e) {
    message(sprintf("ClickHouse query failed: %s", e$message))
    NULL
  })
}

safe_query <- function(sql, fallback = data.frame()) {
  result <- with_conn(function(conn) DBI::dbGetQuery(conn, sql))
  if (is.null(result)) fallback else result
}

table_exists <- function(table_name) {
  res <- safe_query(sprintf(
    "SELECT count() AS c FROM system.tables WHERE database = currentDatabase() AND name = '%s'",
    table_name
  ), fallback = data.frame(c = 0))
  isTRUE(as.numeric(res$c[[1]]) > 0)
}

quote_sql <- function(value) {
  sprintf("'%s'", gsub("'", "''", as.character(value), fixed = TRUE))
}

quote_sql_list <- function(values) {
  paste(vapply(values, quote_sql, character(1)), collapse = ", ")
}

fetch_overview_counters <- function() {
  list(
    flows_total = as.numeric(safe_query(
      "SELECT count() AS c FROM network_flows",
      data.frame(c = 0)
    )$c[[1]]),
    objects_total = as.numeric(safe_query(
      "SELECT count() AS c FROM etl_objects",
      data.frame(c = 0)
    )$c[[1]]),
    objects_loaded = as.numeric(safe_query(
      "SELECT count() AS c FROM etl_objects WHERE status = 'loaded'",
      data.frame(c = 0)
    )$c[[1]]),
    objects_failed = as.numeric(safe_query(
      "SELECT count() AS c FROM etl_objects WHERE status = 'failed'",
      data.frame(c = 0)
    )$c[[1]]),
    runs_total = as.numeric(safe_query(
      "SELECT count() AS c FROM analysis_runs",
      data.frame(c = 0)
    )$c[[1]]),
    detections_total = as.numeric(safe_query(
      "SELECT count() AS c FROM analysis_detections",
      data.frame(c = 0)
    )$c[[1]]),
    signature_total = as.numeric(safe_query(
      "SELECT count() AS c FROM analysis_detections WHERE detector_type = 'signature'",
      data.frame(c = 0)
    )$c[[1]]),
    behavioral_total = as.numeric(safe_query(
      "SELECT count() AS c FROM analysis_detections WHERE detector_type = 'behavioral'",
      data.frame(c = 0)
    )$c[[1]])
  )
}

fetch_severity_breakdown <- function() {
  safe_query("
    SELECT severity, count() AS detections
    FROM analysis_detections
    GROUP BY severity
    ORDER BY detections DESC
  ")
}

fetch_flows_by_day <- function() {
  safe_query("
    SELECT toDate(flow_start) AS day, count() AS flows
    FROM network_flows
    WHERE flow_start IS NOT NULL
      AND flow_start >= toDateTime('2000-01-01 00:00:00')
    GROUP BY day
    ORDER BY day
  ")
}

fetch_flows_by_bucket <- function(granularity = "day", date_from = NULL, date_to = NULL) {
  bucket_expr <- switch(
    granularity,
    "day" = "toDate(flow_start)",
    "week" = "toMonday(flow_start)",
    "month" = "toStartOfMonth(flow_start)",
    "toDate(flow_start)"
  )

  conditions <- c(
    "flow_start IS NOT NULL",
    "flow_start >= toDateTime('2000-01-01 00:00:00')"
  )

  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)",
      quote_sql(format(as.POSIXct(date_from, tz = "UTC"), "%Y-%m-%d 00:00:00"))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)",
      quote_sql(format(as.POSIXct(date_to, tz = "UTC"), "%Y-%m-%d 23:59:59"))))
  }

  where_clause <- paste(conditions, collapse = " AND ")

  safe_query(sprintf("
    SELECT %s AS bucket, count() AS flows
    FROM network_flows
    WHERE %s
    GROUP BY bucket
    ORDER BY bucket
  ", bucket_expr, where_clause))
}

fetch_flow_time_range <- function() {
  safe_query("
    SELECT
      min(flow_start) AS min_ts,
      max(flow_start) AS max_ts
    FROM network_flows
    WHERE flow_start IS NOT NULL
      AND flow_start >= toDateTime('2000-01-01 00:00:00')
  ")
}

fetch_recent_runs <- function(limit = 20L) {
  safe_query(sprintf("
    SELECT
      analysis_run_id,
      started_at,
      finished_at,
      status,
      flow_rows_scanned,
      detections_total,
      signature_total,
      behavioral_total,
      message
    FROM analysis_runs
    ORDER BY started_at DESC
    LIMIT %d
  ", as.integer(limit)))
}

fetch_recent_etl_objects <- function(limit = 50L) {
  safe_query(sprintf("
    SELECT
      processed_at,
      source_key,
      source_dataset,
      source_format,
      handler_name,
      status,
      records_loaded,
      object_size,
      message
    FROM etl_objects
    ORDER BY processed_at DESC
    LIMIT %d
  ", as.integer(limit)))
}

fetch_detections_filtered <- function(detector_types = NULL,
                                      severities = NULL,
                                      src_ip = NULL,
                                      dst_ip = NULL,
                                      date_from = NULL,
                                      date_to = NULL,
                                      limit = 1000L) {
  conditions <- character()

  if (!is.null(detector_types) && length(detector_types) > 0) {
    conditions <- c(conditions, sprintf("detector_type IN (%s)", quote_sql_list(detector_types)))
  }

  if (!is.null(severities) && length(severities) > 0) {
    conditions <- c(conditions, sprintf("severity IN (%s)", quote_sql_list(severities)))
  }

  if (!is.null(src_ip) && nzchar(src_ip)) {
    conditions <- c(conditions, sprintf("src_ip = %s", quote_sql(src_ip)))
  }

  if (!is.null(dst_ip) && nzchar(dst_ip)) {
    conditions <- c(conditions, sprintf("dst_ip = %s", quote_sql(dst_ip)))
  }

  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("created_at >= toDateTime(%s)",
                                        quote_sql(format(date_from, "%Y-%m-%d 00:00:00"))))
  }

  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("created_at <= toDateTime(%s)",
                                        quote_sql(format(date_to, "%Y-%m-%d 23:59:59"))))
  }

  where_clause <- if (length(conditions) == 0) "1=1" else paste(conditions, collapse = " AND ")

  safe_query(sprintf("
    SELECT
      detection_id,
      analysis_run_id,
      detector_type,
      detector_name,
      rule_id,
      rule_name,
      severity,
      confidence_score,
      entity_value,
      src_ip,
      src_port,
      dst_ip,
      dst_port,
      transport_proto,
      app_proto,
      first_seen,
      last_seen,
      flow_count,
      created_at
    FROM analysis_detections
    WHERE %s
    ORDER BY created_at DESC
    LIMIT %d
  ", where_clause, as.integer(limit)))
}

fetch_detection_by_id <- function(detection_id) {
  safe_query(sprintf("
    SELECT *
    FROM analysis_detections
    WHERE detection_id = %s
    LIMIT 1
  ", quote_sql(detection_id)))
}

fetch_detection_events <- function(detection_id, limit = 500L) {
  safe_query(sprintf("
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
    FROM analysis_detection_events
    WHERE detection_id = %s
    ORDER BY flow_start
    LIMIT %d
  ", quote_sql(detection_id), as.integer(limit)))
}

fetch_flow_by_event_id <- function(event_id) {
  safe_query(sprintf("
    SELECT *
    FROM network_flows
    WHERE event_id = %s
    LIMIT 1
  ", quote_sql(event_id)))
}

fetch_sessions_for_detection <- function(detection_id, limit = 500L) {
  safe_query(sprintf("
    SELECT
      f.event_id        AS event_id,
      f.flow_id         AS flow_id,
      f.flow_start      AS flow_start,
      f.flow_end        AS flow_end,
      f.duration_sec    AS duration_sec,
      f.src_ip          AS src_ip,
      f.src_port        AS src_port,
      f.dst_ip          AS dst_ip,
      f.dst_port        AS dst_port,
      f.transport_proto AS transport_proto,
      f.app_proto       AS app_proto,
      f.flow_state      AS flow_state,
      f.packets_total   AS packets_total,
      f.bytes_total     AS bytes_total,
      f.bytes_src       AS bytes_src,
      f.bytes_dst       AS bytes_dst,
      f.source_dataset  AS source_dataset,
      f.source_key      AS source_key
    FROM analysis_detection_events e
    LEFT JOIN network_flows f ON f.event_id = e.event_id
    WHERE e.detection_id = %s
    ORDER BY f.flow_start
    LIMIT %d
  ", quote_sql(detection_id), as.integer(limit)))
}

fetch_traffic_timeline <- function(bucket_seconds = 300L) {
  safe_query(sprintf("
    SELECT
      toStartOfInterval(flow_start, toIntervalSecond(%d)) AS bucket,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      sum(toFloat64(ifNull(packets_total, 0))) AS packets_sum,
      uniqExact(src_ip) AS uniq_src_ips,
      uniqExact(dst_ip) AS uniq_dst_ips
    FROM network_flows
    WHERE flow_start IS NOT NULL
    GROUP BY bucket
    ORDER BY bucket
  ", as.integer(bucket_seconds)))
}

fetch_traffic_timeline_by_severity <- function(bucket_seconds = 300L) {
  safe_query(sprintf("
    SELECT
      toStartOfInterval(d.first_seen, toIntervalSecond(%d)) AS bucket,
      d.severity AS severity,
      count() AS detections
    FROM analysis_detections d
    WHERE d.first_seen IS NOT NULL
    GROUP BY bucket, d.severity
    ORDER BY bucket
  ", as.integer(bucket_seconds)))
}

fetch_top_src_ips <- function(limit = 15L) {
  safe_query(sprintf("
    SELECT
      src_ip,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      uniqExact(dst_ip) AS uniq_dst,
      uniqExact(dst_port) AS uniq_dst_ports
    FROM network_flows
    WHERE src_ip != ''
    GROUP BY src_ip
    ORDER BY flows DESC
    LIMIT %d
  ", as.integer(limit)))
}

fetch_top_dst_ips <- function(limit = 15L) {
  safe_query(sprintf("
    SELECT
      dst_ip,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      uniqExact(src_ip) AS uniq_src,
      uniqExact(dst_port) AS uniq_dst_ports
    FROM network_flows
    WHERE dst_ip != ''
    GROUP BY dst_ip
    ORDER BY flows DESC
    LIMIT %d
  ", as.integer(limit)))
}

fetch_ip_pair_matrix <- function(src_limit = 15L, dst_limit = 15L) {
  safe_query(sprintf("
    WITH
      top_src AS (
        SELECT src_ip FROM network_flows
        WHERE src_ip != ''
        GROUP BY src_ip ORDER BY count() DESC LIMIT %d
      ),
      top_dst AS (
        SELECT dst_ip FROM network_flows
        WHERE dst_ip != ''
        GROUP BY dst_ip ORDER BY count() DESC LIMIT %d
      )
    SELECT
      src_ip,
      dst_ip,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum
    FROM network_flows
    WHERE src_ip IN (SELECT src_ip FROM top_src)
      AND dst_ip IN (SELECT dst_ip FROM top_dst)
    GROUP BY src_ip, dst_ip
  ", as.integer(src_limit), as.integer(dst_limit)))
}

fetch_distinct_values <- function(table_name, column, limit = 100L) {
  safe_query(sprintf("
    SELECT %s AS v
    FROM %s
    WHERE %s != ''
    GROUP BY %s
    ORDER BY count() DESC
    LIMIT %d
  ", column, table_name, column, column, as.integer(limit)))
}
