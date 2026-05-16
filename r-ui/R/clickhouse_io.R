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

format_time_bound <- function(value, end = FALSE) {
  if (is.null(value) || length(value) == 0 || is.na(value)) {
    return(NULL)
  }

  ts_value <- as.POSIXct(value, tz = "UTC")
  if (is.na(ts_value)) {
    return(NULL)
  }

  if (inherits(value, "Date")) {
    ts_value <- as.POSIXct(sprintf(
      "%s %s",
      format(ts_value, "%Y-%m-%d"),
      if (isTRUE(end)) "23:59:59" else "00:00:00"
    ), tz = "UTC")
  }

  format(ts_value, "%Y-%m-%d %H:%M:%S")
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

fetch_detection_time_range <- function() {
  safe_query("
    SELECT
      min(created_at) AS min_ts,
      max(created_at) AS max_ts
    FROM analysis_detections
    WHERE created_at IS NOT NULL
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

build_detection_sources_subquery <- function() {
  "
    SELECT
      e.detection_id AS detection_id,
      arrayStringConcat(arraySort(groupUniqArray(ifNull(f.source_dataset, e.source_dataset))), ', ') AS source_dataset,
      arrayStringConcat(arraySort(groupUniqArray(ifNull(f.source_format, ''))), ', ') AS source_format,
      arrayStringConcat(arraySort(groupUniqArray(ifNull(f.source_key, e.source_key))), ', ') AS source_key,
      arrayStringConcat(arraySort(groupUniqArray(ifNull(f.source_file_name, ''))), ', ') AS source_file_name
    FROM analysis_detection_events e
    LEFT JOIN network_flows f ON f.event_id = e.event_id
    GROUP BY e.detection_id
  "
}

fetch_detection_filter_options <- function() {
  source_sql <- build_detection_sources_subquery()

  list(
    source_formats = safe_query(sprintf("
      SELECT source_format
      FROM (%s)
      ARRAY JOIN splitByString(', ', source_format) AS source_format
      WHERE source_format != ''
      GROUP BY source_format
      ORDER BY source_format
    ", source_sql), fallback = data.frame(source_format = character())),
    source_datasets = safe_query(sprintf("
      SELECT source_dataset
      FROM (%s)
      ARRAY JOIN splitByString(', ', source_dataset) AS source_dataset
      WHERE source_dataset != ''
      GROUP BY source_dataset
      ORDER BY source_dataset
    ", source_sql), fallback = data.frame(source_dataset = character()))
  )
}

fetch_detections_filtered <- function(detector_types = NULL,
                                      severities = NULL,
                                      src_ip = NULL,
                                      dst_ip = NULL,
                                      source_formats = NULL,
                                      source_datasets = NULL,
                                      source_key_pattern = NULL,
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

  if (!is.null(source_formats) && length(source_formats) > 0) {
    source_format_conditions <- vapply(source_formats, function(value) {
      sprintf("positionCaseInsensitiveUTF8(ifNull(src.source_format, ''), %s) > 0", quote_sql(value))
    }, character(1))
    conditions <- c(conditions, sprintf("(%s)", paste(source_format_conditions, collapse = " OR ")))
  }

  if (!is.null(source_datasets) && length(source_datasets) > 0) {
    source_dataset_conditions <- vapply(source_datasets, function(value) {
      sprintf("positionCaseInsensitiveUTF8(ifNull(src.source_dataset, ''), %s) > 0", quote_sql(value))
    }, character(1))
    conditions <- c(conditions, sprintf("(%s)", paste(source_dataset_conditions, collapse = " OR ")))
  }

  if (!is.null(source_key_pattern) && nzchar(source_key_pattern)) {
    conditions <- c(conditions, sprintf(
      "positionCaseInsensitiveUTF8(ifNull(src.source_key, ''), %s) > 0",
      quote_sql(source_key_pattern)
    ))
  }

  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("created_at >= toDateTime(%s)",
                                        quote_sql(format_time_bound(date_from, end = FALSE))))
  }

  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("created_at <= toDateTime(%s)",
                                        quote_sql(format_time_bound(date_to, end = TRUE))))
  }

  where_clause <- if (length(conditions) == 0) "1=1" else paste(conditions, collapse = " AND ")
  source_sql <- build_detection_sources_subquery()

  safe_query(sprintf("
    SELECT
      d.detection_id,
      d.analysis_run_id,
      d.detector_type,
      d.detector_name,
      d.rule_id,
      d.rule_name,
      d.severity,
      d.confidence_score,
      d.entity_value,
      d.src_ip,
      d.src_port,
      d.dst_ip,
      d.dst_port,
      d.transport_proto,
      d.app_proto,
      ifNull(src.source_dataset, '') AS source_dataset,
      ifNull(src.source_format, '') AS source_format,
      ifNull(src.source_key, '') AS source_key,
      ifNull(src.source_file_name, '') AS source_file_name,
      d.first_seen,
      d.last_seen,
      d.flow_count,
      d.created_at
    FROM analysis_detections d
    LEFT JOIN (%s) src ON src.detection_id = d.detection_id
    WHERE %s
    ORDER BY d.created_at DESC
    LIMIT %d
  ", source_sql, where_clause, as.integer(limit)))
}

fetch_detection_by_id <- function(detection_id) {
  source_sql <- build_detection_sources_subquery()
  safe_query(sprintf("
    SELECT
      d.*,
      ifNull(src.source_dataset, '') AS source_dataset,
      ifNull(src.source_format, '') AS source_format,
      ifNull(src.source_key, '') AS source_key,
      ifNull(src.source_file_name, '') AS source_file_name
    FROM analysis_detections d
    LEFT JOIN (%s) src ON src.detection_id = d.detection_id
    WHERE d.detection_id = %s
    LIMIT 1
  ", source_sql, quote_sql(detection_id)))
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
      f.source_key      AS source_key,
      f.source_format   AS source_format,
      f.source_file_name AS source_file_name
    FROM analysis_detection_events e
    LEFT JOIN network_flows f ON f.event_id = e.event_id
    WHERE e.detection_id = %s
    ORDER BY f.flow_start
    LIMIT %d
  ", quote_sql(detection_id), as.integer(limit)))
}

fetch_traffic_timeline <- function(bucket_seconds = 300L, date_from = NULL, date_to = NULL) {
  conditions <- c("flow_start IS NOT NULL")
  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format_time_bound(date_from, end = FALSE))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format_time_bound(date_to, end = TRUE))))
  }

  safe_query(sprintf("
    SELECT
      toStartOfInterval(flow_start, toIntervalSecond(%d)) AS bucket,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      sum(toFloat64(ifNull(packets_total, 0))) AS packets_sum,
      uniqExact(src_ip) AS uniq_src_ips,
      uniqExact(dst_ip) AS uniq_dst_ips
    FROM network_flows
    WHERE %s
    GROUP BY bucket
    ORDER BY bucket
  ", as.integer(bucket_seconds), paste(conditions, collapse = " AND ")))
}

fetch_traffic_timeline_by_severity <- function(bucket_seconds = 300L, date_from = NULL, date_to = NULL) {
  conditions <- c("d.first_seen IS NOT NULL")
  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("d.first_seen >= toDateTime(%s)", quote_sql(format_time_bound(date_from, end = FALSE))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("d.first_seen <= toDateTime(%s)", quote_sql(format_time_bound(date_to, end = TRUE))))
  }

  safe_query(sprintf("
    SELECT
      toStartOfInterval(d.first_seen, toIntervalSecond(%d)) AS bucket,
      d.severity AS severity,
      count() AS detections
    FROM analysis_detections d
    WHERE %s
    GROUP BY bucket, d.severity
    ORDER BY bucket
  ", as.integer(bucket_seconds), paste(conditions, collapse = " AND ")))
}

fetch_top_src_ips <- function(limit = 15L, date_from = NULL, date_to = NULL) {
  conditions <- c("src_ip != ''")
  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format_time_bound(date_from, end = FALSE))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format_time_bound(date_to, end = TRUE))))
  }

  safe_query(sprintf("
    SELECT
      src_ip,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      uniqExact(dst_ip) AS uniq_dst,
      uniqExact(dst_port) AS uniq_dst_ports
    FROM network_flows
    WHERE %s
    GROUP BY src_ip
    ORDER BY flows DESC
    LIMIT %d
  ", paste(conditions, collapse = " AND "), as.integer(limit)))
}

fetch_top_dst_ips <- function(limit = 15L, date_from = NULL, date_to = NULL) {
  conditions <- c("dst_ip != ''")
  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format_time_bound(date_from, end = FALSE))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format_time_bound(date_to, end = TRUE))))
  }

  safe_query(sprintf("
    SELECT
      dst_ip,
      count() AS flows,
      sum(toFloat64(ifNull(bytes_total, 0))) AS bytes_sum,
      uniqExact(src_ip) AS uniq_src,
      uniqExact(dst_port) AS uniq_dst_ports
    FROM network_flows
    WHERE %s
    GROUP BY dst_ip
    ORDER BY flows DESC
    LIMIT %d
  ", paste(conditions, collapse = " AND "), as.integer(limit)))
}

fetch_ip_pair_matrix <- function(src_limit = 15L, dst_limit = 15L, date_from = NULL, date_to = NULL) {
  conditions <- character()
  if (!is.null(date_from)) {
    conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format_time_bound(date_from, end = FALSE))))
  }
  if (!is.null(date_to)) {
    conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format_time_bound(date_to, end = TRUE))))
  }
  where_suffix <- if (length(conditions) == 0) "" else paste0(" AND ", paste(conditions, collapse = " AND "))

  safe_query(sprintf("
    WITH
      top_src AS (
        SELECT src_ip FROM network_flows
        WHERE src_ip != ''
        %s
        GROUP BY src_ip ORDER BY count() DESC LIMIT %d
      ),
      top_dst AS (
        SELECT dst_ip FROM network_flows
        WHERE dst_ip != ''
        %s
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
      %s
    GROUP BY src_ip, dst_ip
  ", where_suffix, as.integer(src_limit), where_suffix, as.integer(dst_limit), where_suffix))
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
