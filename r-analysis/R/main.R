source("R/utils.R")
source("R/clickhouse_io.R")
source("R/signature_rules.R")
source("R/behavioral_detectors.R")

start_analysis_run <- function(conn, analysis_run_id, source_keys = NULL, message = "") {
  run_row <- data.frame(
    analysis_run_id = analysis_run_id,
    started_at = Sys.time(),
    finished_at = as.POSIXct(NA, origin = "1970-01-01", tz = "UTC"),
    status = "running",
    source_table = "network_flows",
    flow_rows_scanned = fetch_flow_count_for_source_keys(conn, source_keys),
    detections_total = NA_real_,
    signature_total = NA_real_,
    behavioral_total = NA_real_,
    message = message,
    stringsAsFactors = FALSE
  )

  insert_analysis_run(conn, run_row)
  run_row
}

finish_analysis_run <- function(conn, analysis_run_id, status, detections_total, signature_total, behavioral_total, message = "") {
  DBI::dbExecute(conn, sprintf("
    ALTER TABLE analysis_runs
    UPDATE
      finished_at = toDateTime(%s),
      status = %s,
      detections_total = %s,
      signature_total = %s,
      behavioral_total = %s,
      message = %s
    WHERE analysis_run_id = %s
  ",
    quote_sql_string(format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
    quote_sql_string(status),
    as.character(as.integer(detections_total)),
    as.character(as.integer(signature_total)),
    as.character(as.integer(behavioral_total)),
    quote_sql_string(message),
    quote_sql_string(analysis_run_id)
  ))
}

run_analysis_pipeline <- function() {
  analysis_run_id <- build_analysis_run_id()
  conn <- get_clickhouse_connection()
  on.exit(close_connection(conn), add = TRUE)

  if (!test_connection(conn)) {
    stop("ClickHouse connection test failed")
  }

  create_all_analysis_tables(conn)
  mark_stale_analysis_runs_failed(conn)
  pending_source_keys <- fetch_pending_source_keys(conn)
  start_analysis_run(
    conn,
    analysis_run_id,
    source_keys = pending_source_keys,
    message = if (length(pending_source_keys) == 0) "no new source objects to analyze" else ""
  )
  completed <- FALSE
  on.exit({
    if (!completed) {
      tryCatch(
        finish_analysis_run(
          conn = conn,
          analysis_run_id = analysis_run_id,
          status = "failed",
          detections_total = 0L,
          signature_total = 0L,
          behavioral_total = 0L,
          message = "analysis pipeline failed"
        ),
        error = function(e) invisible(NULL)
      )
    }
  }, add = TRUE)

  rules_dir <- Sys.getenv("SIGMA_RULES_DIR", "/app/rules/signature")
  window_minutes <- safe_integer(Sys.getenv("ANALYSIS_WINDOW_MINUTES", "5"))
  if (is.na(window_minutes) || window_minutes <= 0L) {
    window_minutes <- 5L
  }

  if (length(pending_source_keys) == 0) {
    finish_analysis_run(
      conn = conn,
      analysis_run_id = analysis_run_id,
      status = "completed",
      detections_total = 0L,
      signature_total = 0L,
      behavioral_total = 0L,
      message = "No new ETL objects found for analysis"
    )
    completed <- TRUE
    info("Analysis skipped: no new ETL objects found")
    return(invisible(NULL))
  }

  signature <- run_signature_analysis(conn, analysis_run_id, rules_dir, source_keys = pending_source_keys)
  behavioral <- run_behavioral_analysis(
    conn,
    analysis_run_id,
    window_minutes = window_minutes,
    source_keys = pending_source_keys
  )

  signature_detections <- if (nrow(signature$detections) == 0) 0L else nrow(signature$detections)
  behavioral_detections <- if (nrow(behavioral$detections) == 0) 0L else nrow(behavioral$detections)

  all_detections <- if (signature_detections + behavioral_detections == 0) {
    data.frame()
  } else {
    data.table::rbindlist(list(signature$detections, behavioral$detections), fill = TRUE)
  }

  all_events <- if (nrow(signature$events) + nrow(behavioral$events) == 0) {
    data.frame()
  } else {
    data.table::rbindlist(list(signature$events, behavioral$events), fill = TRUE)
  }

  insert_analysis_detections(conn, all_detections)
  insert_analysis_detection_events(conn, all_events)

  finish_analysis_run(
    conn = conn,
    analysis_run_id = analysis_run_id,
    status = "completed",
    detections_total = nrow(all_detections),
    signature_total = signature_detections,
    behavioral_total = behavioral_detections,
    message = ""
  )
  completed <- TRUE

  info(sprintf(
    "Analysis completed successfully: %d total detections (%d signature, %d behavioral)",
    nrow(all_detections),
    signature_detections,
    behavioral_detections
  ))
}

main <- function() {
  tryCatch(
    run_analysis_pipeline(),
    error = function(e) {
      error_log(e$message)
      stop(e)
    }
  )
}

if (!interactive()) {
  main()
}
