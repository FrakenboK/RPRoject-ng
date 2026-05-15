source("R/utils.R")
source("R/normalization.R")
source("R/s3_io.R")
source("R/parsing.R")
source("R/tcp_sessions.R")
source("R/clickhouse_io.R")

process_source_object <- function(conn, source_object, ingest_run_id, staging_dir) {
  local_path <- download_s3_object(
    bucket = source_object$bucket,
    key = source_object$key,
    destination_root = staging_dir
  )

  handler <- choose_handler(source_object$key, local_path)
  if (identical(handler, "unsupported")) {
    warning_log(sprintf("Skipping unsupported object: %s", source_object$key))
    insert_etl_object_status(conn, build_object_status_row(
      ingest_run_id = ingest_run_id,
      source_object = source_object,
      handler_name = "unsupported",
      status = "skipped",
      records_loaded = 0,
      message = "Unsupported file type"
    ))
    return(invisible(NULL))
  }

  info(sprintf("Processing %s with handler %s", source_object$key, handler))

  if (handler == "zip") {
    rows_loaded <- process_zip_archive_into_clickhouse(
      conn = conn,
      path = local_path,
      source_object = source_object,
      ingest_run_id = ingest_run_id
    )
  } else {
    flows <- switch(
      handler,
      pcap_zeek = parse_pcap_with_zeek(local_path, source_object, ingest_run_id, staging_dir),
      binetflow = parse_binetflow_file(local_path, source_object, ingest_run_id),
      csv = parse_csv_file(local_path, source_object, ingest_run_id),
      stop(sprintf("Unsupported handler: %s", handler))
    )

    if (nrow(flows) > 0) {
      insert_network_flows(conn, flows)
    } else {
      warning_log(sprintf("Handler %s produced zero rows for %s", handler, source_object$key))
    }

    rows_loaded <- nrow(flows)
  }

  insert_etl_object_status(conn, build_object_status_row(
    ingest_run_id = ingest_run_id,
    source_object = source_object,
    handler_name = handler,
    status = "loaded",
    records_loaded = rows_loaded,
    message = ""
  ))

  invisible(rows_loaded)
}

run_etl_pipeline <- function() {
  config <- get_runtime_config()
  init_runtime_dirs(config$staging_dir)

  ingest_run_id <- build_ingest_run_id()
  info(sprintf("Starting ETL init-container run: %s", ingest_run_id))
  info(sprintf("S3 bucket: %s | prefix: %s", config$s3_bucket, config$s3_prefix))

  source_objects <- list_s3_objects(config$s3_bucket, config$s3_prefix)
  source_objects <- filter_source_objects(source_objects)

  if (nrow(source_objects) == 0) {
    warning_log("No source objects found in S3 prefix")
    return(invisible(NULL))
  }

  info(sprintf("Discovered %d object(s) in bucket", nrow(source_objects)))

  conn <- get_clickhouse_connection()
  on.exit(close_connection(conn), add = TRUE)

  if (!test_connection(conn)) {
    stop("ClickHouse connection test failed")
  }

  create_all_tables(conn)

  failures <- character(0)

  for (row_idx in seq_len(nrow(source_objects))) {
    source_object <- source_objects[row_idx, , drop = FALSE]

    tryCatch({
      process_source_object(conn, source_object, ingest_run_id, config$staging_dir)
    }, error = function(e) {
      failures <<- c(failures, source_object$key)
      error_log(sprintf("Failed to process %s: %s", source_object$key, e$message))

      insert_etl_object_status(conn, build_object_status_row(
        ingest_run_id = ingest_run_id,
        source_object = source_object,
        handler_name = choose_handler(source_object$key, source_object$key),
        status = "failed",
        records_loaded = 0,
        message = e$message
      ))
    })
  }

  if (length(failures) > 0) {
    stop(sprintf(
      "ETL finished with %d failed object(s): %s",
      length(failures),
      paste(failures, collapse = ", ")
    ))
  }

  info("ETL pipeline completed successfully")
  invisible(NULL)
}

main <- function() {
  run_etl_pipeline()
}

if (!interactive()) {
  main()
}
