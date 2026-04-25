source("R/utils.R")
source("R/s3_io.R")
source("R/parsing.R")
source("R/normalization.R")
source("R/clickhouse_io.R")
source("R/tcp_sessions.R")

run_etl_pipeline <- function(s3_bucket_url, item_name) {
  info("Starting ETL pipeline")
  info(sprintf("S3 Bucket: %s", s3_bucket_url))
  info(sprintf("Item: %s", item_name))

  json_data <- tryCatch({
    info("Fetching data from S3")
    get_s3_item(s3_bucket_url, item_name)
  }, error = function(e) {
    error_log(sprintf("Failed to fetch data from S3: %s", e$message))
    stop(e)
  })

  parsed_data <- tryCatch({
    info("Parsing JSON data")
    parse_captipper_json(json_data)
  }, error = function(e) {
    error_log(sprintf("Failed to parse JSON data: %s", e$message))
    stop(e)
  })

  normalized_data <- tryCatch({
    info("Normalizing parsed data")
    normalize_parsed_data(parsed_data)
  }, error = function(e) {
    error_log(sprintf("Failed to normalize data: %s", e$message))
    stop(e)
  })

  # Опциональный шаг: загрузка TCP-сессий из Zeek conn.log (NDJSON) в S3.
  conn_log_prefix <- Sys.getenv("S3_CONN_LOG_PREFIX", "")
  if (nchar(conn_log_prefix) > 0) {
    normalized_data$tcp_sessions <- tryCatch({
      info(sprintf("Fetching Zeek conn.log: %s", conn_log_prefix))
      records <- get_s3_ndjson(s3_bucket_url, conn_log_prefix)
      info(sprintf("Loaded %d conn.log record(s)", length(records)))
      normalize_tcp_sessions(parse_zeek_conn_log(records))
    }, error = function(e) {
      warning_log(sprintf("Skipping TCP sessions: %s", e$message))
      empty_tcp_sessions_df()
    })
  }

  conn <- tryCatch({
    info("Connecting to ClickHouse")
    get_clickhouse_connection()
  }, error = function(e) {
    error_log(sprintf("Failed to connect to ClickHouse: %s", e$message))
    stop(e)
  })

  tryCatch({
    if (!test_connection(conn)) {
      stop("ClickHouse connection test failed")
    }

    info("Creating tables")
    create_all_tables(conn)

    info("Inserting normalized data")
    insert_normalized_data(conn, normalized_data)

    info("ETL pipeline completed successfully")
  }, error = function(e) {
    error_log(sprintf("ETL pipeline failed: %s", e$message))
    stop(e)
  }, finally = {
    close_connection(conn)
  })

  invisible(normalized_data)
}

main <- function() {
  args <- commandArgs(trailingOnly = TRUE)

  # Поддерживаем два режима запуска:
  # 1. Через аргументы командной строки: Rscript main.R <s3_bucket_url> <item_name>
  # 2. Через env-переменные S3_ENDPOINT_URL и S3_PREFIX (Docker-режим)
  if (length(args) >= 2) {
    s3_bucket_url <- args[1]
    item_name <- args[2]
  } else {
    s3_bucket_url <- Sys.getenv("S3_ENDPOINT_URL", "")
    item_name <- Sys.getenv("S3_PREFIX", "dump.json")

    if (nchar(s3_bucket_url) == 0) {
      error_log("No S3 source configured. Set S3_ENDPOINT_URL and S3_PREFIX env vars, or pass args: Rscript main.R <s3_bucket_url> <item_name>")
      stop("Missing S3 configuration")
    }

    # если S3_PREFIX пустой — берём последний сегмент URL как имя файла
    if (nchar(item_name) == 0) {
      item_name <- basename(s3_bucket_url)
      if (nchar(item_name) == 0) item_name <- "dump.json"
    }
  }

  run_etl_pipeline(s3_bucket_url, item_name)
}

if (!interactive()) {
  main()
}
