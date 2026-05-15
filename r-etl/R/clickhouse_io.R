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

create_network_flows_table <- function(conn) {
  DBI::dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS network_flows (
      event_id            String,
      ingest_run_id       String,
      source_dataset      LowCardinality(String),
      source_key          String,
      source_file_name    String,
      source_format       LowCardinality(String),
      handler_name        LowCardinality(String),
      source_record_index UInt64,
      flow_id             String,
      flow_start          Nullable(DateTime),
      flow_end            Nullable(DateTime),
      duration_sec        Nullable(Float64),
      src_ip              String,
      src_port            Nullable(UInt16),
      dst_ip              String,
      dst_port            Nullable(UInt16),
      ip_version          LowCardinality(String),
      transport_proto     LowCardinality(String),
      app_proto           LowCardinality(String),
      flow_state          LowCardinality(String),
      direction           String,
      packets_total       Nullable(UInt64),
      packets_src         Nullable(UInt64),
      packets_dst         Nullable(UInt64),
      bytes_total         Nullable(UInt64),
      bytes_src           Nullable(UInt64),
      bytes_dst           Nullable(UInt64),
      src_ttl             Nullable(UInt16),
      dst_ttl             Nullable(UInt16),
      rtt_sec             Nullable(Float64),
      synack_sec          Nullable(Float64),
      ackdat_sec          Nullable(Float64),
      source_label        String,
      attack_category     String,
      is_malicious        Nullable(UInt8),
      attributes_json     String
    ) ENGINE = MergeTree()
    ORDER BY (source_dataset, source_key, source_record_index)
  ")
}

create_etl_objects_table <- function(conn) {
  DBI::dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS etl_objects (
      ingest_run_id    String,
      source_key       String,
      source_dataset   LowCardinality(String),
      source_format    LowCardinality(String),
      handler_name     LowCardinality(String),
      object_size      Nullable(UInt64),
      status           LowCardinality(String),
      records_loaded   Nullable(UInt64),
      processed_at     DateTime,
      message          String
    ) ENGINE = MergeTree()
    ORDER BY (processed_at, source_key)
  ")
}

create_all_tables <- function(conn) {
  create_network_flows_table(conn)
  create_etl_objects_table(conn)
}

prepare_network_flows_for_insert <- function(df) {
  if (nrow(df) == 0) {
    return(df)
  }

  string_cols <- c(
    "event_id", "ingest_run_id", "source_dataset", "source_key", "source_file_name",
    "source_format", "handler_name", "flow_id", "src_ip", "dst_ip", "ip_version",
    "transport_proto", "app_proto", "flow_state", "direction", "source_label",
    "attack_category", "attributes_json"
  )

  for (col in string_cols) {
    df[[col]][is.na(df[[col]])] <- ""
  }

  df$is_malicious <- as.integer(df$is_malicious)
  df
}

insert_network_flows <- function(conn, flows) {
  if (nrow(flows) == 0) {
    return(invisible(NULL))
  }

  flows <- prepare_network_flows_for_insert(flows)
  DBI::dbWriteTable(conn, "network_flows", flows, append = TRUE, row.names = FALSE)
  info(sprintf("Inserted %d row(s) into network_flows", nrow(flows)))
}

build_object_status_row <- function(ingest_run_id, source_object, handler_name, status, records_loaded, message) {
  data.frame(
    ingest_run_id = ingest_run_id,
    source_key = source_object$key,
    source_dataset = source_object$dataset_name,
    source_format = source_object$extension,
    handler_name = handler_name,
    object_size = source_object$size,
    status = status,
    records_loaded = records_loaded,
    processed_at = Sys.time(),
    message = message,
    stringsAsFactors = FALSE
  )
}

insert_etl_object_status <- function(conn, status_row) {
  DBI::dbWriteTable(conn, "etl_objects", status_row, append = TRUE, row.names = FALSE)
}

test_connection <- function(conn) {
  result <- DBI::dbGetQuery(conn, "SELECT 1 AS ok")
  nrow(result) == 1 && !is.na(suppressWarnings(as.numeric(result$ok[[1]]))) &&
    suppressWarnings(as.numeric(result$ok[[1]])) == 1
}

close_connection <- function(conn) {
  tryCatch(DBI::dbDisconnect(conn), error = function(e) invisible(NULL))
}
