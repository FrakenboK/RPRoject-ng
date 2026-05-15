library(jsonlite)

resolve_zeek_binary <- function() {
  zeek_bin <- Sys.which("zeek")
  if (nzchar(zeek_bin)) {
    return(zeek_bin)
  }

  fallback <- "/opt/zeek/bin/zeek"
  if (file.exists(fallback)) {
    return(fallback)
  }

  stop("Zeek binary was not found in PATH or /opt/zeek/bin/zeek")
}

parse_pcap_with_zeek <- function(path, source_object, ingest_run_id, staging_dir) {
  info(sprintf("Running Zeek for %s", source_object$key))

  output_dir <- file.path(
    staging_dir,
    ".zeek",
    gsub("[^A-Za-z0-9._-]", "_", source_object$key)
  )
  ensure_dir(output_dir)

  old_wd <- getwd()
  on.exit(setwd(old_wd), add = TRUE)
  setwd(output_dir)

  run_command(
    command = resolve_zeek_binary(),
    args = c(
      "-C",
      "-r", normalizePath(path, winslash = "/", mustWork = TRUE),
      "LogAscii::use_json=T"
    )
  )

  conn_log_path <- file.path(output_dir, "conn.log")
  if (!file.exists(conn_log_path)) {
    stop(sprintf("Zeek did not produce conn.log for %s", source_object$key))
  }

  parse_zeek_conn_log_file(conn_log_path, source_object, ingest_run_id)
}

parse_zeek_conn_log_file <- function(log_path, source_object, ingest_run_id) {
  lines <- readLines(log_path, warn = FALSE, encoding = "UTF-8")
  lines <- lines[nzchar(trimws(lines)) & !startsWith(trimws(lines), "#")]

  if (length(lines) == 0) {
    return(empty_network_flows())
  }

  records <- lapply(lines, function(line) {
    jsonlite::fromJSON(line, simplifyVector = FALSE)
  })

  rows <- lapply(records, function(record) {
    list(
      uid = record[["uid"]] %||% "",
      ts = record[["ts"]] %||% NA_real_,
      orig_h = record[["id.orig_h"]] %||% "",
      orig_p = record[["id.orig_p"]] %||% NA_integer_,
      resp_h = record[["id.resp_h"]] %||% "",
      resp_p = record[["id.resp_p"]] %||% NA_integer_,
      proto = record[["proto"]] %||% "",
      service = record[["service"]] %||% "",
      duration = record[["duration"]] %||% NA_real_,
      orig_bytes = record[["orig_bytes"]] %||% NA_real_,
      resp_bytes = record[["resp_bytes"]] %||% NA_real_,
      conn_state = record[["conn_state"]] %||% "",
      history = record[["history"]] %||% "",
      orig_pkts = record[["orig_pkts"]] %||% NA_real_,
      resp_pkts = record[["resp_pkts"]] %||% NA_real_,
      orig_ip_bytes = record[["orig_ip_bytes"]] %||% NA_real_,
      resp_ip_bytes = record[["resp_ip_bytes"]] %||% NA_real_,
      local_orig = record[["local_orig"]] %||% NA,
      local_resp = record[["local_resp"]] %||% NA
    )
  })

  dt <- rbindlist(rows, fill = TRUE)
  frame <- base_unified_frame(nrow(dt), source_object, ingest_run_id, "pcap_zeek_connlog", "pcap")
  frame$flow_id <- safe_character(dt$uid)
  frame$flow_start <- as.POSIXct(safe_numeric(dt$ts), origin = "1970-01-01", tz = "UTC")
  frame$duration_sec <- safe_numeric(dt$duration)
  frame$flow_end <- frame$flow_start + frame$duration_sec
  frame$src_ip <- safe_character(dt$orig_h)
  frame$src_port <- safe_port(dt$orig_p)
  frame$dst_ip <- safe_character(dt$resp_h)
  frame$dst_port <- safe_port(dt$resp_p)
  frame$transport_proto <- safe_character(dt$proto)
  frame$app_proto <- safe_character(dt$service)
  frame$flow_state <- safe_character(dt$conn_state)
  frame$packets_src <- safe_uint64(dt$orig_pkts)
  frame$packets_dst <- safe_uint64(dt$resp_pkts)
  frame$packets_total <- safe_uint64(safe_numeric(dt$orig_pkts) + safe_numeric(dt$resp_pkts))
  frame$bytes_src <- safe_uint64(dt$orig_bytes)
  frame$bytes_dst <- safe_uint64(dt$resp_bytes)
  frame$bytes_total <- safe_uint64(safe_numeric(dt$orig_bytes) + safe_numeric(dt$resp_bytes))
  frame$attributes_json <- rep("{}", nrow(frame))

  finalize_network_flows(frame)
}
