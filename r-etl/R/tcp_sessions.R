library(jsonlite)

# Парсинг Zeek conn.log в формате line-delimited JSON.
# Поддерживается также передача уже разобранного списка записей.
parse_zeek_conn_log <- function(records) {
  if (length(records) == 0) {
    return(empty_tcp_sessions_df())
  }

  rows <- lapply(records, function(r) {
    list(
      uid           = r[["uid"]]              %||% NA_character_,
      ts_raw        = r[["ts"]]               %||% NA_real_,
      proto         = r[["proto"]]            %||% NA_character_,
      service       = r[["service"]]          %||% NA_character_,
      orig_h        = r[["id.orig_h"]]        %||% r$id$orig_h %||% NA_character_,
      orig_p        = r[["id.orig_p"]]        %||% r$id$orig_p %||% NA_integer_,
      resp_h        = r[["id.resp_h"]]        %||% r$id$resp_h %||% NA_character_,
      resp_p        = r[["id.resp_p"]]        %||% r$id$resp_p %||% NA_integer_,
      duration      = r[["duration"]]         %||% NA_real_,
      orig_bytes    = r[["orig_bytes"]]       %||% NA_real_,
      resp_bytes    = r[["resp_bytes"]]       %||% NA_real_,
      conn_state    = r[["conn_state"]]       %||% NA_character_,
      missed_bytes  = r[["missed_bytes"]]     %||% NA_real_,
      history       = r[["history"]]          %||% NA_character_,
      orig_pkts     = r[["orig_pkts"]]        %||% NA_real_,
      orig_ip_bytes = r[["orig_ip_bytes"]]    %||% NA_real_,
      resp_pkts     = r[["resp_pkts"]]        %||% NA_real_,
      resp_ip_bytes = r[["resp_ip_bytes"]]    %||% NA_real_,
      local_orig    = r[["local_orig"]]       %||% NA,
      local_resp    = r[["local_resp"]]       %||% NA
    )
  })

  do.call(rbind.data.frame, c(rows, list(stringsAsFactors = FALSE)))
}

# Только TCP-сессии, остальное отбрасывается на уровне нормализации.
normalize_tcp_sessions <- function(df) {
  if (nrow(df) == 0) {
    return(empty_tcp_sessions_df())
  }

  df <- df[!is.na(df$proto) & toupper(df$proto) == "TCP", , drop = FALSE]
  if (nrow(df) == 0) {
    return(empty_tcp_sessions_df())
  }

  ts_numeric <- suppressWarnings(as.numeric(df$ts_raw))
  ts_parsed  <- as.POSIXct(ts_numeric, origin = "1970-01-01", tz = "UTC")

  data.frame(
    uid              = as.character(df$uid),
    ts               = ts_parsed,
    orig_h           = vapply(df$orig_h, normalize_ipv4,   character(1), USE.NAMES = FALSE),
    orig_p           = normalize_port(df$orig_p),
    resp_h           = vapply(df$resp_h, normalize_ipv4,   character(1), USE.NAMES = FALSE),
    resp_p           = normalize_port(df$resp_p),
    proto            = "TCP",
    service          = ifelse(is.na(df$service), "", as.character(df$service)),
    duration_sec     = vapply(df$duration,      to_float32, numeric(1), USE.NAMES = FALSE),
    orig_bytes       = vapply(df$orig_bytes,    to_uint64,  numeric(1), USE.NAMES = FALSE),
    resp_bytes       = vapply(df$resp_bytes,    to_uint64,  numeric(1), USE.NAMES = FALSE),
    conn_state       = ifelse(is.na(df$conn_state), "", as.character(df$conn_state)),
    missed_bytes     = vapply(df$missed_bytes,  to_uint64,  numeric(1), USE.NAMES = FALSE),
    history          = ifelse(is.na(df$history), "", as.character(df$history)),
    orig_pkts        = vapply(df$orig_pkts,     to_uint64,  numeric(1), USE.NAMES = FALSE),
    orig_ip_bytes    = vapply(df$orig_ip_bytes, to_uint64,  numeric(1), USE.NAMES = FALSE),
    resp_pkts        = vapply(df$resp_pkts,     to_uint64,  numeric(1), USE.NAMES = FALSE),
    resp_ip_bytes    = vapply(df$resp_ip_bytes, to_uint64,  numeric(1), USE.NAMES = FALSE),
    local_orig       = as.integer(as.logical(df$local_orig)),
    local_resp       = as.integer(as.logical(df$local_resp)),
    stringsAsFactors = FALSE
  )
}

empty_tcp_sessions_df <- function() {
  data.frame(
    uid           = character(0),
    ts            = as.POSIXct(character(0), tz = "UTC"),
    orig_h        = character(0),
    orig_p        = integer(0),
    resp_h        = character(0),
    resp_p        = integer(0),
    proto         = character(0),
    service       = character(0),
    duration_sec  = numeric(0),
    orig_bytes    = numeric(0),
    resp_bytes    = numeric(0),
    conn_state    = character(0),
    missed_bytes  = numeric(0),
    history       = character(0),
    orig_pkts     = numeric(0),
    orig_ip_bytes = numeric(0),
    resp_pkts     = numeric(0),
    resp_ip_bytes = numeric(0),
    local_orig    = integer(0),
    local_resp    = integer(0),
    stringsAsFactors = FALSE
  )
}

`%||%` <- function(a, b) if (is.null(a) || (length(a) == 1 && is.na(a))) b else a
