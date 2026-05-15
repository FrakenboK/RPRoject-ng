library(jsonlite)

`%||%` <- function(a, b) {
  if (is.null(a) || length(a) == 0) {
    return(b)
  }

  if (length(a) == 1 && is.na(a)) {
    return(b)
  }

  a
}

init_logger <- function() {
  assign("log_level", toupper(Sys.getenv("LOG_LEVEL", "INFO")), envir = .GlobalEnv)
}

get_log_level <- function() {
  get("log_level", envir = .GlobalEnv)
}

should_log <- function(level) {
  levels <- c("DEBUG", "INFO", "WARNING", "ERROR")
  current <- match(get_log_level(), levels)
  target <- match(level, levels)

  if (is.na(current)) {
    current <- 2L
  }

  if (is.na(target)) {
    target <- 2L
  }

  target >= current
}

log_message <- function(level, message) {
  if (!should_log(level)) {
    return(invisible(NULL))
  }

  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  cat(sprintf("[%s] [%s] %s\n", timestamp, level, message))
  invisible(message)
}

debug <- function(message) log_message("DEBUG", message)
info <- function(message) log_message("INFO", message)
warning_log <- function(message) log_message("WARNING", message)
error_log <- function(message) log_message("ERROR", message)

build_ingest_run_id <- function() {
  format(Sys.time(), "run-%Y%m%d%H%M%S")
}

ensure_dir <- function(path) {
  if (!dir.exists(path)) {
    dir.create(path, recursive = TRUE, showWarnings = FALSE)
  }

  normalizePath(path, winslash = "/", mustWork = TRUE)
}

init_runtime_dirs <- function(staging_dir) {
  ensure_dir(staging_dir)
  invisible(TRUE)
}

run_command <- function(command, args = character(), env = character(), cwd = NULL) {
  original_wd <- getwd()
  on.exit(setwd(original_wd), add = TRUE)

  if (!is.null(cwd)) {
    setwd(cwd)
  }

  output <- system2(
    command = command,
    args = args,
    stdout = TRUE,
    stderr = TRUE,
    env = env
  )

  status <- attr(output, "status")
  if (is.null(status)) {
    status <- 0L
  }

  if (status != 0L) {
    stop(sprintf(
      "Command failed (%s %s): %s",
      command,
      paste(args, collapse = " "),
      paste(output, collapse = "\n")
    ))
  }

  output
}

safe_numeric <- function(value) {
  result <- suppressWarnings(as.numeric(value))
  result[is.infinite(result)] <- NA_real_
  result
}

safe_integer <- function(value) {
  result <- suppressWarnings(as.integer(value))
  result
}

safe_port <- function(value) {
  result <- safe_integer(value)
  result[is.na(result) | result < 0L | result > 65535L] <- NA_integer_
  result
}

safe_uint64 <- function(value) {
  result <- safe_numeric(value)
  result[is.na(result) | result < 0] <- NA_real_
  result
}

safe_bool <- function(value) {
  if (is.logical(value)) {
    return(value)
  }

  value_chr <- tolower(trimws(as.character(value)))
  result <- rep(NA, length(value_chr))
  result[value_chr %in% c("1", "true", "yes", "y")] <- TRUE
  result[value_chr %in% c("0", "false", "no", "n")] <- FALSE
  as.logical(result)
}

safe_character <- function(value) {
  result <- as.character(value)
  result[is.na(result)] <- ""
  result
}

normalize_transport_proto <- function(value) {
  value_chr <- toupper(trimws(safe_character(value)))
  value_chr[value_chr == ""] <- "UNKNOWN"
  value_chr
}

derive_zeek_direction <- function(local_orig, local_resp) {
  local_orig <- as.logical(local_orig)
  local_resp <- as.logical(local_resp)
  result <- rep("external", length(local_orig))
  result[is.na(local_orig) | is.na(local_resp)] <- ""
  result[local_orig & !local_resp] <- "outbound"
  result[!local_orig & local_resp] <- "inbound"
  result[local_orig & local_resp] <- "internal"
  result
}

detect_ip_version <- function(src_ip, dst_ip) {
  probe <- ifelse(nzchar(src_ip), src_ip, dst_ip)
  ifelse(grepl(":", probe, fixed = TRUE), "ipv6", "ipv4")
}

safe_json_compact <- function(df) {
  if (is.null(df) || ncol(df) == 0) {
    return(rep("{}", nrow(df)))
  }

  apply(df, 1, function(row) {
    values <- as.list(row)
    values <- values[!vapply(values, function(x) identical(as.character(x), ""), logical(1))]
    if (length(values) == 0) {
      return("{}")
    }
    jsonlite::toJSON(values, auto_unbox = TRUE, null = "null")
  })
}

parse_datetime <- function(value, formats = c(
  "%Y-%m-%d %H:%M:%S",
  "%Y-%m-%d %H:%M:%OS",
  "%Y/%m/%d %H:%M:%S",
  "%Y/%m/%d %H:%M:%OS",
  "%m/%d/%Y %H:%M:%S",
  "%H:%M:%S"
)) {
  if (inherits(value, "POSIXct")) {
    return(as.POSIXct(value, tz = "UTC"))
  }

  if (is.numeric(value)) {
    return(as.POSIXct(value, origin = "1970-01-01", tz = "UTC"))
  }

  value_chr <- trimws(as.character(value))
  if (length(value_chr) == 0 || is.na(value_chr) || value_chr == "") {
    return(as.POSIXct(NA, tz = "UTC"))
  }

  for (fmt in formats) {
    parsed <- as.POSIXct(strptime(value_chr, fmt, tz = "UTC"), tz = "UTC")
    if (!is.na(parsed)) {
      return(parsed)
    }
  }

  as.POSIXct(NA, tz = "UTC")
}

parse_datetime_vec <- function(value, formats = c(
  "%Y-%m-%d %H:%M:%S",
  "%Y-%m-%d %H:%M:%OS",
  "%Y/%m/%d %H:%M:%S",
  "%Y/%m/%d %H:%M:%OS",
  "%m/%d/%Y %H:%M:%S",
  "%H:%M:%S"
)) {
  as.POSIXct(vapply(value, function(x) {
    as.numeric(parse_datetime(x, formats = formats))
  }, numeric(1)), origin = "1970-01-01", tz = "UTC")
}

init_logger()
