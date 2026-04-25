library(yaml)

load_logging_config <- function(config_path = "config/logging.yml") {
  tryCatch({
    if (!file.exists(config_path)) {
      return(list(
        level = "INFO",
        format = "%Y-%m-%d %H:%M:%S",
        file = NULL,
        console = TRUE
      ))
    }
    yaml_config <- yaml::read_yaml(config_path)
    return(yaml_config)
  }, error = function(e) {
    return(list(
      level = "INFO",
      format = "%Y-%m-%d %H:%M:%S",
      file = NULL,
      console = TRUE
    ))
  })
}

init_logger <- function(config = NULL) {
  if (is.null(config)) {
    config <- load_logging_config()
  }
  logger <- list(
    level = config$level,
    format = config$format,
    file = config$file,
    console = config$console
  )
  assign("logger", logger, envir = .GlobalEnv)
  return(logger)
}

get_log_level <- function() {
  logger <- get("logger", envir = .GlobalEnv)
  return(logger$level)
}

should_log <- function(message_level) {
  levels <- c("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
  current_level <- toupper(get_log_level())
  current_idx <- match(current_level, levels)
  msg_idx <- match(toupper(message_level), levels)
  return(msg_idx >= current_idx)
}

format_log_message <- function(level, message) {
  logger <- get("logger", envir = .GlobalEnv)
  timestamp <- format(Sys.time(), logger$format)
  return(sprintf("[%s] [%s] %s", timestamp, level, message))
}

log_message <- function(level, message, ...) {
  if (!should_log(level)) {
    return(invisible(NULL))
  }
  formatted_msg <- format_log_message(level, message)
  args <- list(formatted_msg, ...)
  do.call("message", args)
  logger <- get("logger", envir = .GlobalEnv)
  if (!is.null(logger$file) && file.exists(logger$file)) {
    tryCatch({
      cat(formatted_msg, "\n", file = logger$file, append = TRUE)
    }, error = function(e) {
    })
  }
  invisible(formatted_msg)
}

debug <- function(message, ...) {
  log_message("DEBUG", message, ...)
}

info <- function(message, ...) {
  log_message("INFO", message, ...)
}

warning_log <- function(message, ...) {
  log_message("WARNING", message, ...)
}

error_log <- function(message, ...) {
  log_message("ERROR", message, ...)
}

critical_log <- function(message, ...) {
  log_message("CRITICAL", message, ...)
}

create_etl_error <- function(message, code = "UNKNOWN", details = NULL) {
  structure(
    list(
      message = message,
      code = code,
      details = details,
      timestamp = Sys.time()
    ),
    class = c("ETLError", "error", "condition")
  )
}

handle_etl_error <- function(expr, context = "ETL Operation") {
  result <- tryCatch(
    expr,
    error = function(e) {
      if (inherits(e, "ETLError")) {
        error_log(sprintf("[%s] %s: %s", context, e$message, e$code))
      } else {
        error_log(sprintf("[%s] Error: %s", context, e$message))
      }
      return(NULL)
    }
  )
  if (is.null(result)) {
    return(invisible(NULL))
  }
  return(result)
}

safe_function <- function(fn, context = "Function") {
  function(...) {
    handle_etl_error({
      fn(...)
    }, context)
  }
}

is_valid_ipv4 <- function(ip) {
  if (is.null(ip) || !is.character(ip) || length(ip) != 1) {
    return(FALSE)
  }
  pattern <- "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  return(grepl(pattern, ip, ignore.case = TRUE))
}

is_valid_port <- function(port) {
  if (is.null(port)) return(FALSE)
  if (is.numeric(port)) {
    return(port >= 0 && port <= 65535)
  }
  if (is.character(port)) {
    port_num <- as.integer(port)
    return(!is.na(port_num) && port_num >= 0 && port_num <= 65535)
  }
  return(FALSE)
}

is_valid_protocol <- function(protocol) {
  if (is.null(protocol)) return(FALSE)
  valid_protocols <- c("TCP", "UDP", "ICMP")
  return(toupper(protocol) %in% valid_protocols)
}

is_valid_direction <- function(direction) {
  if (is.null(direction)) return(FALSE)
  valid_directions <- c("IN", "OUT", "INTERNAL")
  return(toupper(direction) %in% valid_directions)
}

is_valid_application <- function(app) {
  if (is.null(app)) return(FALSE)
  valid_apps <- c("HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "IMAP", "POP3", "RDP", "SMB", "UNKNOWN")
  return(toupper(app) %in% valid_apps)
}

is_valid_severity <- function(severity) {
  if (is.null(severity)) return(FALSE)
  valid_severities <- c("LOW", "MEDIUM", "HIGH", "CRITICAL")
  return(toupper(severity) %in% valid_severities)
}

is_valid_threat_score <- function(score) {
  if (is.null(score)) return(FALSE)
  if (is.numeric(score)) {
    return(score >= 0 && score <= 1)
  }
  return(FALSE)
}

generate_uuid <- function() {
  paste0(
    sprintf("%04x", sample(0:65535, 1)),
    sprintf("%04x", sample(0:65535, 1)),
    sprintf("%04x", sample(0:65535, 1)),
    sprintf("%04x", sample(0:65535, 1)),
    sprintf("%04x", sample(0:65535, 1)),
    sprintf("%04x", sample(0:65535, 1))
  )
}

to_uint16 <- function(value) {
  if (is.null(value)) return(NA_integer_)
  if (is.numeric(value)) {
    val <- as.integer(value)
    if (val >= 0 && val <= 65535) return(val)
  }
  if (is.character(value)) {
    val <- suppressWarnings(as.integer(value))
    if (!is.na(val) && val >= 0 && val <= 65535) return(val)
  }
  return(NA_integer_)
}

to_uint32 <- function(value) {
  if (is.null(value)) return(NA_integer_)
  if (is.numeric(value)) {
    val <- as.integer(value)
    if (val >= 0 && val <= 4294967295) return(val)
  }
  if (is.character(value)) {
    val <- suppressWarnings(as.integer(value))
    if (!is.na(val) && val >= 0 && val <= 4294967295) return(val)
  }
  return(NA_integer_)
}

to_uint64 <- function(value) {
  if (is.null(value)) return(NA_real_)
  if (is.numeric(value)) {
    val <- as.numeric(value)
    if (val >= 0 && val <= 18446744073709551615) return(val)
  }
  if (is.character(value)) {
    val <- suppressWarnings(as.numeric(value))
    if (!is.na(val) && val >= 0 && val <= 18446744073709551615) return(val)
  }
  return(NA_real_)
}

to_float32 <- function(value) {
  if (is.null(value)) return(NA_real_)
  if (is.numeric(value)) {
    val <- as.numeric(value)
    if (!is.infinite(val) && !is.nan(val)) return(val)
  }
  if (is.character(value)) {
    val <- suppressWarnings(as.numeric(value))
    if (!is.na(val) && !is.infinite(val) && !is.nan(val)) return(val)
  }
  return(NA_real_)
}

create_progress_tracker <- function(total, description = "Processing") {
  tracker <- list(
    total = total,
    processed = 0,
    description = description,
    start_time = Sys.time(),
    last_update = Sys.time()
  )
  return(tracker)
}

update_progress <- function(tracker, increment = 1) {
  tracker$processed <- tracker$processed + increment
  tracker$last_update <- Sys.time()
  return(tracker)
}

print_progress <- function(tracker) {
  if (tracker$processed == 0) return(invisible(NULL))
  percentage <- (tracker$processed / tracker$total) * 100
  elapsed <- difftime(Sys.time(), tracker$start_time, units = "secs")
  rate <- if (elapsed > 0) tracker$processed / elapsed else 0
  remaining <- if (rate > 0) (tracker$total - tracker$processed) / rate else 0
  info(sprintf(
    "[%s] Progress: %d/%d (%.1f%%) | Elapsed: %.1fs | Rate: %.1f items/s | ETA: %.1fs",
    tracker$description,
    tracker$processed,
    tracker$total,
    percentage,
    as.numeric(elapsed),
    rate,
    as.numeric(remaining)
  ))
  return(invisible(NULL))
}

finalize_progress <- function(tracker) {
  if (tracker$processed == tracker$total) {
    info(sprintf("[%s] Completed: %d items processed", tracker$description, tracker$processed))
  } else {
    warning_log(sprintf("[%s] Incomplete: %d/%d items processed", tracker$description, tracker$processed, tracker$total))
  }
  return(invisible(NULL))
}

load_env <- function(env_path = ".env") {
  if (!file.exists(env_path)) {
    return(list())
  }
  env_vars <- list()
  lines <- readLines(env_path, warn = FALSE)
  for (line in lines) {
    line <- trimws(line)
    if (nchar(line) == 0 || startsWith(line, "#")) next
    if (grepl("=", line)) {
      parts <- strsplit(line, "=", fixed = TRUE)[[1]]
      key <- trimws(parts[1])
      value <- trimws(paste(parts[-1], collapse = "="))
      env_vars[[key]] <- value
    }
  }
  return(env_vars)
}

get_env <- function(name, default = NULL) {
  env <- load_env()
  if (name %in% names(env)) {
    return(env[[name]])
  }
  return(default)
}

file_readable <- function(filepath) {
  if (!file.exists(filepath)) return(FALSE)
  if (!file.info(filepath)$isdir) {
    return(file.access(filepath, 4) == 0)
  }
  return(FALSE)
}

dir_writable <- function(dirpath) {
  if (!dir.exists(dirpath)) return(FALSE)
  return(file.access(dirpath, 2) == 0)
}

ensure_dir <- function(dirpath, recursive = TRUE) {
  if (dir.exists(dirpath)) return(TRUE)
  if (recursive) {
    dir.create(dirpath, recursive = TRUE, showWarnings = FALSE)
  }
  return(dir.exists(dirpath))
}

init_utils <- function(config = NULL) {
  if (is.null(config)) {
    config <- load_logging_config()
  }
  init_logger(config)
  info("Utils module initialized")
  invisible(NULL)
}

init_utils()
