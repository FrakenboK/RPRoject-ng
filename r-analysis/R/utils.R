library(jsonlite)

`%||%` <- function(lhs, rhs) {
  if (is.null(lhs) || length(lhs) == 0) {
    return(rhs)
  }

  lhs
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

build_analysis_run_id <- function() {
  format(Sys.time(), "analysis-%Y%m%d%H%M%S")
}

safe_numeric <- function(value) {
  result <- suppressWarnings(as.numeric(value))
  result[is.infinite(result)] <- NA_real_
  result
}

safe_integer <- function(value) {
  suppressWarnings(as.integer(value))
}

safe_character <- function(value) {
  result <- as.character(value)
  result[is.na(result)] <- ""
  result
}

safe_port <- function(value) {
  result <- safe_integer(value)
  result[is.na(result) | result < 0L | result > 65535L] <- NA_integer_
  result
}

safe_json <- function(value) {
  if (is.null(value)) {
    return("{}")
  }

  jsonlite::toJSON(value, auto_unbox = TRUE, null = "null")
}

percent_rank_vec <- function(x) {
  if (length(x) == 0) {
    return(numeric())
  }

  ranks <- rank(x, ties.method = "average", na.last = "keep")
  denom <- sum(!is.na(ranks))
  if (denom <= 1) {
    return(rep(0, length(x)))
  }

  (ranks - 1) / (denom - 1)
}

normalize_score <- function(x) {
  x_num <- safe_numeric(x)
  x_num[is.na(x_num)] <- 0
  x_num
}

quote_sql_string <- function(value) {
  sprintf("'%s'", gsub("'", "''", safe_character(value), fixed = TRUE))
}

build_detection_id <- local({
  counter <- 0L

  function(run_id) {
    counter <<- counter + 1L
    sprintf("%s-%06d", run_id, counter)
  }
})

init_logger()
