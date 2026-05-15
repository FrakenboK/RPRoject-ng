library(processx)

JOB_REGISTRY <- new.env(parent = emptyenv())
JOB_LOG_DIR <- "/tmp/r-ui-jobs"

ensure_job_log_dir <- function() {
  if (!dir.exists(JOB_LOG_DIR)) {
    dir.create(JOB_LOG_DIR, recursive = TRUE, showWarnings = FALSE)
  }
  JOB_LOG_DIR
}

compose_project_root <- function() {
  Sys.getenv("COMPOSE_PROJECT_DIR", "/compose")
}

compose_project_name <- function() {
  Sys.getenv("COMPOSE_PROJECT_NAME", "rproject-ng")
}

job_key <- function(service) {
  sprintf("%s", service)
}

start_compose_job <- function(service) {
  if (!service %in% c("etl-init", "analysis")) {
    stop(sprintf("Unsupported service: %s", service))
  }

  existing <- JOB_REGISTRY[[job_key(service)]]
  if (!is.null(existing) && inherits(existing$proc, "process") && existing$proc$is_alive()) {
    return(list(ok = FALSE, message = sprintf("Job '%s' is already running", service)))
  }

  ensure_job_log_dir()
  stamp <- format(Sys.time(), "%Y%m%d-%H%M%S")
  log_path <- file.path(JOB_LOG_DIR, sprintf("%s-%s.log", service, stamp))

  args <- c(
    "compose",
    "--project-directory", compose_project_root(),
    "-p", compose_project_name(),
    "run", "--rm", service
  )

  proc <- tryCatch(
    processx::process$new(
      command = "docker",
      args = args,
      stdout = log_path,
      stderr = "2>&1",
      cleanup = FALSE,
      supervise = FALSE
    ),
    error = function(e) {
      return(list(error = e$message))
    }
  )

  if (is.list(proc) && !is.null(proc$error)) {
    return(list(ok = FALSE, message = sprintf("Failed to start: %s", proc$error)))
  }

  JOB_REGISTRY[[job_key(service)]] <- list(
    proc = proc,
    started_at = Sys.time(),
    log_path = log_path,
    service = service
  )

  list(ok = TRUE, message = sprintf("Started '%s' (log: %s)", service, log_path))
}

job_status <- function(service) {
  job <- JOB_REGISTRY[[job_key(service)]]
  if (is.null(job)) {
    return(list(state = "idle", started_at = NA, log_path = NA_character_, exit_code = NA))
  }

  proc <- job$proc
  if (!inherits(proc, "process")) {
    return(list(state = "idle", started_at = NA, log_path = NA_character_, exit_code = NA))
  }

  is_alive <- tryCatch(proc$is_alive(), error = function(e) FALSE)
  if (is_alive) {
    return(list(
      state = "running",
      started_at = job$started_at,
      log_path = job$log_path,
      exit_code = NA
    ))
  }

  exit_code <- tryCatch(proc$get_exit_status(), error = function(e) NA_integer_)
  list(
    state = if (isTRUE(exit_code == 0L)) "completed" else "failed",
    started_at = job$started_at,
    log_path = job$log_path,
    exit_code = exit_code
  )
}

tail_job_log <- function(service, n_lines = 200L) {
  job <- JOB_REGISTRY[[job_key(service)]]
  if (is.null(job) || !file.exists(job$log_path)) {
    return("")
  }

  lines <- tryCatch(readLines(job$log_path, warn = FALSE), error = function(e) character())
  if (length(lines) == 0) {
    return("")
  }

  tail_lines <- utils::tail(lines, n_lines)
  paste(tail_lines, collapse = "\n")
}
