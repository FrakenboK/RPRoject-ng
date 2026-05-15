REPO_ROOT <- Sys.getenv("REPO_ROOT", "/repo")

stub_clickhouse_io <- function() {
  pkg_env <- new.env(parent = .GlobalEnv)
  pkg_env$get_clickhouse_connection <- function(...) stop("CH not available in tests")
  pkg_env$close_connection <- function(...) invisible(NULL)
  pkg_env$test_connection <- function(...) FALSE
  pkg_env$create_all_tables <- function(...) invisible(NULL)
  pkg_env$create_all_analysis_tables <- function(...) invisible(NULL)
  pkg_env$mark_stale_analysis_runs_failed <- function(...) invisible(NULL)
  pkg_env$insert_analysis_run <- function(...) invisible(NULL)
  pkg_env$insert_analysis_detections <- function(...) invisible(NULL)
  pkg_env$insert_analysis_detection_events <- function(...) invisible(NULL)
  pkg_env$insert_network_flows <- function(...) invisible(NULL)
  pkg_env$insert_etl_object_status <- function(...) invisible(NULL)
  invisible(list2env(as.list(pkg_env), envir = .GlobalEnv))
}

source_etl <- function() {
  base <- file.path(REPO_ROOT, "r-etl/R")
  source(file.path(base, "utils.R"), local = FALSE)
  source(file.path(base, "normalization.R"), local = FALSE)
  source(file.path(base, "s3_io.R"), local = FALSE)
}

source_etl_full <- function() {
  source_etl()
  base <- file.path(REPO_ROOT, "r-etl/R")
  source(file.path(base, "parsing.R"), local = FALSE)
}

source_analysis <- function() {
  base <- file.path(REPO_ROOT, "r-analysis/R")
  source(file.path(base, "utils.R"), local = FALSE)
  source(file.path(base, "signature_rules.R"), local = FALSE)
}

source_without_library <- function(path) {
  lines <- readLines(path, warn = FALSE)
  lines <- lines[!grepl("^\\s*library\\(", lines)]
  eval(parse(text = paste(lines, collapse = "\n")), envir = .GlobalEnv)
}

source_ui <- function() {
  base <- file.path(REPO_ROOT, "r-ui/R")
  source_without_library(file.path(base, "clickhouse_io.R"))
}
