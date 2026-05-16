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
  source(file.path(base, "tcp_sessions.R"), local = FALSE)
}

source_etl_clickhouse <- function() {
  source_etl()
  base <- file.path(REPO_ROOT, "r-etl/R")
  fake_dbi <- new.env(parent = emptyenv())
  source(file.path(base, "clickhouse_io.R"), local = fake_dbi)
  for (nm in ls(fake_dbi)) {
    assign(nm, get(nm, envir = fake_dbi), envir = .GlobalEnv)
  }
}

source_analysis <- function() {
  base <- file.path(REPO_ROOT, "r-analysis/R")
  source(file.path(base, "utils.R"), local = FALSE)
  source(file.path(base, "signature_rules.R"), local = FALSE)
}

source_ui <- function() {
  base <- file.path(REPO_ROOT, "r-ui/R")
  source(file.path(base, "clickhouse_io.R"), local = FALSE)
}

source_ui_runner <- function() {
  base <- file.path(REPO_ROOT, "r-ui/R")
  source(file.path(base, "runner.R"), local = FALSE)
}

# Selectively load helper definitions from app.R without running shinyApp().
source_ui_app_helpers <- function() {
  app_path <- file.path(REPO_ROOT, "r-ui/R/app.R")
  target_names <- c(
    "%||%", "plot_family", "set_plot_par", "render_empty_plot",
    "build_time_choices", "split_time_value", "safe_range_value",
    "combine_date_time", "format_int", "format_bytes",
    "severity_badge", "status_badge"
  )
  exprs <- parse(file = app_path)
  for (expr in exprs) {
    if (length(expr) >= 2 && is.call(expr) &&
        identical(expr[[1]], as.name("<-"))) {
      tgt <- expr[[2]]
      nm <- if (is.name(tgt)) as.character(tgt) else NA_character_
      if (!is.na(nm) && nm %in% target_names) {
        eval(expr, envir = .GlobalEnv)
      }
    }
  }
  invisible(TRUE)
}
