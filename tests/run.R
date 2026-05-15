Sys.setenv(REPO_ROOT = Sys.getenv("REPO_ROOT", "/repo"))

if (!requireNamespace("testthat", quietly = TRUE)) {
  stop("testthat is not installed in this container")
}

reporter <- if (interactive()) "summary" else "progress"

result <- testthat::test_dir(
  path = file.path(Sys.getenv("REPO_ROOT"), "tests/testthat"),
  reporter = reporter,
  stop_on_failure = FALSE,
  load_helpers = TRUE
)

result_df <- as.data.frame(result)
total_failed <- sum(result_df$failed)
total_warnings <- sum(result_df$warning)
total_pass <- sum(result_df$nb)

cat(sprintf("\n==> tests: %d passed, %d failed, %d warnings\n",
            total_pass, total_failed, total_warnings))

if (total_failed > 0) {
  quit(status = 1)
}
