stub_clickhouse_io()
source_ui()

test_that("quote_sql escapes single quotes and wraps in quotes", {
  expect_equal(quote_sql("plain"), "'plain'")
  expect_equal(quote_sql("o'reilly"), "'o''reilly'")
  expect_equal(quote_sql(123), "'123'")
})

test_that("quote_sql_list joins quoted values with commas", {
  expect_equal(quote_sql_list(c("a", "b")), "'a', 'b'")
  expect_equal(quote_sql_list(c("a'b", "c")), "'a''b', 'c'")
})

test_that("quote_sql_list on single element", {
  expect_equal(quote_sql_list("single"), "'single'")
})

test_that("safe_query returns fallback on null connection", {
  result <- safe_query("SELECT 1", fallback = data.frame(x = 42))
  expect_equal(result$x, 42)
})

test_that("table_exists returns FALSE without ClickHouse", {
  expect_false(table_exists("never_existed_table_xyz"))
})

test_that("fetch_overview_counters returns zeros without CH", {
  counters <- fetch_overview_counters()
  expect_named(counters,
               c("flows_total", "objects_total", "objects_loaded",
                 "objects_failed", "runs_total", "detections_total",
                 "signature_total", "behavioral_total"))
  expect_equal(unname(unlist(counters)), rep(0, length(counters)))
})

test_that("fetch_detections_filtered returns empty frame with fallback", {
  expect_equal(nrow(fetch_detections_filtered()), 0)
  expect_equal(nrow(fetch_detections_filtered(severities = c("high", "medium"))), 0)
})

test_that("fetch_flows_by_bucket builds SQL with custom date range", {
  expect_equal(nrow(fetch_flows_by_bucket(granularity = "week",
                                          date_from = "2024-01-01",
                                          date_to = "2024-01-31")), 0)
})
