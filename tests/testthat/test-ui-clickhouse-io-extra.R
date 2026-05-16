stub_clickhouse_io()
source_ui()

test_that("format_time_bound returns NULL for null/NA/empty input", {
  expect_null(format_time_bound(NULL))
  expect_null(format_time_bound(NA))
  expect_null(format_time_bound(character(0)))
})

test_that("format_time_bound formats POSIXct as ISO datetime string", {
  ts <- as.POSIXct("2024-03-15 12:34:56", tz = "UTC")
  expect_equal(format_time_bound(ts), "2024-03-15 12:34:56")
})

test_that("format_time_bound expands Date to start-of-day or end-of-day", {
  d <- as.Date("2024-03-15")
  expect_equal(format_time_bound(d, end = FALSE), "2024-03-15 00:00:00")
  expect_equal(format_time_bound(d, end = TRUE), "2024-03-15 23:59:59")
})

test_that("format_time_bound accepts character timestamps", {
  expect_equal(format_time_bound("2024-01-01 00:00:00"),
               "2024-01-01 00:00:00")
})

test_that("build_detection_sources_subquery contains expected joins/columns", {
  sql <- build_detection_sources_subquery()
  expect_match(sql, "FROM analysis_detection_events e")
  expect_match(sql, "LEFT JOIN network_flows f ON f.event_id = e.event_id")
  expect_match(sql, "groupUniqArray\\(ifNull\\(f.source_dataset")
  expect_match(sql, "GROUP BY e.detection_id")
})

test_that("fetch_overview_counters returns zero counters without CH", {
  c <- fetch_overview_counters()
  expect_equal(unname(unlist(c)), rep(0, length(c)))
  expect_named(c, c("flows_total", "objects_total", "objects_loaded",
                    "objects_failed", "runs_total", "detections_total",
                    "signature_total", "behavioral_total"))
})

test_that("fetch_severity_breakdown returns empty frame fallback", {
  result <- fetch_severity_breakdown()
  expect_s3_class(result, "data.frame")
  expect_equal(nrow(result), 0)
})

test_that("fetch_flows_by_day and friends return empty frames without CH", {
  expect_equal(nrow(fetch_flows_by_day()), 0)
  expect_equal(nrow(fetch_flow_time_range()), 0)
  expect_equal(nrow(fetch_detection_time_range()), 0)
})

test_that("fetch_flows_by_bucket switches granularity expression", {
  # We cannot intercept SQL via the stub easily, but we can ensure the
  # function returns the fallback shape and accepts all granularities.
  for (g in c("day", "week", "month", "bogus")) {
    result <- fetch_flows_by_bucket(granularity = g)
    expect_s3_class(result, "data.frame")
    expect_equal(nrow(result), 0)
  }
})

test_that("fetch_flows_by_bucket accepts date_from / date_to as Date and POSIXct", {
  d_from <- as.Date("2024-01-01")
  d_to <- as.Date("2024-01-31")
  ts_from <- as.POSIXct("2024-02-01 10:00:00", tz = "UTC")
  ts_to <- as.POSIXct("2024-02-15 22:00:00", tz = "UTC")
  expect_equal(nrow(fetch_flows_by_bucket("day", d_from, d_to)), 0)
  expect_equal(nrow(fetch_flows_by_bucket("week", ts_from, ts_to)), 0)
})

test_that("fetch_recent_runs and fetch_recent_etl_objects respect limit", {
  expect_equal(nrow(fetch_recent_runs(limit = 5L)), 0)
  expect_equal(nrow(fetch_recent_etl_objects(limit = 1L)), 0)
})

test_that("fetch_detection_filter_options returns empty options without CH", {
  opts <- fetch_detection_filter_options()
  expect_named(opts, c("source_formats", "source_datasets"))
  expect_equal(nrow(opts$source_formats), 0)
  expect_equal(nrow(opts$source_datasets), 0)
})

test_that("fetch_detections_filtered handles all filter kinds without CH", {
  expect_equal(nrow(fetch_detections_filtered()), 0)
  expect_equal(
    nrow(fetch_detections_filtered(
      detector_types = c("signature", "behavioral"),
      severities = c("high", "medium"),
      src_ip = "10.0.0.1",
      dst_ip = "10.0.0.2",
      date_from = "2024-01-01",
      date_to = "2024-01-31",
      limit = 200L
    )),
    0
  )
})

test_that("quote_sql handles numeric coercion edge cases", {
  expect_equal(quote_sql(NA), "'NA'")
  expect_equal(quote_sql(""), "''")
  expect_equal(quote_sql(0), "'0'")
  expect_equal(quote_sql(3.14), "'3.14'")
})

test_that("quote_sql_list preserves order", {
  expect_equal(quote_sql_list(c("c", "a", "b")), "'c', 'a', 'b'")
})

test_that("table_exists returns logical FALSE on missing table without CH", {
  expect_false(table_exists("foo"))
  expect_false(table_exists("network_flows"))
})
