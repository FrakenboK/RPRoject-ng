source_ui_app_helpers()

test_that("format_int returns em dash for NULL / NA", {
  expect_equal(format_int(NULL), "—")
  expect_equal(format_int(NA), "—")
})

test_that("format_int adds non-breaking space thousand separator", {
  expect_equal(format_int(1000), "1 000")
  expect_equal(format_int(1234567), "1 234 567")
  expect_equal(format_int(0), "0")
})

test_that("format_int accepts character numeric input", {
  expect_equal(format_int("42"), "42")
  expect_equal(format_int("999999"), "999 999")
})

test_that("format_bytes returns em dash for NULL / NA", {
  expect_equal(format_bytes(NULL), "—")
  expect_equal(format_bytes(NA), "—")
})

test_that("format_bytes returns '0 B' for zero or negative", {
  expect_equal(format_bytes(0), "0 B")
  expect_equal(format_bytes(-100), "0 B")
})

test_that("format_bytes picks correct unit (B, KB, MB, GB, TB)", {
  expect_equal(format_bytes(1), "1.00 B")
  expect_equal(format_bytes(1024), "1.00 KB")
  expect_equal(format_bytes(1024 * 1024), "1.00 MB")
  expect_equal(format_bytes(1024^3), "1.00 GB")
  expect_equal(format_bytes(1024^4), "1.00 TB")
  expect_equal(format_bytes(1024^5), "1024.00 TB")
})

test_that("format_bytes handles fractional sizes", {
  expect_equal(format_bytes(1536), "1.50 KB")
  expect_equal(format_bytes(2.5 * 1024^2), "2.50 MB")
})

test_that("severity_badge emits correct bootstrap colour class", {
  expect_match(severity_badge("critical"), 'class="badge bg-danger"')
  expect_match(severity_badge("high"), 'class="badge bg-danger"')
  expect_match(severity_badge("medium"), 'class="badge bg-warning"')
  expect_match(severity_badge("low"), 'class="badge bg-info"')
  expect_match(severity_badge("anything-else"), 'class="badge bg-secondary"')
})

test_that("severity_badge embeds the original severity text", {
  expect_match(severity_badge("medium"), ">medium</span>$")
  expect_match(severity_badge("CRITICAL"), ">CRITICAL</span>$")
})

test_that("status_badge maps states to bootstrap colour classes", {
  expect_match(status_badge("running"), "bg-primary")
  expect_match(status_badge("completed"), "bg-success")
  expect_match(status_badge("loaded"), "bg-success")
  expect_match(status_badge("failed"), "bg-danger")
  expect_match(status_badge("skipped"), "bg-secondary")
  expect_match(status_badge("idle"), "bg-secondary")
  expect_match(status_badge("anything-else"), "bg-secondary")
})

test_that("build_time_choices returns 24 hours of labels in HH:MM, every 15 min by default", {
  choices <- build_time_choices()
  # 24 * 60 / 15 = 96 slots, plus 23:59 at the end = 97 labels.
  expect_length(choices, 97L)
  expect_equal(choices[1], "00:00")
  expect_equal(choices[2], "00:15")
  expect_equal(choices[97], "23:59")
  expect_true(all(grepl("^\\d{2}:\\d{2}$", choices)))
})

test_that("build_time_choices works with 60-minute step", {
  choices <- build_time_choices(step_minutes = 60L)
  expect_length(choices, 25L)
  expect_equal(choices[1], "00:00")
  expect_equal(choices[2], "01:00")
  expect_equal(choices[24], "23:00")
  expect_equal(choices[25], "23:59")
})

test_that("split_time_value extracts HH:MM from POSIXct", {
  ts <- as.POSIXct("2024-03-15 13:45:00", tz = "UTC")
  expect_equal(split_time_value(ts), "13:45")
})

test_that("split_time_value falls back when value is NULL / NA / empty", {
  expect_equal(split_time_value(NULL), "00:00")
  expect_equal(split_time_value(NA), "00:00")
  expect_equal(split_time_value(NULL, fallback = c("06:00", "18:00")), "06:00")
})

test_that("safe_range_value returns NULL when input is NULL / short / NA", {
  expect_null(safe_range_value(NULL, 1))
  expect_null(safe_range_value(as.Date(NA), 1))
  expect_null(safe_range_value(as.Date("2024-01-01"), 2))
})

test_that("safe_range_value returns the indexed element when present", {
  dates <- as.Date(c("2024-01-01", "2024-02-01"))
  expect_equal(safe_range_value(dates, 1), as.Date("2024-01-01"))
  expect_equal(safe_range_value(dates, 2), as.Date("2024-02-01"))
})

test_that("combine_date_time merges date + HH:MM into POSIXct UTC", {
  ts <- combine_date_time(as.Date("2024-03-15"), "13:45")
  expect_s3_class(ts, "POSIXct")
  expect_equal(format(ts, "%Y-%m-%d %H:%M:%S", tz = "UTC"),
               "2024-03-15 13:45:00")
})

test_that("combine_date_time defaults the time to 00:00 or 23:59 by end_default", {
  ts_start <- combine_date_time(as.Date("2024-03-15"), NULL)
  ts_end <- combine_date_time(as.Date("2024-03-15"), NULL, end_default = TRUE)
  expect_equal(format(ts_start, "%H:%M:%S", tz = "UTC"), "00:00:00")
  expect_equal(format(ts_end, "%H:%M:%S", tz = "UTC"), "23:59:00")
})

test_that("combine_date_time returns NULL for missing date", {
  expect_null(combine_date_time(NULL, "10:00"))
  expect_null(combine_date_time(NA, "10:00"))
})

test_that("%||% defined in app.R falls back on NULL / NA / empty", {
  expect_equal(NULL %||% "x", "x")
  expect_equal(NA %||% "x", "x")
  expect_equal(character(0) %||% "x", "x")
  expect_equal("kept" %||% "x", "kept")
})

test_that("format_int handles negatives and produces stable output", {
  expect_equal(format_int(-1500), "-1 500")
  expect_equal(format_int(-1), "-1")
})

test_that("format_bytes always uses two decimal places", {
  expect_match(format_bytes(1), "^\\d+\\.\\d{2} ")
  expect_match(format_bytes(123456789), "^\\d+\\.\\d{2} ")
})

test_that("severity_badge survives NULL by emitting fallback colour", {
  expect_match(severity_badge(NULL), 'class="badge bg-secondary"')
  expect_match(severity_badge(""), 'class="badge bg-secondary"')
})

test_that("status_badge survives NULL by emitting fallback colour", {
  expect_match(status_badge(NULL), 'class="badge bg-secondary"')
  expect_match(status_badge(""), 'class="badge bg-secondary"')
})

test_that("build_time_choices is monotonic in time-of-day", {
  choices <- build_time_choices()
  numeric_view <- as.integer(sub(":", "", choices))
  expect_true(all(diff(numeric_view) > 0))
})

test_that("combine_date_time accepts character date input", {
  ts <- combine_date_time("2024-03-15", "08:30")
  expect_equal(format(ts, "%Y-%m-%d %H:%M:%S", tz = "UTC"),
               "2024-03-15 08:30:00")
})

test_that("safe_range_value returns the indexed element for POSIXct ranges", {
  rng <- as.POSIXct(c("2024-01-01 00:00:00", "2024-01-02 12:34:56"), tz = "UTC")
  expect_equal(format(safe_range_value(rng, 1), "%H:%M:%S", tz = "UTC"),
               "00:00:00")
  expect_equal(format(safe_range_value(rng, 2), "%H:%M:%S", tz = "UTC"),
               "12:34:56")
})
