source_etl()

test_that("`%||%` returns lhs when not NULL/NA/empty", {
  expect_equal("a" %||% "b", "a")
  expect_equal(NULL %||% "b", "b")
  expect_equal(NA %||% "b", "b")
  expect_equal(character() %||% "fallback", "fallback")
  expect_equal(c("a", "b") %||% "fallback", c("a", "b"))
})

test_that("safe_numeric coerces and clamps inf to NA", {
  expect_equal(safe_numeric("3.14"), 3.14)
  expect_equal(safe_numeric(c("1", "2", "x")), c(1, 2, NA_real_))
  expect_true(is.na(safe_numeric(Inf)))
  expect_true(is.na(safe_numeric(-Inf)))
})

test_that("safe_integer coerces strings, returns NA for garbage", {
  expect_equal(safe_integer(c("1", "2", "x")), c(1L, 2L, NA_integer_))
  expect_equal(safe_integer("42"), 42L)
})

test_that("safe_port clamps to valid TCP/UDP range", {
  expect_equal(safe_port(c(80, 65535, 0)), c(80L, 65535L, 0L))
  expect_true(is.na(safe_port(-1)))
  expect_true(is.na(safe_port(70000)))
  expect_true(is.na(safe_port("abc")))
})

test_that("safe_uint64 rejects negatives", {
  expect_equal(safe_uint64(c(0, 1, 100)), c(0, 1, 100))
  expect_true(is.na(safe_uint64(-1)))
})

test_that("safe_bool maps string truthiness", {
  expect_equal(safe_bool(c("true", "false", "1", "0", "yes", "no")),
               c(TRUE, FALSE, TRUE, FALSE, TRUE, FALSE))
  expect_true(is.na(safe_bool("maybe")))
  expect_equal(safe_bool(c(TRUE, FALSE)), c(TRUE, FALSE))
})

test_that("safe_character replaces NA with empty string", {
  expect_equal(safe_character(c("a", NA, "b")), c("a", "", "b"))
  expect_equal(safe_character(123), "123")
})

test_that("normalize_transport_proto uppercases and fills UNKNOWN", {
  expect_equal(normalize_transport_proto(c("tcp", "  udp ", "", NA)),
               c("TCP", "UDP", "UNKNOWN", "UNKNOWN"))
})

test_that("detect_ip_version distinguishes ipv4 and ipv6", {
  expect_equal(detect_ip_version("1.2.3.4", "5.6.7.8"), "ipv4")
  expect_equal(detect_ip_version("fe80::1", "fe80::2"), "ipv6")
  expect_equal(detect_ip_version("", "1.2.3.4"), "ipv4")
  expect_equal(detect_ip_version("", "::1"), "ipv6")
})

test_that("parse_datetime parses common formats", {
  parsed <- parse_datetime("2024-05-10 12:34:56")
  expect_s3_class(parsed, "POSIXct")
  expect_equal(format(parsed, "%Y-%m-%d %H:%M:%S", tz = "UTC"),
               "2024-05-10 12:34:56")
  parsed_us <- parse_datetime("05/10/2024 12:34:56")
  expect_equal(format(parsed_us, "%Y-%m-%d", tz = "UTC"), "2024-05-10")
  expect_true(is.na(parse_datetime("not-a-date")))
  expect_true(is.na(parse_datetime("")))
})

test_that("parse_datetime handles numeric epoch", {
  parsed <- parse_datetime(0)
  expect_equal(format(parsed, "%Y-%m-%d", tz = "UTC"), "1970-01-01")
})

test_that("parse_datetime_vec vectorises", {
  v <- unname(parse_datetime_vec(c("2024-01-01 00:00:00", "2025-02-02 03:04:05")))
  expect_length(v, 2)
  expect_equal(format(v[1], "%Y-%m-%d", tz = "UTC"), "2024-01-01")
  expect_equal(format(v[2], "%Y-%m-%d", tz = "UTC"), "2025-02-02")
})

test_that("safe_json_compact emits empty json for empty rows", {
  df <- data.frame(a = "", b = "", stringsAsFactors = FALSE)
  expect_equal(safe_json_compact(df), "{}")
})

test_that("safe_json_compact keeps non-empty fields", {
  df <- data.frame(a = "value", b = "", stringsAsFactors = FALSE)
  result <- safe_json_compact(df)
  expect_match(result, "\"a\"\\s*:\\s*\"value\"")
  expect_false(grepl("\"b\"", result))
})

test_that("build_ingest_run_id has expected prefix and length", {
  expect_match(build_ingest_run_id(), "^run-\\d{14}$")
})

test_that("ensure_dir creates directory and returns absolute path", {
  tmp <- file.path(tempdir(), sprintf("etl-test-%s", as.integer(Sys.time())))
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  result <- ensure_dir(tmp)
  expect_true(dir.exists(tmp))
  expect_true(file.exists(result))
})

test_that("should_log honors log level threshold", {
  assign("log_level", "WARNING", envir = .GlobalEnv)
  expect_false(should_log("INFO"))
  expect_true(should_log("WARNING"))
  expect_true(should_log("ERROR"))
  assign("log_level", "DEBUG", envir = .GlobalEnv)
  expect_true(should_log("INFO"))
})
