source_analysis()

test_that("`%||%` in analysis utils", {
  expect_equal("x" %||% "y", "x")
  expect_equal(NULL %||% "y", "y")
  expect_equal(character() %||% "y", "y")
})

test_that("percent_rank_vec returns 0..1 range", {
  ranks <- percent_rank_vec(c(10, 20, 30, 40))
  expect_equal(ranks, c(0, 1/3, 2/3, 1))
  expect_equal(percent_rank_vec(numeric(0)), numeric(0))
})

test_that("percent_rank_vec handles ties and NA", {
  ranks <- percent_rank_vec(c(10, 10, 20, NA))
  expect_equal(ranks[1], ranks[2])
  expect_true(is.na(ranks[4]))
})

test_that("percent_rank_vec on single point returns 0", {
  expect_equal(percent_rank_vec(c(5)), 0)
})

test_that("normalize_score replaces NA with 0", {
  expect_equal(normalize_score(c(1, NA, 2)), c(1, 0, 2))
  expect_equal(normalize_score(c("1", "x", "2")), c(1, 0, 2))
})

test_that("quote_sql_string doubles single quotes", {
  expect_equal(quote_sql_string("hello"), "'hello'")
  expect_equal(quote_sql_string("o'reilly"), "'o''reilly'")
  expect_equal(quote_sql_string(NA), "''")
  expect_equal(quote_sql_string(""), "''")
})

test_that("build_detection_id generates monotonically increasing ids", {
  a <- build_detection_id("run-X")
  b <- build_detection_id("run-X")
  c <- build_detection_id("run-X")
  expect_match(a, "^run-X-\\d{6}$")
  expect_match(b, "^run-X-\\d{6}$")
  num_a <- as.integer(sub("^run-X-", "", a))
  num_b <- as.integer(sub("^run-X-", "", b))
  num_c <- as.integer(sub("^run-X-", "", c))
  expect_true(num_b == num_a + 1L)
  expect_true(num_c == num_b + 1L)
})

test_that("build_analysis_run_id has expected format", {
  id <- build_analysis_run_id()
  expect_match(id, "^analysis-\\d{14}$")
})

test_that("safe_port in analysis clamps invalid values", {
  expect_equal(safe_port(c(80, 65535, 0)), c(80L, 65535L, 0L))
  expect_true(is.na(safe_port(70000)))
  expect_true(is.na(safe_port(-1)))
})

test_that("safe_json wraps lists/NULL", {
  expect_equal(safe_json(NULL), "{}")
  expect_match(safe_json(list(a = 1)), "\"a\"")
  expect_match(safe_json(list("x", "y")), "\\[\"x\",\"y\"\\]")
})

test_that("safe_character handles NA in analysis utils", {
  expect_equal(safe_character(c("a", NA)), c("a", ""))
})
