source_analysis()

normalize_ws <- function(x) gsub("\\s+", " ", trimws(x))

test_that("build_scalar_sql eq for numeric and string", {
  expect_equal(build_scalar_sql("dst_port", 3389, "eq"), "dst_port = 3389")
  expect_equal(build_scalar_sql("transport_proto", "TCP", "eq"),
               "transport_proto = 'TCP'")
})

test_that("build_scalar_sql comparison modifiers", {
  expect_equal(build_scalar_sql("bytes_total", 1000, "gte"),
               "bytes_total >= 1000")
  expect_equal(build_scalar_sql("duration_sec", 30, "gt"),
               "duration_sec > 30")
  expect_equal(build_scalar_sql("packets_total", 5, "lte"),
               "packets_total <= 5")
  expect_equal(build_scalar_sql("ttl", 64, "lt"), "ttl < 64")
})

test_that("build_scalar_sql contains / startswith / endswith use CH funcs", {
  expect_equal(build_scalar_sql("app_proto", "http", "contains"),
               "positionCaseInsensitiveUTF8(app_proto, 'http') > 0")
  expect_equal(build_scalar_sql("flow_state", "RST", "startswith"),
               "startsWith(lowerUTF8(flow_state), lowerUTF8('RST'))")
  expect_equal(build_scalar_sql("flow_state", "TO", "endswith"),
               "endsWith(lowerUTF8(flow_state), lowerUTF8('TO'))")
})

test_that("build_scalar_sql regex and cidr", {
  expect_equal(build_scalar_sql("src_ip", "^10\\.", "re"),
               "match(src_ip, '^10\\.')")
  expect_equal(build_scalar_sql("src_ip", "10.0.0.0/8", "cidr"),
               "isIPAddressInRange(src_ip, '10.0.0.0/8')")
})

test_that("build_scalar_sql rejects unsupported modifier", {
  expect_error(build_scalar_sql("x", 1, "unknown_op"), "Unsupported Sigma modifier")
})

test_that("build_field_sql wraps in parens and parses modifier from field name", {
  sql <- build_field_sql("dst_port", 3389)
  expect_equal(sql, "(dst_port = 3389)")
  sql_gte <- build_field_sql("duration_sec|gte", 30)
  expect_equal(sql_gte, "(duration_sec >= 30)")
})

test_that("build_field_sql with list value emits OR group", {
  sql <- build_field_sql("dst_port", c(3389, 5900))
  expect_match(sql, "dst_port = 3389")
  expect_match(sql, "dst_port = 5900")
  expect_match(sql, "OR")
})

test_that("build_field_sql exists modifier", {
  sql_true <- build_field_sql("app_proto|exists", TRUE)
  sql_false <- build_field_sql("app_proto|exists", FALSE)
  expect_match(sql_true, "app_proto IS NOT NULL")
  expect_match(sql_false, "app_proto IS NULL")
})

test_that("build_selection_sql joins fields with AND", {
  selection <- list(transport_proto = "TCP", dst_port = 3389)
  sql <- build_selection_sql(selection)
  expect_match(sql, "transport_proto = 'TCP'")
  expect_match(sql, "dst_port = 3389")
  expect_match(sql, "AND")
})

test_that("condition_to_sql substitutes selection names and AND/OR/NOT", {
  sel_sql <- list(selection_a = "x = 1", selection_b = "y = 2")
  sql <- condition_to_sql("selection_a and selection_b", sel_sql)
  expect_match(sql, "x = 1")
  expect_match(sql, "y = 2")
  expect_match(sql, "AND")
  sql_or <- condition_to_sql("selection_a or selection_b", sel_sql)
  expect_match(sql_or, "OR")
  sql_not <- condition_to_sql("not selection_a", sel_sql)
  expect_match(sql_not, "NOT")
})

test_that("build_sigma_sql compiles full rule for RDP failure", {
  rule <- list(
    id = "test-rdp",
    title = "RDP failures",
    detection = list(
      selection_proto = list(transport_proto = "TCP", dst_port = 3389),
      selection_state = list(flow_state = c("S0", "REJ", "RSTO")),
      condition = "selection_proto and selection_state"
    ),
    level = "medium"
  )
  sql <- normalize_ws(build_sigma_sql(rule))
  expect_match(sql, "transport_proto = 'TCP'")
  expect_match(sql, "dst_port = 3389")
  expect_match(sql, "flow_state = 'S0'")
  expect_match(sql, "flow_state = 'REJ'")
  expect_match(sql, "AND")
})

test_that("build_sigma_sql rejects rule without selections or condition", {
  expect_error(
    build_sigma_sql(list(id = "x", title = "y",
                          detection = list(condition = "selection_a"))),
    "no selections"
  )
  expect_error(
    build_sigma_sql(list(id = "x", title = "y",
                          detection = list(selection_a = list(x = 1)))),
    "no detection condition"
  )
})

test_that("load_sigma_rules parses YAML files from disk", {
  tmp_dir <- tempfile(pattern = "sigma-rules-")
  dir.create(tmp_dir)
  on.exit(unlink(tmp_dir, recursive = TRUE), add = TRUE)
  writeLines(c(
    "title: tmp rule",
    "id: tmp.rule",
    "detection:",
    "    selection:",
    "        transport_proto: TCP",
    "    condition: selection",
    "level: low"
  ), file.path(tmp_dir, "rule.yml"))

  rules <- load_sigma_rules(tmp_dir)
  expect_length(rules, 1)
  expect_equal(rules[[1]]$id, "tmp.rule")
  expect_equal(rules[[1]]$level, "low")
})
