source_etl()

test_that("empty_network_flows returns canonical columns", {
  empty <- empty_network_flows()
  expect_equal(nrow(empty), 0)
  expect_true(all(UNIFIED_FLOW_COLUMNS %in% names(empty)))
  expect_equal(names(empty), UNIFIED_FLOW_COLUMNS)
})

test_that("make_event_ids sanitizes and indexes records", {
  ids <- make_event_ids("raw/path/file.pcap", "file.pcap", c(1L, 2L, 3L))
  expect_equal(ids, c(
    "raw/path/file.pcap::file.pcap#1",
    "raw/path/file.pcap::file.pcap#2",
    "raw/path/file.pcap::file.pcap#3"
  ))
})

test_that("make_event_ids backfills missing record_index from position", {
  ids <- make_event_ids("k", "f", c(NA, NA, NA))
  expect_equal(ids, c("k::f#1", "k::f#2", "k::f#3"))
})

test_that("make_event_ids escapes unsupported characters", {
  ids <- make_event_ids("path with space!", "name@home", 1L)
  expect_equal(ids, "path_with_space_::name_home#1")
})

test_that("make_event_ids is globally unique across source_record_index", {
  ids <- make_event_ids(
    source_key = rep("k", 5),
    source_file_name = c("a", "a", "b", "b", "b"),
    source_record_index = c(1L, 2L, 1L, 2L, 3L)
  )
  expect_equal(length(unique(ids)), 5)
})

test_that("base_unified_frame produces n rows with all required columns", {
  src <- data.frame(
    key = "s3://bucket/path/file.csv",
    dataset_name = "unsw-nb15",
    extension = "csv",
    stringsAsFactors = FALSE
  )
  frame <- base_unified_frame(3, src, "run-1", "csv_unsw_nb15", "csv")
  expect_equal(nrow(frame), 3)
  expect_equal(frame$ingest_run_id, rep("run-1", 3))
  expect_equal(frame$source_dataset, rep("unsw-nb15", 3))
  expect_equal(frame$handler_name, rep("csv_unsw_nb15", 3))
  expect_equal(frame$source_record_index, 1:3)
  expect_equal(frame$source_file_name, rep("file.csv", 3))
  expect_true(all(UNIFIED_FLOW_COLUMNS %in% names(frame)))
})

test_that("base_unified_frame respects source_file_name override", {
  src <- data.frame(
    key = "archive.zip",
    dataset_name = "kyoto-2006-plus",
    extension = "zip",
    source_file_name = "2007/01/20070101.txt",
    stringsAsFactors = FALSE
  )
  frame <- base_unified_frame(2, src, "run-x", "zip_kyoto", "zip")
  expect_equal(frame$source_file_name, rep("2007/01/20070101.txt", 2))
})

test_that("infer_attack_category labels malicious and benign", {
  labels <- c("Botnet-Neris", "background", "benign", "malware-foo", "")
  result <- infer_attack_category(labels)
  expect_equal(result[1], "malicious")
  expect_equal(result[2], "benign")
  expect_equal(result[3], "benign")
  expect_equal(result[4], "malicious")
  expect_equal(result[5], "")
})

test_that("infer_malicious_flag returns logical TRUE/FALSE/NA", {
  result <- infer_malicious_flag(c("Botnet", "Normal", "unknown"))
  expect_true(result[1])
  expect_false(result[2])
  expect_true(is.na(result[3]))
})

test_that("finalize_network_flows backfills ip_version and flow_end", {
  src <- data.frame(
    key = "x", dataset_name = "ds", extension = "csv",
    stringsAsFactors = FALSE
  )
  frame <- base_unified_frame(2, src, "run", "h", "csv")
  frame$src_ip <- c("10.0.0.1", "fe80::1")
  frame$dst_ip <- c("10.0.0.2", "fe80::2")
  frame$flow_start <- as.POSIXct(c("2024-01-01 00:00:00", "2024-01-01 00:00:00"), tz = "UTC")
  frame$duration_sec <- c(5, 10)

  final <- finalize_network_flows(frame)
  expect_equal(final$ip_version, c("ipv4", "ipv6"))
  expect_equal(as.numeric(final$flow_end - final$flow_start, units = "secs"),
               c(5, 10))
})

test_that("finalize_network_flows regenerates event_id from key+file+index", {
  src <- data.frame(
    key = "s3://b/k", dataset_name = "ds", extension = "csv",
    stringsAsFactors = FALSE
  )
  frame <- base_unified_frame(2, src, "run", "h", "csv")
  final <- finalize_network_flows(frame)
  expect_match(final$event_id[1], "^s3://b/k::k#1$")
  expect_match(final$event_id[2], "^s3://b/k::k#2$")
})

test_that("finalize_network_flows accepts empty input", {
  result <- finalize_network_flows(empty_network_flows())
  expect_equal(nrow(result), 0)
  expect_equal(names(result), UNIFIED_FLOW_COLUMNS)
})
