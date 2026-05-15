source_etl()

test_that("infer_source_dataset detects known datasets in keys", {
  expect_equal(infer_source_dataset("raw/UNSW-NB15/file.csv"), "unsw-nb15")
  expect_equal(infer_source_dataset("raw/kyoto2006/2007/01.txt"), "kyoto-2006-plus")
  expect_equal(infer_source_dataset("raw/stratosphere/ctu-malware.pcap"),
               "stratosphereips")
  expect_equal(infer_source_dataset("raw/CTU-Malware/file.binetflow"),
               "stratosphereips")
  expect_equal(infer_source_dataset("raw/random/file.pcap"), "unknown")
})

test_that("infer_extension matches expected formats case-insensitively", {
  expect_equal(infer_extension("foo.pcap"), "pcap")
  expect_equal(infer_extension("foo.PCAP"), "pcap")
  expect_equal(infer_extension("foo.pcapng"), "pcapng")
  expect_equal(infer_extension("foo.binetflow"), "binetflow")
  expect_equal(infer_extension("foo.csv"), "csv")
  expect_equal(infer_extension("foo.zip"), "zip")
  expect_equal(infer_extension("foo.txt"), "txt")
  expect_equal(infer_extension("README"), "")
})

test_that("choose_handler routes by extension", {
  expect_equal(choose_handler("a.pcap", "/tmp/a.pcap"), "pcap_zeek")
  expect_equal(choose_handler("a.pcapng", "/tmp/a.pcapng"), "pcap_zeek")
  expect_equal(choose_handler("a.binetflow", "/tmp/a.binetflow"), "binetflow")
  expect_equal(choose_handler("a.csv", "/tmp/a.csv"), "csv")
  expect_equal(choose_handler("a.zip", "/tmp/a.zip"), "zip")
  expect_equal(choose_handler("unknown.dat", "/tmp/x"), "unsupported")
})

test_that("choose_handler picks kyoto_txt only for kyoto txt", {
  expect_equal(choose_handler("kyoto2006/2007/01.txt", "/tmp/x"), "kyoto_txt")
  expect_equal(choose_handler("random/file.txt", "/tmp/x"), "unsupported")
})

test_that("filter_source_objects drops directory-like keys and sorts", {
  df <- data.frame(
    bucket = "b",
    key = c("a/file.csv", "b/", "c/file.pcap", "0/first.zip"),
    size = c(100, 0, 200, 300),
    last_modified = "",
    etag = "",
    dataset_name = "unknown",
    extension = c("csv", "", "pcap", "zip"),
    stringsAsFactors = FALSE
  )
  result <- filter_source_objects(df)
  expect_equal(nrow(result), 3)
  expect_false(any(grepl("/$", result$key)))
  expect_equal(result$key, c("0/first.zip", "a/file.csv", "c/file.pcap"))
})

test_that("filter_source_objects handles empty input", {
  df <- data.frame(
    bucket = character(), key = character(), size = numeric(),
    last_modified = character(), etag = character(),
    dataset_name = character(), extension = character(),
    stringsAsFactors = FALSE
  )
  expect_equal(nrow(filter_source_objects(df)), 0)
})
