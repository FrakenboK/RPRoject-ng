source_etl_full()

make_source_object <- function(key, dataset = "unknown", ext = "csv") {
  data.frame(
    bucket = "test",
    key = key,
    size = 0,
    last_modified = "",
    etag = "",
    dataset_name = dataset,
    extension = ext,
    stringsAsFactors = FALSE
  )
}

write_unsw_csv <- function(rows = 3L) {
  values <- list(
    srcip = "10.0.0.1", sport = 1234, dstip = "10.0.0.2", dsport = 80,
    proto = "tcp", state = "FIN", dur = 1.5, sbytes = 100, dbytes = 200,
    sttl = 64, dttl = 64, sloss = 0, dloss = 0, service = "http",
    Sload = 0, Dload = 0, Spkts = 2, Dpkts = 3, swin = 0, dwin = 0,
    stcpb = 0, dtcpb = 0, smeansz = 0, dmeansz = 0, trans_depth = 0,
    res_bdy_len = 0, Sjit = 0, Djit = 0, Stime = 1577836800,
    Ltime = 1577836810, Sintpkt = 0, Dintpkt = 0, tcprtt = 0,
    synack = 0, ackdat = 0, is_sm_ips_ports = 0, ct_state_ttl = 0,
    ct_flw_http_mthd = 0, is_ftp_login = 0, ct_ftp_cmd = 0,
    ct_srv_src = 0, ct_srv_dst = 0, ct_dst_ltm = 0, ct_src_ltm = 0,
    ct_src_dport_ltm = 0, ct_dst_sport_ltm = 0, ct_dst_src_ltm = 0,
    attack_cat = "Normal", label = 0
  )
  row_str <- paste(unlist(values), collapse = ",")
  body <- paste(rep(row_str, rows), collapse = "\n")
  path <- tempfile(fileext = ".csv")
  writeLines(body, path)
  path
}

test_that("parse_unsw_nb15_csv parses headerless rows", {
  path <- write_unsw_csv(rows = 2L)
  on.exit(unlink(path), add = TRUE)

  src <- make_source_object("raw/unsw/file.csv", "unsw-nb15", "csv")
  df <- parse_unsw_nb15_csv(path, src, "run-1", header = FALSE)

  expect_equal(nrow(df), 2)
  expect_equal(unique(df$src_ip), "10.0.0.1")
  expect_equal(unique(df$dst_port), 80L)
  expect_equal(unique(df$transport_proto), "TCP")
  expect_equal(unique(df$app_proto), "http")
  expect_equal(df$bytes_total, c(300, 300))
  expect_equal(df$packets_total, c(5, 5))
  expect_equal(df$handler_name, rep("csv_unsw_nb15", 2))
})

test_that("parse_generic_csv handles minimum schema", {
  body <- paste(
    "src_ip,dst_ip,proto,dst_port,bytes_total,label",
    "10.0.0.1,10.0.0.2,tcp,443,1500,benign",
    "10.0.0.3,10.0.0.4,udp,53,200,attack",
    sep = "\n"
  )
  path <- tempfile(fileext = ".csv")
  writeLines(body, path)
  on.exit(unlink(path), add = TRUE)

  src <- make_source_object("raw/x/generic.csv", "unknown", "csv")
  df <- parse_generic_csv(path, src, "run-3")
  expect_equal(nrow(df), 2)
  expect_equal(df$src_ip, c("10.0.0.1", "10.0.0.3"))
  expect_equal(df$transport_proto, c("TCP", "UDP"))
  expect_equal(df$attack_category[1], "benign")
  expect_equal(df$attack_category[2], "malicious")
  expect_false(df$is_malicious[1])
  expect_true(df$is_malicious[2])
})

test_that("parse_generic_csv rejects schema without required ip/proto", {
  path <- tempfile(fileext = ".csv")
  writeLines("foo,bar\n1,2", path)
  on.exit(unlink(path), add = TRUE)

  src <- make_source_object("raw/x/bad.csv", "unknown", "csv")
  expect_error(parse_generic_csv(path, src, "run-4"),
               "Unsupported generic CSV")
})

test_that("parse_binetflow_file maps standard columns", {
  body <- paste(
    "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label",
    "2011/08/10 09:46:54.452,2.5,tcp,10.0.0.1,12345,->,10.0.0.2,80,FIN_FIN,0,0,10,1500,500,flow=From-Botnet",
    "2011/08/10 09:46:55.000,1.0,udp,10.0.0.3,53000,->,10.0.0.4,53,CON,0,0,2,200,100,flow=Background",
    sep = "\n"
  )
  path <- tempfile(fileext = ".binetflow")
  writeLines(body, path)
  on.exit(unlink(path), add = TRUE)

  src <- make_source_object("raw/strato/a.binetflow",
                            "stratosphereips", "binetflow")
  df <- parse_binetflow_file(path, src, "run-5")

  expect_equal(nrow(df), 2)
  expect_equal(df$src_ip, c("10.0.0.1", "10.0.0.3"))
  expect_equal(df$dst_port, c(80L, 53L))
  expect_equal(df$transport_proto, c("TCP", "UDP"))
  expect_equal(df$packets_total, c(10, 2))
  expect_equal(df$bytes_total, c(1500, 200))
  expect_equal(df$bytes_src, c(500, 100))
  expect_equal(df$bytes_dst, c(1000, 100))
  expect_equal(df$attack_category[1], "malicious")
  expect_equal(df$attack_category[2], "benign")
})
