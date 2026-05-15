library(data.table)
library(dbscan)
library(isotree)

prepare_feature_matrix <- function(df, numeric_columns) {
  if (nrow(df) == 0) {
    return(list(data = matrix(numeric(0), nrow = 0), rows = logical()))
  }

  matrix_data <- as.data.frame(df[, ..numeric_columns], stringsAsFactors = FALSE)
  for (col in names(matrix_data)) {
    matrix_data[[col]] <- normalize_score(matrix_data[[col]])
  }

  keep_rows <- complete.cases(matrix_data)
  matrix_scaled <- scale(as.matrix(matrix_data[keep_rows, , drop = FALSE]))
  matrix_scaled[is.na(matrix_scaled)] <- 0

  list(data = matrix_scaled, rows = keep_rows)
}

run_outlier_ensemble <- function(matrix_scaled, min_pts = 10L) {
  n <- nrow(matrix_scaled)
  if (n == 0) {
    return(data.frame())
  }

  if (n < 5) {
    return(data.frame(
      dbscan_noise = rep(FALSE, n),
      lof_score = rep(0, n),
      iforest_score = rep(0, n),
      ensemble_score = rep(0, n)
    ))
  }

  min_pts <- min(max(5L, min_pts), max(5L, n - 1L))
  knn_distance <- dbscan::kNNdist(matrix_scaled, k = min_pts)
  eps <- as.numeric(stats::quantile(knn_distance, probs = 0.95, na.rm = TRUE))
  if (!is.finite(eps) || eps <= 0) {
    eps <- 1
  }

  dbscan_fit <- dbscan::dbscan(matrix_scaled, eps = eps, minPts = min_pts)
  dbscan_noise <- dbscan_fit$cluster == 0

  lof_score <- dbscan::lof(matrix_scaled, minPts = min_pts)
  lof_rank <- percent_rank_vec(lof_score)

  iforest_model <- isotree::isolation.forest(
    matrix_scaled,
    ntrees = 200,
    sample_size = min(n, 256),
    ndim = 1
  )
  iforest_score <- as.numeric(predict(iforest_model, matrix_scaled, type = "score"))
  iforest_rank <- percent_rank_vec(iforest_score)

  ensemble_score <- rowMeans(cbind(as.numeric(dbscan_noise), lof_rank, iforest_rank))

  data.frame(
    dbscan_noise = dbscan_noise,
    lof_score = lof_score,
    iforest_score = iforest_score,
    ensemble_score = ensemble_score
  )
}

build_window_detection_events <- function(conn, analysis_run_id, detection_id, rule_id, detector_name, src_ip, window_start, window_minutes) {
  events <- fetch_events_for_window_detection(conn, src_ip, window_start, window_minutes)
  if (nrow(events) == 0) {
    return(data.frame())
  }

  data.frame(
    analysis_run_id = analysis_run_id,
    detection_id = detection_id,
    detector_type = "behavioral",
    rule_id = rule_id,
    event_id = safe_character(events$event_id),
    flow_id = safe_character(events$flow_id),
    flow_start = events$flow_start,
    src_ip = safe_character(events$src_ip),
    src_port = safe_port(events$src_port),
    dst_ip = safe_character(events$dst_ip),
    dst_port = safe_port(events$dst_port),
    transport_proto = safe_character(events$transport_proto),
    app_proto = safe_character(events$app_proto),
    source_dataset = safe_character(events$source_dataset),
    source_key = safe_character(events$source_key),
    stringsAsFactors = FALSE
  )
}

build_pair_detection_events <- function(conn, analysis_run_id, detection_id, rule_id, src_ip, dst_ip, dst_port, transport_proto) {
  events <- fetch_events_for_pair_detection(conn, src_ip, dst_ip, dst_port, transport_proto)
  if (nrow(events) == 0) {
    return(data.frame())
  }

  data.frame(
    analysis_run_id = analysis_run_id,
    detection_id = detection_id,
    detector_type = "behavioral",
    rule_id = rule_id,
    event_id = safe_character(events$event_id),
    flow_id = safe_character(events$flow_id),
    flow_start = events$flow_start,
    src_ip = safe_character(events$src_ip),
    src_port = safe_port(events$src_port),
    dst_ip = safe_character(events$dst_ip),
    dst_port = safe_port(events$dst_port),
    transport_proto = safe_character(events$transport_proto),
    app_proto = safe_character(events$app_proto),
    source_dataset = safe_character(events$source_dataset),
    source_key = safe_character(events$source_key),
    stringsAsFactors = FALSE
  )
}

run_behavioral_analysis <- function(conn, analysis_run_id, window_minutes = 5L) {
  src_window <- as.data.table(fetch_src_window_features(conn, window_minutes = window_minutes))
  pair_features <- as.data.table(fetch_pair_features(conn))
  max_window_ml_rows <- 20000L
  max_pair_ml_rows <- 15000L

  detections <- list()
  events <- list()

  if (nrow(src_window) > 0) {
    info(sprintf("Behavioral stage: %d source-window aggregate row(s) loaded", nrow(src_window)))
    numeric_window_cols <- c(
      "flow_count", "uniq_dst_ips", "uniq_dst_ports", "avg_duration_sec", "max_duration_sec",
      "bytes_total_sum", "packets_total_sum", "failure_ratio", "web_ratio", "smb_ratio", "remote_admin_ratio"
    )
    for (col_name in numeric_window_cols) {
      src_window[[col_name]] <- normalize_score(src_window[[col_name]])
    }
    src_window[, window_start := as.POSIXct(window_start, tz = "UTC")]
    src_window[, analysis_row_id := .I]
    src_window[, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") := .(FALSE, 0, 0, 0)]

    src_window_ml <- src_window[
      flow_count >= 10 |
      uniq_dst_ips >= 6 |
      uniq_dst_ports >= 6 |
      failure_ratio >= 0.15 |
      web_ratio >= 0.50 |
      smb_ratio >= 0.25
    ]

    if (nrow(src_window_ml) > max_window_ml_rows) {
      src_window_ml[, activity_score :=
        flow_count +
        (uniq_dst_ips * 5) +
        (uniq_dst_ports * 5) +
        (failure_ratio * 50) +
        (web_ratio * 10) +
        (smb_ratio * 10) +
        pmin(max_duration_sec, 300)
      ]
      data.table::setorder(src_window_ml, -activity_score)
      src_window_ml <- src_window_ml[seq_len(max_window_ml_rows)]
      src_window_ml[, activity_score := NULL]
    }

    info(sprintf(
      "Behavioral stage: %d source-window row(s) selected for DBSCAN/LOF/Isolation Forest",
      nrow(src_window_ml)
    ))

    src_window_matrix <- prepare_feature_matrix(
      src_window_ml,
      c("flow_count", "uniq_dst_ips", "uniq_dst_ports", "avg_duration_sec", "max_duration_sec",
        "bytes_total_sum", "packets_total_sum", "failure_ratio", "web_ratio", "smb_ratio", "remote_admin_ratio")
    )

    src_window_scores <- run_outlier_ensemble(src_window_matrix$data, min_pts = 10L)
    score_rows <- src_window_matrix$rows
    if (nrow(src_window_scores) > 0) {
      src_window_ml[score_rows, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") := src_window_scores]
      src_window[src_window_ml$analysis_row_id, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") :=
        .(src_window_ml$dbscan_noise, src_window_ml$lof_score, src_window_ml$iforest_score, src_window_ml$ensemble_score)]
    }

    port_scan <- src_window[
      flow_count >= 40 &
      uniq_dst_ports >= 20 &
      failure_ratio >= 0.50 &
      avg_duration_sec <= 10 &
      ensemble_score >= 0.80
    ]

    host_scan <- src_window[
      flow_count >= 40 &
      uniq_dst_ips >= 20 &
      failure_ratio >= 0.50 &
      avg_duration_sec <= 10 &
      ensemble_score >= 0.80
    ]

    web_bruteforce <- src_window[
      flow_count >= 50 &
      web_ratio >= 0.90 &
      uniq_dst_ports <= 3 &
      uniq_dst_ips <= 10 &
      failure_ratio >= 0.40 &
      avg_duration_sec <= 10 &
      ensemble_score >= 0.80
    ]

    smb_bruteforce <- src_window[
      flow_count >= 30 &
      smb_ratio >= 0.80 &
      uniq_dst_ports <= 2 &
      uniq_dst_ips <= 5 &
      failure_ratio >= 0.40 &
      avg_duration_sec <= 15 &
      ensemble_score >= 0.80
    ]

    add_window_detections <- function(candidate_df, rule_id, rule_name, severity, description) {
      if (nrow(candidate_df) == 0) {
        return(invisible(NULL))
      }

      for (idx in seq_len(nrow(candidate_df))) {
        row <- candidate_df[idx]
        detection_id <- build_detection_id(analysis_run_id)
        entity_value <- sprintf("%s|%s", row$src_ip[[1]], format(row$window_start[[1]], "%Y-%m-%d %H:%M:%S"))

        detections[[length(detections) + 1L]] <<- data.frame(
          detection_id = detection_id,
          analysis_run_id = analysis_run_id,
          detector_type = "behavioral",
          detector_name = detector_name,
          rule_id = rule_id,
          rule_name = rule_name,
          severity = severity,
          confidence_score = row$ensemble_score[[1]],
          entity_type = "src_ip_window",
          entity_value = entity_value,
          src_ip = row$src_ip[[1]],
          src_port = NA_integer_,
          dst_ip = "",
          dst_port = NA_integer_,
          transport_proto = row$transport_proto[[1]],
          app_proto = "",
          first_seen = row$window_start[[1]],
          last_seen = row$window_start[[1]] + as.difftime(window_minutes, units = "mins"),
          flow_count = row$flow_count[[1]],
          aggregation_key = entity_value,
          title = rule_name,
          description = description,
          tags_json = safe_json(list("behavioral", detector_name, rule_id)),
          detail_json = safe_json(list(
            flow_count = row$flow_count[[1]],
            uniq_dst_ips = row$uniq_dst_ips[[1]],
            uniq_dst_ports = row$uniq_dst_ports[[1]],
            failure_ratio = row$failure_ratio[[1]],
            web_ratio = row$web_ratio[[1]],
            smb_ratio = row$smb_ratio[[1]],
            lof_score = row$lof_score[[1]],
            iforest_score = row$iforest_score[[1]],
            ensemble_score = row$ensemble_score[[1]],
            dbscan_noise = row$dbscan_noise[[1]]
          )),
          created_at = Sys.time(),
          stringsAsFactors = FALSE
        )

        events[[length(events) + 1L]] <<- build_window_detection_events(
          conn = conn,
          analysis_run_id = analysis_run_id,
          detection_id = detection_id,
          rule_id = rule_id,
          detector_name = detector_name,
          src_ip = row$src_ip[[1]],
          window_start = row$window_start[[1]],
          window_minutes = window_minutes
        )
      }
    }

    detector_name <- "dbscan_lof_isolation_forest"
    add_window_detections(
      port_scan,
      "behavior.portscan.vertical",
      "Vertical Port Scan Candidate",
      "high",
      "Аномальное число уникальных портов на одном источнике в коротком временном окне."
    )
    add_window_detections(
      host_scan,
      "behavior.portscan.horizontal",
      "Horizontal Host Scan Candidate",
      "high",
      "Аномальное число уникальных адресов назначения на одном источнике в коротком временном окне."
    )
    add_window_detections(
      web_bruteforce,
      "behavior.http.bruteforce_or_fuzz",
      "HTTP Brute Force or Directory Fuzzing Candidate",
      "medium",
      "Высокочастотный HTTP-подобный трафик с признаками подбора или фаззинга по flow-паттерну."
    )
    add_window_detections(
      smb_bruteforce,
      "behavior.smb.bruteforce",
      "SMB Brute Force Candidate",
      "high",
      "Повторяющиеся TCP-сессии к SMB с большим числом ошибок и аномальными частотными признаками."
    )
  }

  if (nrow(pair_features) > 0) {
    info(sprintf("Behavioral stage: %d src-dst aggregate row(s) loaded", nrow(pair_features)))
    numeric_pair_cols <- c(
      "span_sec", "flow_count", "avg_duration_sec", "max_duration_sec", "duration_stddev",
      "bytes_total_sum", "avg_bytes_total", "bytes_stddev", "packets_total_sum",
      "avg_packets_total", "failure_ratio"
    )
    for (col_name in numeric_pair_cols) {
      pair_features[[col_name]] <- normalize_score(pair_features[[col_name]])
    }
    pair_features[, first_seen := as.POSIXct(first_seen, tz = "UTC")]
    pair_features[, last_seen := as.POSIXct(last_seen, tz = "UTC")]
    pair_features[, avg_interarrival_sec := ifelse(flow_count > 1, span_sec / (flow_count - 1), span_sec)]
    pair_features[, bytes_per_second := ifelse(span_sec > 0, bytes_total_sum / span_sec, bytes_total_sum)]
    pair_features[, analysis_row_id := .I]
    pair_features[, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") := .(FALSE, 0, 0, 0)]

    pair_features_ml <- pair_features[
      flow_count >= 5 &
      (span_sec >= 900 | avg_duration_sec >= 30 | max_duration_sec >= 120)
    ]

    if (nrow(pair_features_ml) > max_pair_ml_rows) {
      pair_features_ml[, activity_score :=
        (flow_count * 2) +
        pmin(span_sec, 86400) / 60 +
        pmin(avg_duration_sec, 3600) +
        pmin(max_duration_sec, 3600) +
        (bytes_total_sum / 1000000)
      ]
      data.table::setorder(pair_features_ml, -activity_score)
      pair_features_ml <- pair_features_ml[seq_len(max_pair_ml_rows)]
      pair_features_ml[, activity_score := NULL]
    }

    info(sprintf(
      "Behavioral stage: %d src-dst row(s) selected for DBSCAN/LOF/Isolation Forest",
      nrow(pair_features_ml)
    ))

    pair_matrix <- prepare_feature_matrix(
      pair_features_ml,
      c("flow_count", "span_sec", "avg_duration_sec", "max_duration_sec",
        "duration_stddev", "bytes_total_sum", "avg_bytes_total", "bytes_stddev",
        "packets_total_sum", "avg_packets_total", "failure_ratio",
        "avg_interarrival_sec", "bytes_per_second")
    )

    pair_scores <- run_outlier_ensemble(pair_matrix$data, min_pts = 10L)
    score_rows <- pair_matrix$rows
    if (nrow(pair_scores) > 0) {
      pair_features_ml[score_rows, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") := pair_scores]
      pair_features[pair_features_ml$analysis_row_id, c("dbscan_noise", "lof_score", "iforest_score", "ensemble_score") :=
        .(pair_features_ml$dbscan_noise, pair_features_ml$lof_score, pair_features_ml$iforest_score, pair_features_ml$ensemble_score)]
    }

    c2_candidates <- pair_features[
      flow_count >= 5 &
      flow_count <= 200 &
      span_sec >= 3600 &
      avg_duration_sec >= 120 &
      failure_ratio <= 0.15 &
      !dst_port %in% c(22, 23, 25, 53, 80, 110, 123, 135, 137, 138, 139, 143, 389, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443) &
      !tolower(app_proto) %in% c("smtp", "ssh", "dns", "http", "ssl", "ftp", "pop3", "imap", "dhcp", "ntp", "smb", "rdp") &
      ensemble_score >= 0.85
    ]

    if (nrow(c2_candidates) > 0) {
      for (idx in seq_len(nrow(c2_candidates))) {
        row <- c2_candidates[idx]
        detection_id <- build_detection_id(analysis_run_id)
        entity_value <- sprintf("%s->%s:%s", row$src_ip[[1]], row$dst_ip[[1]], row$dst_port[[1]])
        rule_id <- "behavior.long_lived_c2"
        rule_name <- "Long-Lived C2 Session Candidate"

        detections[[length(detections) + 1L]] <- data.frame(
          detection_id = detection_id,
          analysis_run_id = analysis_run_id,
          detector_type = "behavioral",
          detector_name = "dbscan_lof_isolation_forest",
          rule_id = rule_id,
          rule_name = rule_name,
          severity = "high",
          confidence_score = row$ensemble_score[[1]],
          entity_type = "src_dst_pair",
          entity_value = entity_value,
          src_ip = row$src_ip[[1]],
          src_port = NA_integer_,
          dst_ip = row$dst_ip[[1]],
          dst_port = safe_port(row$dst_port[[1]]),
          transport_proto = row$transport_proto[[1]],
          app_proto = safe_character(row$app_proto[[1]]),
          first_seen = row$first_seen[[1]],
          last_seen = row$last_seen[[1]],
          flow_count = row$flow_count[[1]],
          aggregation_key = entity_value,
          title = rule_name,
          description = "Долгоживущая или регулярно повторяющаяся TCP-коммуникация между парой узлов с аномальными признаками возможного C2.",
          tags_json = safe_json(list("behavioral", "c2", "long-lived")),
          detail_json = safe_json(list(
            span_sec = row$span_sec[[1]],
            avg_duration_sec = row$avg_duration_sec[[1]],
            max_duration_sec = row$max_duration_sec[[1]],
            avg_interarrival_sec = row$avg_interarrival_sec[[1]],
            bytes_per_second = row$bytes_per_second[[1]],
            failure_ratio = row$failure_ratio[[1]],
            lof_score = row$lof_score[[1]],
            iforest_score = row$iforest_score[[1]],
            ensemble_score = row$ensemble_score[[1]],
            dbscan_noise = row$dbscan_noise[[1]]
          )),
          created_at = Sys.time(),
          stringsAsFactors = FALSE
        )

        events[[length(events) + 1L]] <- build_pair_detection_events(
          conn = conn,
          analysis_run_id = analysis_run_id,
          detection_id = detection_id,
          rule_id = rule_id,
          src_ip = row$src_ip[[1]],
          dst_ip = row$dst_ip[[1]],
          dst_port = row$dst_port[[1]],
          transport_proto = row$transport_proto[[1]]
        )
      }
    }
  }

  list(
    detections = if (length(detections) == 0) data.frame() else data.table::rbindlist(detections, fill = TRUE),
    events = if (length(events) == 0) data.frame() else data.table::rbindlist(events, fill = TRUE)
  )
}
