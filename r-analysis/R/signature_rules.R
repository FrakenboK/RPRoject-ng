library(yaml)
library(data.table)

load_sigma_rules <- function(rules_dir) {
  if (!dir.exists(rules_dir)) {
    warning_log(sprintf("Sigma rules directory does not exist: %s", rules_dir))
    return(list())
  }

  rule_files <- list.files(rules_dir, pattern = "\\.ya?ml$", full.names = TRUE, recursive = TRUE)
  if (length(rule_files) == 0) {
    return(list())
  }

  lapply(rule_files, function(path) {
    rule <- yaml::read_yaml(path)
    rule$file_path <- path
    rule
  })
}

build_sigma_sql <- function(rule) {
  detection <- rule$detection
  if (is.null(detection) || is.null(detection$condition)) {
    stop(sprintf("Sigma rule %s has no detection condition", rule$id %||% rule$title))
  }

  selection_names <- setdiff(names(detection), "condition")
  if (length(selection_names) == 0) {
    stop(sprintf("Sigma rule %s has no selections", rule$id %||% rule$title))
  }

  selection_sql <- lapply(selection_names, function(name) {
    build_selection_sql(detection[[name]])
  })
  names(selection_sql) <- selection_names

  condition_to_sql(detection$condition, selection_sql)
}

build_selection_sql <- function(selection) {
  if (!is.list(selection) || is.null(names(selection))) {
    stop("Only named Sigma selections are supported")
  }

  field_sql <- vapply(names(selection), function(field_name) {
    build_field_sql(field_name, selection[[field_name]])
  }, character(1))

  paste0("(", paste(field_sql, collapse = " AND "), ")")
}

build_field_sql <- function(field_name, value) {
  parts <- strsplit(field_name, "\\|", perl = TRUE)[[1]]
  column_name <- parts[1]
  modifiers <- parts[-1]

  if (length(modifiers) == 0) {
    modifiers <- "eq"
  }

  value_sql <- build_value_sql(column_name, value, modifiers)
  paste0("(", value_sql, ")")
}

build_value_sql <- function(column_name, value, modifiers) {
  modifier <- modifiers[[1]]

  if (modifier == "exists") {
    exists_flag <- isTRUE(value)
    return(if (exists_flag) sprintf("%s IS NOT NULL", column_name) else sprintf("%s IS NULL", column_name))
  }

  if (length(value) > 1 && !is.list(value)) {
    parts <- vapply(value, function(item) build_scalar_sql(column_name, item, modifier), character(1))
    return(sprintf("(%s)", paste(parts, collapse = " OR ")))
  }

  if (is.list(value) && is.null(names(value))) {
    parts <- vapply(value, function(item) build_scalar_sql(column_name, item, modifier), character(1))
    return(sprintf("(%s)", paste(parts, collapse = " OR ")))
  }

  build_scalar_sql(column_name, value, modifier)
}

build_scalar_sql <- function(column_name, value, modifier) {
  if (modifier == "eq") {
    if (is.numeric(value)) {
      return(sprintf("%s = %s", column_name, as.character(value)))
    }
    return(sprintf("%s = %s", column_name, quote_sql_string(value)))
  }

  if (modifier == "contains") {
    return(sprintf("positionCaseInsensitiveUTF8(%s, %s) > 0", column_name, quote_sql_string(value)))
  }

  if (modifier == "startswith") {
    return(sprintf("startsWith(lowerUTF8(%s), lowerUTF8(%s))", column_name, quote_sql_string(value)))
  }

  if (modifier == "endswith") {
    return(sprintf("endsWith(lowerUTF8(%s), lowerUTF8(%s))", column_name, quote_sql_string(value)))
  }

  if (modifier == "re") {
    return(sprintf("match(%s, %s)", column_name, quote_sql_string(value)))
  }

  if (modifier == "gt") {
    return(sprintf("%s > %s", column_name, as.character(value)))
  }

  if (modifier == "gte") {
    return(sprintf("%s >= %s", column_name, as.character(value)))
  }

  if (modifier == "lt") {
    return(sprintf("%s < %s", column_name, as.character(value)))
  }

  if (modifier == "lte") {
    return(sprintf("%s <= %s", column_name, as.character(value)))
  }

  if (modifier == "cidr") {
    return(sprintf("isIPAddressInRange(%s, %s)", column_name, quote_sql_string(value)))
  }

  if (modifier == "between") {
    return(sprintf("%s BETWEEN %s AND %s", column_name, as.character(value[[1]]), as.character(value[[2]])))
  }

  stop(sprintf("Unsupported Sigma modifier: %s", modifier))
}

condition_to_sql <- function(condition, selection_sql) {
  sql <- safe_character(condition)

  pattern_names <- names(selection_sql)

  for (name in pattern_names) {
    star_pattern <- paste0("1 of ", name, "\\*")
    if (grepl(star_pattern, sql, perl = TRUE)) {
      matched <- selection_sql[startsWith(names(selection_sql), name)]
      sql <- gsub(star_pattern, paste0("(", paste(unlist(matched), collapse = " OR "), ")"), sql, perl = TRUE)
    }

    all_pattern <- paste0("all of ", name, "\\*")
    if (grepl(all_pattern, sql, perl = TRUE)) {
      matched <- selection_sql[startsWith(names(selection_sql), name)]
      sql <- gsub(all_pattern, paste0("(", paste(unlist(matched), collapse = " AND "), ")"), sql, perl = TRUE)
    }
  }

  for (name in pattern_names) {
    sql <- gsub(
      sprintf("\\b%s\\b", name),
      paste0("(", selection_sql[[name]], ")"),
      sql,
      perl = TRUE
    )
  }

  sql <- gsub("\\band\\b", "AND", sql, ignore.case = TRUE)
  sql <- gsub("\\bor\\b", "OR", sql, ignore.case = TRUE)
  sql <- gsub("\\bnot\\b", "NOT", sql, ignore.case = TRUE)
  sql
}

run_signature_analysis <- function(conn, analysis_run_id, rules_dir) {
  rules <- load_sigma_rules(rules_dir)
  if (length(rules) == 0) {
    warning_log("No Sigma rules found")
    return(list(detections = data.frame(), events = data.frame()))
  }

  all_detections <- list()
  all_events <- list()

  for (rule in rules) {
    sql_where <- build_sigma_sql(rule)
    matches <- fetch_signature_matches(conn, sql_where)

    if (nrow(matches) == 0) {
      next
    }

    grouped <- data.table::as.data.table(matches)
    grouped[, src_port := safe_port(src_port)]
    grouped[, dst_port := safe_port(dst_port)]
    grouped[, detection_group := paste(src_ip, dst_ip, ifelse(is.na(dst_port), "", dst_port), transport_proto, sep = "|")]

    summaries <- grouped[, .(
      first_seen = suppressWarnings(min(flow_start, na.rm = TRUE)),
      last_seen = suppressWarnings(max(flow_start, na.rm = TRUE)),
      flow_count = .N,
      src_ip = src_ip[[1]],
      src_port = safe_port(src_port[[1]]),
      dst_ip = dst_ip[[1]],
      dst_port = safe_port(dst_port[[1]]),
      transport_proto = safe_character(transport_proto[[1]]),
      app_proto = safe_character(app_proto[[1]])
    ), by = detection_group]

    detections_rows <- vector("list", nrow(summaries))
    events_rows <- vector("list", nrow(summaries))

    for (idx in seq_len(nrow(summaries))) {
      summary_row <- summaries[idx]
      if (!is.finite(as.numeric(summary_row$first_seen[[1]]))) {
        summary_row$first_seen[[1]] <- as.POSIXct(NA, origin = "1970-01-01", tz = "UTC")
      }
      if (!is.finite(as.numeric(summary_row$last_seen[[1]]))) {
        summary_row$last_seen[[1]] <- as.POSIXct(NA, origin = "1970-01-01", tz = "UTC")
      }
      detection_id <- build_detection_id(analysis_run_id)
      detail <- list(
        sigma_file = basename(rule$file_path),
        sigma_condition = rule$detection$condition,
        flow_count = summary_row$flow_count[[1]]
      )

      detections_rows[[idx]] <- data.frame(
        detection_id = detection_id,
        analysis_run_id = analysis_run_id,
        detector_type = "signature",
        detector_name = "sigma",
        rule_id = safe_character(rule$id %||% basename(rule$file_path)),
        rule_name = safe_character(rule$title %||% basename(rule$file_path)),
        severity = safe_character(rule$level %||% "medium"),
        confidence_score = 1,
        entity_type = "flow_tuple",
        entity_value = summary_row$detection_group[[1]],
        src_ip = summary_row$src_ip[[1]],
        src_port = summary_row$src_port[[1]],
        dst_ip = summary_row$dst_ip[[1]],
        dst_port = summary_row$dst_port[[1]],
        transport_proto = summary_row$transport_proto[[1]],
        app_proto = summary_row$app_proto[[1]],
        first_seen = summary_row$first_seen[[1]],
        last_seen = summary_row$last_seen[[1]],
        flow_count = summary_row$flow_count[[1]],
        aggregation_key = summary_row$detection_group[[1]],
        title = safe_character(rule$title %||% basename(rule$file_path)),
        description = safe_character(rule$description %||% ""),
        tags_json = safe_json(rule$tags %||% list()),
        detail_json = safe_json(detail),
        created_at = Sys.time(),
        stringsAsFactors = FALSE
      )

      group_events <- grouped[detection_group == summary_row$detection_group[[1]]]
      events_rows[[idx]] <- data.frame(
        analysis_run_id = analysis_run_id,
        detection_id = detection_id,
        detector_type = "signature",
        rule_id = safe_character(rule$id %||% basename(rule$file_path)),
        event_id = safe_character(group_events$event_id),
        flow_id = safe_character(group_events$flow_id),
        flow_start = group_events$flow_start,
        src_ip = safe_character(group_events$src_ip),
        src_port = safe_port(group_events$src_port),
        dst_ip = safe_character(group_events$dst_ip),
        dst_port = safe_port(group_events$dst_port),
        transport_proto = safe_character(group_events$transport_proto),
        app_proto = safe_character(group_events$app_proto),
        source_dataset = safe_character(group_events$source_dataset),
        source_key = safe_character(group_events$source_key),
        stringsAsFactors = FALSE
      )
    }

    all_detections[[length(all_detections) + 1L]] <- data.table::rbindlist(detections_rows, fill = TRUE)
    all_events[[length(all_events) + 1L]] <- data.table::rbindlist(events_rows, fill = TRUE)
  }

  list(
    detections = if (length(all_detections) == 0) data.frame() else data.table::rbindlist(all_detections, fill = TRUE),
    events = if (length(all_events) == 0) data.frame() else data.table::rbindlist(all_events, fill = TRUE)
  )
}
