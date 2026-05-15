library(jsonlite)

aws_cli_env <- function() {
  c(
    sprintf("AWS_ACCESS_KEY_ID=%s", Sys.getenv("AWS_ACCESS_KEY_ID", "")),
    sprintf("AWS_SECRET_ACCESS_KEY=%s", Sys.getenv("AWS_SECRET_ACCESS_KEY", "")),
    sprintf("AWS_DEFAULT_REGION=%s", Sys.getenv("AWS_DEFAULT_REGION", "us-east-1"))
  )
}

aws_cli_args <- function(args) {
  endpoint <- Sys.getenv("S3_ENDPOINT_URL", "")
  if (!nzchar(endpoint)) {
    return(args)
  }

  c("--endpoint-url", endpoint, args)
}

aws_cli_json <- function(args) {
  output <- run_command(
    command = "aws",
    args = aws_cli_args(args),
    env = aws_cli_env()
  )

  jsonlite::fromJSON(paste(output, collapse = "\n"), simplifyDataFrame = TRUE)
}

list_s3_objects <- function(bucket, prefix = "") {
  if (!nzchar(bucket)) {
    stop("S3_BUCKET is not configured")
  }

  info(sprintf("Listing all objects in s3://%s/%s", bucket, prefix))

  contents_parts <- list()
  continuation_token <- NULL

  repeat {
    args <- c(
      "s3api", "list-objects-v2",
      "--bucket", bucket,
      "--prefix", prefix,
      "--output", "json"
    )

    if (!is.null(continuation_token) && nzchar(continuation_token)) {
      args <- c(args, "--continuation-token", continuation_token)
    }

    response <- aws_cli_json(args)
    if (!is.null(response$Contents) && length(response$Contents) > 0) {
      contents_parts[[length(contents_parts) + 1L]] <- as.data.frame(
        response$Contents,
        stringsAsFactors = FALSE
      )
    }

    is_truncated <- isTRUE(response$IsTruncated)
    next_token <- safe_character(response$NextContinuationToken %||% "")

    if (!is_truncated || !nzchar(next_token)) {
      break
    }

    continuation_token <- next_token
  }

  if (length(contents_parts) == 0) {
    return(data.frame(
      bucket = character(),
      key = character(),
      size = numeric(),
      last_modified = character(),
      etag = character(),
      dataset_name = character(),
      extension = character(),
      stringsAsFactors = FALSE
    ))
  }

  contents <- data.table::rbindlist(contents_parts, fill = TRUE)
  contents <- as.data.frame(contents, stringsAsFactors = FALSE)
  names(contents) <- tolower(names(contents))

  data.frame(
    bucket = bucket,
    key = contents$key,
    size = safe_uint64(contents$size),
    last_modified = safe_character(contents$lastmodified),
    etag = safe_character(contents$etag),
    dataset_name = vapply(contents$key, infer_source_dataset, character(1)),
    extension = vapply(contents$key, infer_extension, character(1)),
    stringsAsFactors = FALSE
  )
}

filter_source_objects <- function(objects) {
  if (nrow(objects) == 0) {
    return(objects)
  }

  objects <- objects[!grepl("/$", objects$key), , drop = FALSE]
  objects[order(objects$key), , drop = FALSE]
}

download_s3_object <- function(bucket, key, destination_root) {
  local_path <- file.path(destination_root, key)
  ensure_dir(dirname(local_path))

  info(sprintf("Downloading s3://%s/%s", bucket, key))

  run_command(
    command = "aws",
    args = aws_cli_args(c(
      "s3", "cp",
      sprintf("s3://%s/%s", bucket, key),
      local_path
    )),
    env = aws_cli_env()
  )

  normalizePath(local_path, winslash = "/", mustWork = TRUE)
}

infer_source_dataset <- function(key) {
  lowered <- tolower(key)

  if (grepl("unsw", lowered)) {
    return("unsw-nb15")
  }

  if (grepl("kyoto", lowered)) {
    return("kyoto-2006-plus")
  }

  if (grepl("stratosphere|ctu-malware", lowered)) {
    return("stratosphereips")
  }

  "unknown"
}

infer_extension <- function(path) {
  lowered <- tolower(path)

  if (grepl("\\.pcapng$", lowered)) return("pcapng")
  if (grepl("\\.pcap$", lowered)) return("pcap")
  if (grepl("\\.binetflow$", lowered)) return("binetflow")
  if (grepl("\\.csv$", lowered)) return("csv")
  if (grepl("\\.zip$", lowered)) return("zip")
  if (grepl("\\.txt$", lowered)) return("txt")

  tools::file_ext(lowered)
}

choose_handler <- function(source_key, local_path) {
  extension <- infer_extension(source_key)

  if (extension %in% c("pcap", "pcapng")) {
    return("pcap_zeek")
  }

  if (extension == "binetflow") {
    return("binetflow")
  }

  if (extension == "csv") {
    return("csv")
  }

  if (extension == "zip") {
    return("zip")
  }

  if (extension == "txt" && grepl("kyoto", tolower(source_key))) {
    return("kyoto_txt")
  }

  "unsupported"
}
