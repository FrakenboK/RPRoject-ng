library(jsonlite)

get_s3_item <- function(s3_bucket_url, item_name) {
  # Поддерживаем оба варианта имён переменных: новые (AWS_*) и старые (S3_*)
  s3_endpoint <- Sys.getenv("S3_ENDPOINT_URL",
                   Sys.getenv("S3_ENDPOINT", ""))
  s3_access_key <- Sys.getenv("AWS_ACCESS_KEY_ID",
                     Sys.getenv("S3_ACCESS_KEY", ""))
  s3_secret_key <- Sys.getenv("AWS_SECRET_ACCESS_KEY",
                     Sys.getenv("S3_SECRET_KEY", ""))

  # Строим прямой HTTP URL:
  # Если endpoint вида https://BUCKET.s3.host — добавляем /item_name
  # Иначе строим https://BUCKET.s3.HOST/item_name
  if (nchar(s3_endpoint) > 0) {
    base <- gsub("/+$", "", s3_endpoint)
    download_url <- paste0(base, "/", item_name)
  } else {
    # формируем из s3_bucket_url
    base <- gsub("/+$", "", s3_bucket_url)
    download_url <- paste0(base, "/", item_name)
  }

  info(sprintf("S3 fetch URL: %s", download_url))

  tryCatch({
    # Добавляем auth-заголовок только если ключи заданы
    headers <- c()
    if (nchar(s3_access_key) > 0 && nchar(s3_secret_key) > 0) {
      # Простой Bearer/Basic — для публичных бакетов не нужно
      info("Using access key authentication")
    } else {
      info("Public bucket, no auth")
    }

    # Используем curl напрямую через download.file
    tmp_file <- tempfile(fileext = ".json")
    on.exit(unlink(tmp_file), add = TRUE)

    result <- tryCatch({
      download.file(
        url      = download_url,
        destfile = tmp_file,
        quiet    = TRUE,
        method   = "libcurl"
      )
      0L
    }, warning = function(w) {
      # download.file может warning при HTTP != 200
      if (grepl("404|403|40[0-9]|50[0-9]", conditionMessage(w))) {
        stop(conditionMessage(w))
      }
      0L
    })

    if (!file.exists(tmp_file) || file.info(tmp_file)$size == 0) {
      stop(sprintf("Downloaded file is empty or missing: %s", download_url))
    }

    info(sprintf("Downloaded %.1f MB", file.info(tmp_file)$size / 1e6))

    # Файл может содержать невалидные UTF-8 байты в бинарных полях (напр. hexpeek).
    # Читаем в latin1, тогда iconv перекодирует в UTF-8 с заменой невалидных символов
    json_str <- tryCatch({
      raw_bytes <- readBin(tmp_file, "raw", n = file.info(tmp_file)$size)
      # Преобразуем рав в latin1-строку, затем iconv latin1->UTF-8 sub=""
      latin1_str <- rawToChar(raw_bytes)
      iconv(latin1_str, from = "latin1", to = "UTF-8", sub = "")
    }, error = function(e) {
      # запасной вариант: читаем строками через readLines
      lines <- readLines(tmp_file, warn = FALSE, encoding = "latin1")
      paste(lines, collapse = "\n")
    })

    json_data <- fromJSON(json_str, simplifyVector = FALSE)
    return(json_data)

  }, error = function(e) {
    stop(sprintf("Failed to get S3 item '%s': %s", download_url, e$message))
  })
}

# Скачивает NDJSON (Zeek conn.log в JSON-режиме): по объекту на строку.
get_s3_ndjson <- function(s3_bucket_url, item_name) {
  s3_endpoint <- Sys.getenv("S3_ENDPOINT_URL", Sys.getenv("S3_ENDPOINT", ""))
  base <- gsub("/+$", "", if (nchar(s3_endpoint) > 0) s3_endpoint else s3_bucket_url)
  download_url <- paste0(base, "/", item_name)

  info(sprintf("S3 NDJSON fetch URL: %s", download_url))

  tmp_file <- tempfile(fileext = ".ndjson")
  on.exit(unlink(tmp_file), add = TRUE)

  download.file(url = download_url, destfile = tmp_file, quiet = TRUE, method = "libcurl")

  if (!file.exists(tmp_file) || file.info(tmp_file)$size == 0) {
    stop(sprintf("Downloaded NDJSON is empty or missing: %s", download_url))
  }

  lines <- readLines(tmp_file, warn = FALSE, encoding = "UTF-8")
  lines <- lines[nzchar(trimws(lines)) & !startsWith(trimws(lines), "#")]

  lapply(lines, function(ln) fromJSON(ln, simplifyVector = FALSE))
}
