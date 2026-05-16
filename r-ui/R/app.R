library(shiny)
library(bslib)
library(DT)
library(data.table)
library(jsonlite)

source("clickhouse_io.R", local = TRUE)
source("runner.R", local = TRUE)

options(bitmapType = "cairo")
try(Sys.setlocale("LC_CTYPE", "ru_RU.UTF-8"), silent = TRUE)
try(Sys.setlocale("LC_TIME", "ru_RU.UTF-8"), silent = TRUE)

`%||%` <- function(a, b) if (is.null(a) || length(a) == 0 || (length(a) == 1 && is.na(a))) b else a

plot_family <- function() "DejaVu Sans"

set_plot_par <- function(...) {
  par(family = plot_family(), ...)
}

render_empty_plot <- function(label) {
  set_plot_par(mar = c(1, 1, 1, 1))
  plot.new()
  text(0.5, 0.5, label, cex = 1.05)
}

build_time_choices <- function(step_minutes = 15L) {
  values <- seq(0, 24 * 60 - step_minutes, by = step_minutes)
  labels <- sprintf("%02d:%02d", values %/% 60, values %% 60)
  c(labels, "23:59")
}

split_time_value <- function(value, fallback = c("00:00", "23:59")) {
  ts_value <- as.POSIXct(value, tz = "UTC")
  if (length(ts_value) == 0 || is.na(ts_value[[1]])) {
    return(fallback[[1]])
  }

  format(ts_value[[1]], "%H:%M")
}

safe_range_value <- function(range_value, index) {
  if (is.null(range_value) || length(range_value) < index || is.na(range_value[[index]])) {
    return(NULL)
  }

  range_value[[index]]
}

combine_date_time <- function(date_value, time_value, end_default = FALSE) {
  if (is.null(date_value) || length(date_value) == 0 || is.na(date_value)) {
    return(NULL)
  }

  time_value <- time_value %||% if (isTRUE(end_default)) "23:59" else "00:00"
  as.POSIXct(sprintf("%s %s:00", format(as.Date(date_value), "%Y-%m-%d"), time_value), tz = "UTC")
}

format_int <- function(x) {
  if (is.null(x) || is.na(x)) return("—")
  formatC(as.numeric(x), format = "d", big.mark = " ")
}

format_bytes <- function(x) {
  if (is.null(x) || is.na(x)) return("—")
  units <- c("B", "KB", "MB", "GB", "TB")
  size <- as.numeric(x)
  if (size <= 0) return("0 B")
  power <- min(floor(log(size, 1024)), length(units) - 1)
  sprintf("%.2f %s", size / 1024^power, units[power + 1])
}

severity_badge <- function(severity) {
  color <- switch(tolower(as.character(severity)),
    "critical" = "danger",
    "high" = "danger",
    "medium" = "warning",
    "low" = "info",
    "secondary"
  )
  sprintf('<span class="badge bg-%s">%s</span>', color, severity)
}

status_badge <- function(state) {
  color <- switch(tolower(as.character(state)),
    "running" = "primary",
    "completed" = "success",
    "loaded" = "success",
    "failed" = "danger",
    "skipped" = "secondary",
    "idle" = "secondary",
    "secondary"
  )
  sprintf('<span class="badge bg-%s">%s</span>', color, state)
}

ui <- page_navbar(
  id = "main_nav",
  title = "RPR IPS",
  theme = bs_theme(bootswatch = "flatly", version = 5),
  fillable = FALSE,

  nav_panel(
    title = "Обзор",
    icon = icon("gauge-high"),

    layout_columns(
      col_widths = c(3, 3, 3, 3),
      value_box(
        title = "Flows загружено",
        value = textOutput("kpi_flows"),
        showcase = icon("network-wired"),
        theme = "primary"
      ),
      value_box(
        title = "Объектов из S3",
        value = textOutput("kpi_objects"),
        showcase = icon("box"),
        theme = "info"
      ),
      value_box(
        title = "Запусков анализа",
        value = textOutput("kpi_runs"),
        showcase = icon("rotate"),
        theme = "secondary"
      ),
      value_box(
        title = "Всего сработок",
        value = textOutput("kpi_detections"),
        showcase = icon("triangle-exclamation"),
        theme = "warning"
      )
    ),

    layout_columns(
      col_widths = c(6, 6),
      card(
        card_header("Сработки по severity"),
        plotOutput("plot_severity", height = "280px")
      ),
      card(
        card_header("Сработки по типу детектора"),
        layout_columns(
          col_widths = c(6, 6),
          value_box(
            title = "Signature",
            value = textOutput("kpi_signature"),
            theme = "info"
          ),
          value_box(
            title = "Behavioral",
            value = textOutput("kpi_behavioral"),
            theme = "warning"
          )
        )
      )
    ),

    card(
      card_header("Потоки по периоду"),
      layout_columns(
        col_widths = c(3, 5, 4),
        selectInput("flows_granularity", "Гранулярность",
                    choices = c("День" = "day", "Неделя" = "week", "Месяц" = "month"),
                    selected = "day"),
        dateRangeInput("flows_date_range", "Диапазон дат",
                       start = NULL, end = NULL,
                       startview = "year", weekstart = 1, separator = " — "),
        actionButton("flows_reset", "Авто-диапазон",
                     icon = icon("magnifying-glass-arrow-right"),
                     class = "btn-secondary")
      ),
      plotOutput("plot_flows_day", height = "320px"),
      tags$small(textOutput("flows_range_info"), style = "color: #7f8c8d;")
    ),

    layout_columns(
      col_widths = c(6, 6),
      card(
        card_header("Последние analysis_runs"),
        DTOutput("tbl_recent_runs")
      ),
      card(
        card_header("Последние etl_objects"),
        DTOutput("tbl_recent_objects")
      )
    )
  ),

  nav_panel(
    title = "Сработки",
    icon = icon("triangle-exclamation"),

    layout_sidebar(
      sidebar = sidebar(
        title = "Фильтры",
        width = 280,
        checkboxGroupInput(
          "f_detector_type",
          "Тип детектора",
          choices = c("signature", "behavioral"),
          selected = c("signature", "behavioral")
        ),
        checkboxGroupInput(
          "f_severity",
          "Severity",
          choices = c("critical", "high", "medium", "low"),
          selected = c("critical", "high", "medium", "low")
        ),
        textInput("f_src_ip", "src_ip"),
        textInput("f_dst_ip", "dst_ip"),
        checkboxGroupInput(
          "f_source_format",
          "Формат источника",
          choices = character(),
          selected = character()
        ),
        checkboxGroupInput(
          "f_source_dataset",
          "Датасет-источник",
          choices = character(),
          selected = character()
        ),
        textInput("f_source_key", "source_key / file"),
        dateRangeInput(
          "f_date_range",
          "Период (created_at)",
          start = NULL,
          end = NULL,
          startview = "month",
          weekstart = 1,
          separator = " — "
        ),
        selectInput("f_time_from", "Время с", choices = build_time_choices(), selected = "00:00"),
        selectInput("f_time_to", "Время по", choices = build_time_choices(), selected = "23:59"),
        numericInput("f_limit", "Лимит строк", value = 1000, min = 50, max = 50000, step = 50),
        actionButton("f_refresh", "Обновить", icon = icon("arrows-rotate"), class = "btn-primary w-100")
      ),

      card(
        card_header(textOutput("detections_summary")),
        DTOutput("tbl_detections")
      )
    )
  ),

  nav_panel(
    title = "Детализация",
    icon = icon("magnifying-glass"),

    layout_columns(
      col_widths = c(4, 8),
      card(
        card_header("Выбор сработки"),
        p(em("Кликни строку на вкладке «Сработки» — детали загрузятся автоматически и сюда переключит.")),
        textInput("dd_detection_id", "detection_id", placeholder = "или вставь detection_id вручную"),
        hr(),
        uiOutput("dd_summary")
      ),
      card(
        card_header("TCP-сессии по сработке"),
        DTOutput("tbl_dd_sessions")
      )
    ),

    card(
      card_header("Временная шкала сессий (Gantt)"),
      plotOutput("plot_dd_gantt", height = "320px")
    ),

    card(
      card_header("Сырая запись из network_flows (по выбранному event_id)"),
      verbatimTextOutput("dd_raw_flow")
    )
  ),

  nav_panel(
    title = "Трафик",
    icon = icon("chart-line"),

    layout_columns(
      col_widths = c(3, 3, 3, 3),
      value_box(
        title = "Уникальных src IP",
        value = textOutput("kpi_uniq_src"),
        showcase = icon("user")
      ),
      value_box(
        title = "Уникальных dst IP",
        value = textOutput("kpi_uniq_dst"),
        showcase = icon("server")
      ),
      value_box(
        title = "Суммарный объём",
        value = textOutput("kpi_total_bytes"),
        showcase = icon("database")
      ),
      value_box(
        title = "Суммарных пакетов",
        value = textOutput("kpi_total_packets"),
        showcase = icon("paper-plane")
      )
    ),

    card(
      card_header("Всплески трафика (потоки + байты)"),
      layout_columns(
        col_widths = c(3, 3, 3, 3),
        sliderInput("traffic_bucket_min", "Размер бакета (мин)", min = 1, max = 60, value = 5, step = 1),
        dateRangeInput("traffic_date_range", "Диапазон дат",
                       start = NULL, end = NULL,
                       startview = "month", weekstart = 1, separator = " — "),
        selectInput("traffic_time_from", "Время с", choices = build_time_choices(), selected = "00:00"),
        selectInput("traffic_time_to", "Время по", choices = build_time_choices(), selected = "23:59")
      ),
      actionButton("traffic_reset", "Авто-диапазон", icon = icon("magnifying-glass-arrow-right"), class = "btn-secondary"),
      plotOutput("plot_traffic_timeline", height = "320px")
    ),

    card(
      card_header("Всплески сработок по severity"),
      plotOutput("plot_detections_timeline", height = "260px")
    ),

    layout_columns(
      col_widths = c(6, 6),
      card(
        card_header("Top src_ip по числу flow"),
        plotOutput("plot_top_src", height = "320px"),
        DTOutput("tbl_top_src")
      ),
      card(
        card_header("Top dst_ip по числу flow"),
        plotOutput("plot_top_dst", height = "320px"),
        DTOutput("tbl_top_dst")
      )
    ),

    card(
      card_header("Heatmap взаимодействий src_ip × dst_ip (по числу flow)"),
      plotOutput("plot_ip_heatmap", height = "480px")
    )
  ),

  nav_panel(
    title = "Действия",
    icon = icon("play"),

    layout_columns(
      col_widths = c(6, 6),
      card(
        card_header("Запуск ETL"),
        p("Запускает docker-сервис ", code("etl-init"), ". Прогресс смотрите в журнале ", code("etl_objects"), " на вкладке «Обзор» и в логе ниже."),
        actionButton("run_etl", "Запустить ETL", icon = icon("play"), class = "btn-success"),
        hr(),
        uiOutput("etl_status_ui"),
        verbatimTextOutput("etl_log")
      ),
      card(
        card_header("Запуск анализа"),
        p("Запускает docker-сервис ", code("analysis"), ". Прогресс смотрите в журнале ", code("analysis_runs"), " на вкладке «Обзор» и в логе ниже."),
        actionButton("run_analysis", "Запустить анализ", icon = icon("brain"), class = "btn-success"),
        hr(),
        uiOutput("analysis_status_ui"),
        verbatimTextOutput("analysis_log")
      )
    )
  ),

  nav_spacer(),
  nav_item(
    span(
      style = "color: rgba(255,255,255,0.7); font-size: 0.85rem;",
      textOutput("ch_status", inline = TRUE)
    )
  )
)

server <- function(input, output, session) {

  auto_tick <- reactiveTimer(10000)
  selected_event_id <- reactiveVal(NULL)

  output$ch_status <- renderText({
    auto_tick()
    ok <- !is.null(with_conn(function(conn) DBI::dbGetQuery(conn, "SELECT 1")))
    if (ok) "ClickHouse: online" else "ClickHouse: offline"
  })

  counters <- reactive({
    auto_tick()
    fetch_overview_counters()
  })

  output$kpi_flows <- renderText(format_int(counters()$flows_total))
  output$kpi_objects <- renderText(format_int(counters()$objects_total))
  output$kpi_runs <- renderText(format_int(counters()$runs_total))
  output$kpi_detections <- renderText(format_int(counters()$detections_total))
  output$kpi_signature <- renderText(format_int(counters()$signature_total))
  output$kpi_behavioral <- renderText(format_int(counters()$behavioral_total))

  output$plot_severity <- renderPlot({
    auto_tick()
    df <- fetch_severity_breakdown()
    if (is.null(df) || nrow(df) == 0) {
      render_empty_plot("Нет данных")
      return()
    }
    df$detections <- as.numeric(df$detections)
    df <- df[order(df$detections, decreasing = TRUE), , drop = FALSE]
    colors <- ifelse(df$severity %in% c("critical", "high"), "#e74c3c",
              ifelse(df$severity == "medium", "#f39c12",
              ifelse(df$severity == "low", "#3498db", "#95a5a6")))

    set_plot_par(mar = c(4, 5, 2, 1))
    counts_sqrt <- sqrt(df$detections)
    ymax <- max(counts_sqrt) * 1.18
    bp <- barplot(
      counts_sqrt,
      names.arg = df$severity,
      col = colors,
      border = NA,
      las = 1,
      main = "",
      ylab = "Число сработок (√-шкала)",
      ylim = c(0, ymax),
      yaxt = "n"
    )
    nice_ticks <- pretty(c(0, max(df$detections)), n = 6)
    axis(2, at = sqrt(nice_ticks), labels = format(nice_ticks, big.mark = " "), las = 1)
    text(bp, counts_sqrt, labels = format(df$detections, big.mark = " "),
         pos = 3, cex = 0.95, font = 2)
  })

  flow_time_range <- reactive({
    auto_tick()
    fetch_flow_time_range()
  })

  detection_time_range <- reactive({
    auto_tick()
    fetch_detection_time_range()
  })

  observe({
    rng <- flow_time_range()
    if (is.null(rng) || nrow(rng) == 0) return()
    min_ts <- as.Date(as.POSIXct(rng$min_ts[[1]], tz = "UTC"))
    max_ts <- as.Date(as.POSIXct(rng$max_ts[[1]], tz = "UTC"))
    if (!is.na(min_ts) && !is.na(max_ts) &&
        (is.null(input$flows_date_range) || is.na(input$flows_date_range[[1]]))) {
      updateDateRangeInput(session, "flows_date_range", start = min_ts, end = max_ts)
    }
    if (!is.na(min_ts) && !is.na(max_ts) &&
        (is.null(input$traffic_date_range) || is.na(input$traffic_date_range[[1]]))) {
      updateDateRangeInput(session, "traffic_date_range", start = min_ts, end = max_ts)
      updateSelectInput(session, "traffic_time_from", selected = split_time_value(rng$min_ts[[1]], "00:00"))
      updateSelectInput(session, "traffic_time_to", selected = split_time_value(rng$max_ts[[1]], "23:59"))
    }
  })

  observeEvent(input$flows_reset, {
    rng <- flow_time_range()
    if (is.null(rng) || nrow(rng) == 0) return()
    min_ts <- as.Date(as.POSIXct(rng$min_ts[[1]], tz = "UTC"))
    max_ts <- as.Date(as.POSIXct(rng$max_ts[[1]], tz = "UTC"))
    updateDateRangeInput(session, "flows_date_range", start = min_ts, end = max_ts)
  })

  observeEvent(input$traffic_reset, {
    rng <- flow_time_range()
    if (is.null(rng) || nrow(rng) == 0) return()
    updateDateRangeInput(
      session,
      "traffic_date_range",
      start = as.Date(as.POSIXct(rng$min_ts[[1]], tz = "UTC")),
      end = as.Date(as.POSIXct(rng$max_ts[[1]], tz = "UTC"))
    )
    updateSelectInput(session, "traffic_time_from", selected = split_time_value(rng$min_ts[[1]], "00:00"))
    updateSelectInput(session, "traffic_time_to", selected = split_time_value(rng$max_ts[[1]], "23:59"))
  })

  observe({
    rng <- detection_time_range()
    if (is.null(rng) || nrow(rng) == 0) return()
    min_ts <- as.Date(as.POSIXct(rng$min_ts[[1]], tz = "UTC"))
    max_ts <- as.Date(as.POSIXct(rng$max_ts[[1]], tz = "UTC"))
    if (!is.na(min_ts) && !is.na(max_ts) &&
        (is.null(input$f_date_range) || is.na(input$f_date_range[[1]]))) {
      updateDateRangeInput(session, "f_date_range", start = min_ts, end = max_ts)
      updateSelectInput(session, "f_time_from", selected = split_time_value(rng$min_ts[[1]], "00:00"))
      updateSelectInput(session, "f_time_to", selected = split_time_value(rng$max_ts[[1]], "23:59"))
    }
  })

  output$flows_range_info <- renderText({
    rng <- flow_time_range()
    if (is.null(rng) || nrow(rng) == 0) return("")
    sprintf("Данные в БД: %s — %s",
            format(as.POSIXct(rng$min_ts[[1]], tz = "UTC"), "%Y-%m-%d"),
            format(as.POSIXct(rng$max_ts[[1]], tz = "UTC"), "%Y-%m-%d"))
  })

  output$plot_flows_day <- renderPlot({
    auto_tick()
    granularity <- input$flows_granularity %||% "day"
    date_from <- if (!is.null(input$flows_date_range)) input$flows_date_range[[1]] else NULL
    date_to <- if (!is.null(input$flows_date_range)) input$flows_date_range[[2]] else NULL

    df <- fetch_flows_by_bucket(granularity = granularity,
                                 date_from = date_from, date_to = date_to)
    if (is.null(df) || nrow(df) == 0) {
      render_empty_plot("Нет данных в выбранном диапазоне"); return()
    }

    df$bucket <- as.Date(df$bucket)
    df$flows <- as.numeric(df$flows)
    df <- df[order(df$bucket), , drop = FALSE]

    set_plot_par(mar = c(5, 5.5, 1, 1))
    label_format <- switch(granularity,
      "month" = "%Y-%m",
      "week" = "%Y-%m-%d",
      "%Y-%m-%d"
    )
    bp <- barplot(df$flows,
                  names.arg = format(df$bucket, label_format),
                  col = "#2c3e50", border = NA,
                  las = 2, cex.names = 0.75,
                  ylab = "Потоки", main = "",
                  yaxt = "n")
    nice_ticks <- pretty(c(0, max(df$flows, na.rm = TRUE)), n = 6)
    axis(2, at = nice_ticks, labels = format(nice_ticks, big.mark = " "), las = 1)
    grid(nx = NA, ny = NULL, col = "#ecf0f1")
  })

  output$tbl_recent_runs <- renderDT({
    auto_tick()
    df <- fetch_recent_runs(limit = 15L)
    if (is.null(df) || nrow(df) == 0) {
      return(datatable(data.frame(message = "нет данных"), options = list(dom = "t")))
    }
    df$status <- vapply(df$status, status_badge, character(1))
    datatable(
      df,
      escape = FALSE,
      rownames = FALSE,
      options = list(pageLength = 5, dom = "tip", scrollX = TRUE)
    )
  })

  output$tbl_recent_objects <- renderDT({
    auto_tick()
    df <- fetch_recent_etl_objects(limit = 30L)
    if (is.null(df) || nrow(df) == 0) {
      return(datatable(data.frame(message = "нет данных"), options = list(dom = "t")))
    }
    df$object_size <- vapply(df$object_size, format_bytes, character(1))
    df$status <- vapply(df$status, status_badge, character(1))
    datatable(
      df,
      escape = FALSE,
      rownames = FALSE,
      options = list(pageLength = 5, dom = "tip", scrollX = TRUE)
    )
  })

  observe({
    auto_tick()
    options <- fetch_detection_filter_options()

    source_formats <- sort(unique(as.character(options$source_formats$source_format %||% character())))
    source_formats <- source_formats[nzchar(source_formats)]
    updateCheckboxGroupInput(
      session,
      "f_source_format",
      choices = source_formats,
      selected = intersect(input$f_source_format %||% source_formats, source_formats)
    )

    source_datasets <- sort(unique(as.character(options$source_datasets$source_dataset %||% character())))
    source_datasets <- source_datasets[nzchar(source_datasets)]
    updateCheckboxGroupInput(
      session,
      "f_source_dataset",
      choices = source_datasets,
      selected = intersect(input$f_source_dataset %||% source_datasets, source_datasets)
    )
  })

  detections_data <- eventReactive(
    list(input$f_refresh, auto_tick()),
    {
      isolate({
        fetch_detections_filtered(
          detector_types = input$f_detector_type,
          severities = input$f_severity,
          src_ip = input$f_src_ip,
          dst_ip = input$f_dst_ip,
          source_formats = input$f_source_format,
          source_datasets = input$f_source_dataset,
          source_key_pattern = input$f_source_key,
          date_from = combine_date_time(safe_range_value(input$f_date_range, 1), input$f_time_from, end_default = FALSE),
          date_to = combine_date_time(safe_range_value(input$f_date_range, 2), input$f_time_to, end_default = TRUE),
          limit = input$f_limit %||% 1000L
        )
      })
    },
    ignoreNULL = FALSE
  )

  output$detections_summary <- renderText({
    df <- detections_data()
    if (is.null(df)) return("нет соединения с ClickHouse")
    sprintf("Найдено %s сработок", format_int(nrow(df)))
  })

  output$tbl_detections <- renderDT({
    df <- detections_data()
    if (is.null(df) || nrow(df) == 0) {
      return(datatable(data.frame(message = "нет данных"), options = list(dom = "t")))
    }
    df$severity <- vapply(df$severity, severity_badge, character(1))
    df$confidence_score <- ifelse(is.na(df$confidence_score), "",
                                  sprintf("%.2f", as.numeric(df$confidence_score)))
    datatable(
      df,
      escape = FALSE,
      rownames = FALSE,
      selection = "single",
      filter = "top",
      options = list(
        pageLength = 25,
        scrollX = TRUE,
        order = list(list(17, "desc")),
        columnDefs = list(list(width = "150px", targets = 0))
      )
    )
  })

  observeEvent(input$tbl_detections_rows_selected, {
    df <- detections_data()
    sel <- input$tbl_detections_rows_selected
    if (length(sel) == 1 && !is.null(df) && nrow(df) >= sel) {
      updateTextInput(session, "dd_detection_id", value = df$detection_id[[sel]])
      bslib::nav_select(id = "main_nav", selected = "Детализация", session = session)
    }
  })

  detection_detail <- reactive({
    req(nzchar(input$dd_detection_id))
    list(
      detection = fetch_detection_by_id(input$dd_detection_id),
      events = fetch_detection_events(input$dd_detection_id),
      sessions = fetch_sessions_for_detection(input$dd_detection_id)
    )
  })

  output$dd_summary <- renderUI({
    detail <- tryCatch(detection_detail(), error = function(e) NULL)
    if (is.null(detail) || is.null(detail$detection) || nrow(detail$detection) == 0) {
      return(p(em("Введите detection_id и нажмите «Загрузить».")))
    }

    row <- detail$detection[1, , drop = FALSE]
    tags$dl(
      class = "row",
      tags$dt(class = "col-sm-5", "rule_name"),
      tags$dd(class = "col-sm-7", row$rule_name),
      tags$dt(class = "col-sm-5", "rule_id"),
      tags$dd(class = "col-sm-7", code(row$rule_id)),
      tags$dt(class = "col-sm-5", "severity"),
      tags$dd(class = "col-sm-7", HTML(severity_badge(row$severity))),
      tags$dt(class = "col-sm-5", "detector"),
      tags$dd(class = "col-sm-7", sprintf("%s / %s", row$detector_type, row$detector_name)),
      tags$dt(class = "col-sm-5", "entity"),
      tags$dd(class = "col-sm-7", code(row$entity_value)),
      tags$dt(class = "col-sm-5", "first / last seen"),
      tags$dd(class = "col-sm-7", sprintf("%s — %s", row$first_seen, row$last_seen)),
      tags$dt(class = "col-sm-5", "flow_count"),
      tags$dd(class = "col-sm-7", format_int(row$flow_count)),
      tags$dt(class = "col-sm-5", "confidence"),
      tags$dd(class = "col-sm-7", sprintf("%.2f", as.numeric(row$confidence_score %||% 0))),
      tags$dt(class = "col-sm-5", "source_format"),
      tags$dd(class = "col-sm-7", code(row$source_format %||% "")),
      tags$dt(class = "col-sm-5", "source_dataset"),
      tags$dd(class = "col-sm-7", row$source_dataset %||% ""),
      tags$dt(class = "col-sm-5", "source_key"),
      tags$dd(class = "col-sm-7", code(row$source_key %||% "")),
      tags$dt(class = "col-sm-5", "description"),
      tags$dd(class = "col-sm-7", row$description),
      tags$dt(class = "col-sm-5", "tags"),
      tags$dd(class = "col-sm-7", code(row$tags_json)),
      tags$dt(class = "col-sm-5", "detail"),
      tags$dd(class = "col-sm-7", tags$pre(row$detail_json))
    )
  })

  output$tbl_dd_sessions <- renderDT({
    detail <- tryCatch(detection_detail(), error = function(e) NULL)
    if (is.null(detail) || is.null(detail$sessions) || nrow(detail$sessions) == 0) {
      return(datatable(data.frame(message = "нет сессий"), options = list(dom = "t")))
    }

    df <- detail$sessions
    df$bytes_total <- vapply(df$bytes_total, format_bytes, character(1))
    df$bytes_src <- vapply(df$bytes_src, format_bytes, character(1))
    df$bytes_dst <- vapply(df$bytes_dst, format_bytes, character(1))
    df$duration_sec <- ifelse(is.na(df$duration_sec), "",
                              sprintf("%.2f s", as.numeric(df$duration_sec)))

    datatable(
      df,
      rownames = FALSE,
      selection = "single",
      options = list(pageLength = 12, scrollX = TRUE)
    )
  })

  output$plot_dd_gantt <- renderPlot({
    detail <- tryCatch(detection_detail(), error = function(e) NULL)
    if (is.null(detail) || is.null(detail$sessions) || nrow(detail$sessions) == 0) {
      render_empty_plot("Нет сессий"); return()
    }

    df <- detail$sessions
    df$flow_start <- as.POSIXct(df$flow_start, tz = "UTC")
    df$flow_end <- as.POSIXct(df$flow_end, tz = "UTC")
    bad_end <- is.na(df$flow_end) | df$flow_end <= df$flow_start
    df$flow_end[bad_end] <- df$flow_start[bad_end] + 1
    df <- df[order(df$flow_start), , drop = FALSE]
    df <- utils::head(df, 60)

    color_for_state <- function(state) {
      ifelse(state %in% c("SF", "S1", "S2", "S3"), "#27ae60",
      ifelse(state %in% c("REJ", "RSTO", "RSTR", "S0", "SH"), "#e74c3c",
      ifelse(state == "OTH", "#7f8c8d", "#3498db")))
    }

    set_plot_par(mar = c(4, 14, 1, 1))
    y_positions <- seq_len(nrow(df))
    labels <- sprintf("%s:%s→%s:%s",
                      substr(df$src_ip, 1, 15),
                      ifelse(is.na(df$src_port), "?", df$src_port),
                      substr(df$dst_ip, 1, 15),
                      ifelse(is.na(df$dst_port), "?", df$dst_port))

    plot(
      range(c(df$flow_start, df$flow_end)),
      c(0.5, nrow(df) + 0.5),
      type = "n", yaxt = "n", xlab = "Время", ylab = "",
      main = ""
    )
    axis(2, at = y_positions, labels = labels, las = 1, cex.axis = 0.7)
    grid(col = "#ecf0f1", lty = 1)
    segments(
      x0 = df$flow_start, x1 = df$flow_end,
      y0 = y_positions, y1 = y_positions,
      col = color_for_state(df$flow_state),
      lwd = 6, lend = 1
    )
    legend("topright", inset = c(0, -0.02),
           legend = c("SF/S1-S3", "REJ/RST/S0/SH", "OTH", "other"),
           col = c("#27ae60", "#e74c3c", "#7f8c8d", "#3498db"),
           lwd = 4, bty = "n", cex = 0.75, horiz = TRUE, xpd = TRUE)
  })

  observeEvent(input$tbl_dd_sessions_rows_selected, {
    detail <- tryCatch(detection_detail(), error = function(e) NULL)
    sel <- input$tbl_dd_sessions_rows_selected
    if (length(sel) == 1 && !is.null(detail) && !is.null(detail$sessions) && nrow(detail$sessions) >= sel) {
      selected_event_id(detail$sessions$event_id[[sel]])
    }
  })

  output$dd_raw_flow <- renderPrint({
    eid <- selected_event_id()
    if (is.null(eid) || !nzchar(eid)) {
      cat("Выберите строку в таблице связанных событий.")
      return()
    }
    flow <- fetch_flow_by_event_id(eid)
    if (is.null(flow) || nrow(flow) == 0) {
      cat(sprintf("Строка не найдена для event_id = %s", eid))
      return()
    }
    str(as.list(flow[1, , drop = FALSE]))
  })

  observeEvent(input$run_etl, {
    cat(sprintf("[%s] >>> run_etl observer fired (n=%s)\n",
                format(Sys.time(), "%H:%M:%S"), input$run_etl))
    flush(stdout())
    res <- tryCatch(start_compose_job("etl-init"),
                    error = function(e) list(ok = FALSE, message = sprintf("Error: %s", e$message)))
    cat(sprintf("[%s] >>> run_etl result ok=%s msg=%s\n",
                format(Sys.time(), "%H:%M:%S"), res$ok, res$message))
    flush(stdout())
    showNotification(res$message, type = if (isTRUE(res$ok)) "message" else "warning", duration = 8)
  }, ignoreInit = TRUE)

  observeEvent(input$run_analysis, {
    cat(sprintf("[%s] >>> run_analysis observer fired (n=%s)\n",
                format(Sys.time(), "%H:%M:%S"), input$run_analysis))
    flush(stdout())
    res <- tryCatch(start_compose_job("analysis"),
                    error = function(e) list(ok = FALSE, message = sprintf("Error: %s", e$message)))
    cat(sprintf("[%s] >>> run_analysis result ok=%s msg=%s\n",
                format(Sys.time(), "%H:%M:%S"), res$ok, res$message))
    flush(stdout())
    showNotification(res$message, type = if (isTRUE(res$ok)) "message" else "warning", duration = 8)
  }, ignoreInit = TRUE)

  render_status_block <- function(service) {
    status <- job_status(service)
    started <- if (is.na(status$started_at)) "—" else format(status$started_at, "%Y-%m-%d %H:%M:%S")
    tagList(
      HTML(sprintf("Статус: %s", status_badge(status$state))),
      tags$br(),
      tags$small(sprintf("Запущен: %s", started)),
      if (!is.na(status$exit_code)) tagList(tags$br(), tags$small(sprintf("exit code: %s", status$exit_code)))
    )
  }

  output$etl_status_ui <- renderUI({
    auto_tick()
    render_status_block("etl-init")
  })

  output$analysis_status_ui <- renderUI({
    auto_tick()
    render_status_block("analysis")
  })

  output$etl_log <- renderText({
    auto_tick()
    log <- tail_job_log("etl-init", 50L)
    if (!nzchar(log)) "лог пуст" else log
  })

  output$analysis_log <- renderText({
    auto_tick()
    log <- tail_job_log("analysis", 50L)
    if (!nzchar(log)) "лог пуст" else log
  })

  # ---- вкладка «Трафик» ----

  traffic_bucket_seconds <- reactive({
    bucket_min <- input$traffic_bucket_min %||% 5L
    as.integer(bucket_min) * 60L
  })

  traffic_window <- reactive({
    list(
      date_from = combine_date_time(safe_range_value(input$traffic_date_range, 1), input$traffic_time_from, end_default = FALSE),
      date_to = combine_date_time(safe_range_value(input$traffic_date_range, 2), input$traffic_time_to, end_default = TRUE)
    )
  })

  traffic_timeline_data <- reactive({
    auto_tick()
    rng <- traffic_window()
    fetch_traffic_timeline(traffic_bucket_seconds(), date_from = rng$date_from, date_to = rng$date_to)
  })

  detections_timeline_data <- reactive({
    auto_tick()
    rng <- traffic_window()
    fetch_traffic_timeline_by_severity(traffic_bucket_seconds(), date_from = rng$date_from, date_to = rng$date_to)
  })

  top_src_data <- reactive({
    auto_tick()
    rng <- traffic_window()
    fetch_top_src_ips(limit = 15L, date_from = rng$date_from, date_to = rng$date_to)
  })

  top_dst_data <- reactive({
    auto_tick()
    rng <- traffic_window()
    fetch_top_dst_ips(limit = 15L, date_from = rng$date_from, date_to = rng$date_to)
  })

  ip_pair_data <- reactive({
    auto_tick()
    rng <- traffic_window()
    fetch_ip_pair_matrix(src_limit = 15L, dst_limit = 15L, date_from = rng$date_from, date_to = rng$date_to)
  })

  output$kpi_uniq_src <- renderText({
    rng <- traffic_window()
    conditions <- c("src_ip != ''")
    if (!is.null(rng$date_from)) conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format(rng$date_from, "%Y-%m-%d %H:%M:%S"))))
    if (!is.null(rng$date_to)) conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format(rng$date_to, "%Y-%m-%d %H:%M:%S"))))
    res <- safe_query(sprintf("SELECT uniqExact(src_ip) AS c FROM network_flows WHERE %s",
                              paste(conditions, collapse = " AND ")),
                      data.frame(c = 0))
    format_int(as.numeric(res$c[[1]]))
  })

  output$kpi_uniq_dst <- renderText({
    rng <- traffic_window()
    conditions <- c("dst_ip != ''")
    if (!is.null(rng$date_from)) conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format(rng$date_from, "%Y-%m-%d %H:%M:%S"))))
    if (!is.null(rng$date_to)) conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format(rng$date_to, "%Y-%m-%d %H:%M:%S"))))
    res <- safe_query(sprintf("SELECT uniqExact(dst_ip) AS c FROM network_flows WHERE %s",
                              paste(conditions, collapse = " AND ")),
                      data.frame(c = 0))
    format_int(as.numeric(res$c[[1]]))
  })

  output$kpi_total_bytes <- renderText({
    rng <- traffic_window()
    conditions <- c("1 = 1")
    if (!is.null(rng$date_from)) conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format(rng$date_from, "%Y-%m-%d %H:%M:%S"))))
    if (!is.null(rng$date_to)) conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format(rng$date_to, "%Y-%m-%d %H:%M:%S"))))
    res <- safe_query(sprintf("SELECT sum(toFloat64(ifNull(bytes_total, 0))) AS c FROM network_flows WHERE %s",
                              paste(conditions, collapse = " AND ")),
                      data.frame(c = 0))
    format_bytes(as.numeric(res$c[[1]]))
  })

  output$kpi_total_packets <- renderText({
    rng <- traffic_window()
    conditions <- c("1 = 1")
    if (!is.null(rng$date_from)) conditions <- c(conditions, sprintf("flow_start >= toDateTime(%s)", quote_sql(format(rng$date_from, "%Y-%m-%d %H:%M:%S"))))
    if (!is.null(rng$date_to)) conditions <- c(conditions, sprintf("flow_start <= toDateTime(%s)", quote_sql(format(rng$date_to, "%Y-%m-%d %H:%M:%S"))))
    res <- safe_query(sprintf("SELECT sum(toFloat64(ifNull(packets_total, 0))) AS c FROM network_flows WHERE %s",
                              paste(conditions, collapse = " AND ")),
                      data.frame(c = 0))
    format_int(as.numeric(res$c[[1]]))
  })

  output$plot_traffic_timeline <- renderPlot({
    df <- traffic_timeline_data()
    if (is.null(df) || nrow(df) == 0) { render_empty_plot("Нет данных"); return() }
    df$bucket <- as.POSIXct(df$bucket, tz = "UTC")
    df$flows <- as.numeric(df$flows)
    df$bytes_sum <- as.numeric(df$bytes_sum)
    df <- df[order(df$bucket), , drop = FALSE]

    set_plot_par(mar = c(4, 4.5, 1, 4.5))
    plot(df$bucket, df$flows, type = "l", lwd = 2, col = "#2c3e50",
         xlab = "Время", ylab = "Потоки", main = "")
    points(df$bucket, df$flows, pch = 19, col = "#2c3e50", cex = 0.5)
    grid(col = "#ecf0f1")

    par(new = TRUE)
    plot(df$bucket, df$bytes_sum, type = "l", lwd = 1.5, col = "#e67e22",
         lty = 2, axes = FALSE, xlab = "", ylab = "")
    axis(4, col.axis = "#e67e22")
    mtext("Байт", side = 4, line = 3, col = "#e67e22")

    legend("topleft", legend = c("Потоки (лев. ось)", "Байт (прав. ось)"),
           col = c("#2c3e50", "#e67e22"), lwd = c(2, 1.5), lty = c(1, 2),
           bty = "n", cex = 0.85)
  })

  output$plot_detections_timeline <- renderPlot({
    df <- detections_timeline_data()
    if (is.null(df) || nrow(df) == 0) { render_empty_plot("Нет сработок"); return() }
    df$bucket <- as.POSIXct(df$bucket, tz = "UTC")
    df$detections <- as.numeric(df$detections)
    df <- df[order(df$bucket), , drop = FALSE]

    severities <- unique(df$severity)
    palette_map <- c(critical = "#c0392b", high = "#e74c3c",
                     medium = "#f39c12", low = "#3498db")

    set_plot_par(mar = c(4, 4.5, 1, 1))
    plot(range(df$bucket), c(0, max(df$detections, na.rm = TRUE) * 1.05),
         type = "n", xlab = "Время", ylab = "Сработок")
    grid(col = "#ecf0f1")
    for (sev in severities) {
      sub <- df[df$severity == sev, , drop = FALSE]
      sub <- sub[order(sub$bucket), , drop = FALSE]
      lines(sub$bucket, sub$detections, lwd = 2,
            col = palette_map[[sev]] %||% "#7f8c8d")
      points(sub$bucket, sub$detections, pch = 19, cex = 0.55,
             col = palette_map[[sev]] %||% "#7f8c8d")
    }
    legend("topleft", legend = severities,
           col = vapply(severities, function(s) palette_map[[s]] %||% "#7f8c8d", character(1)),
           lwd = 2, bty = "n", cex = 0.85)
  })

  render_top_ips_bar <- function(df, label_col) {
    if (is.null(df) || nrow(df) == 0) { render_empty_plot("Нет данных"); return() }
    df$flows <- as.numeric(df$flows)
    df <- df[order(df$flows), , drop = FALSE]
    set_plot_par(mar = c(4, 13, 1, 1))
    barplot(df$flows, names.arg = df[[label_col]], horiz = TRUE, las = 1,
            col = "#2c3e50", border = NA, cex.names = 0.78,
            xlab = "Число flow", main = "")
  }

  output$plot_top_src <- renderPlot({ render_top_ips_bar(top_src_data(), "src_ip") })
  output$plot_top_dst <- renderPlot({ render_top_ips_bar(top_dst_data(), "dst_ip") })

  output$tbl_top_src <- renderDT({
    df <- top_src_data()
    if (is.null(df) || nrow(df) == 0) {
      return(datatable(data.frame(message = "нет данных"), options = list(dom = "t")))
    }
    df$bytes_sum <- vapply(df$bytes_sum, format_bytes, character(1))
    datatable(df, rownames = FALSE, options = list(pageLength = 10, dom = "tp", scrollX = TRUE))
  })

  output$tbl_top_dst <- renderDT({
    df <- top_dst_data()
    if (is.null(df) || nrow(df) == 0) {
      return(datatable(data.frame(message = "нет данных"), options = list(dom = "t")))
    }
    df$bytes_sum <- vapply(df$bytes_sum, format_bytes, character(1))
    datatable(df, rownames = FALSE, options = list(pageLength = 10, dom = "tp", scrollX = TRUE))
  })

  output$plot_ip_heatmap <- renderPlot({
    df <- ip_pair_data()
    if (is.null(df) || nrow(df) == 0) { render_empty_plot("Нет пар IP"); return() }

    df$flows <- as.numeric(df$flows)
    src_ips <- unique(df$src_ip)
    dst_ips <- unique(df$dst_ip)
    mat <- matrix(0, nrow = length(src_ips), ncol = length(dst_ips),
                  dimnames = list(src_ips, dst_ips))
    for (i in seq_len(nrow(df))) {
      mat[df$src_ip[i], df$dst_ip[i]] <- df$flows[i]
    }

    log_mat <- log1p(mat)

    set_plot_par(mar = c(10, 12, 1, 1))
    palette_heat <- colorRampPalette(c("#ecf0f1", "#3498db", "#9b59b6", "#e74c3c"))(64)
    image(seq_len(ncol(log_mat)), seq_len(nrow(log_mat)), t(log_mat[nrow(log_mat):1, , drop = FALSE]),
          col = palette_heat, xaxt = "n", yaxt = "n", xlab = "", ylab = "")
    axis(1, at = seq_len(ncol(log_mat)), labels = dst_ips, las = 2, cex.axis = 0.7)
    axis(2, at = seq_len(nrow(log_mat)), labels = rev(src_ips), las = 1, cex.axis = 0.7)
    mtext("dst_ip", side = 1, line = 8)
    mtext("src_ip", side = 2, line = 10)
  })
}

shinyApp(ui, server)
