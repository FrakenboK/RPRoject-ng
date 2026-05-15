# RPRoject-ng

`RPRoject-ng` — IDC-система на `R`.

Сейчас в репозитории реализованы три части:

- ETL-модуль
- модуль анализа данных
- веб-интерфейс на `R Shiny`

Все части запускаются из одного корневого `docker-compose.yml`.

## Состав проекта

- `clickhouse` — хранилище нормализованных потоков и сработок
- `etl-init` — одноразовый ETL-контейнер
- `analysis` — одноразовый контейнер анализа данных
- `ui` — Shiny-интерфейс с обзором, фильтрами по сработкам, drill-down и запуском ETL/analysis

## Запуск

```bash
cp .env.example .env
docker compose up --build etl-init
docker compose up --build analysis
docker compose up --build ui
```

UI доступен на `http://localhost:3838` (порт настраивается переменной `UI_PORT`).
`ClickHouse` наружу не публикуется и доступен только внутри docker-сети.

## Что уже сделано

### ETL

- листинг всех объектов в `S3` по префиксу без хардкода имён
- загрузка всех найденных файлов по `RO`-учётке
- обработка `pcap`, `pcapng`, `binetflow`, `csv`, `zip`
- разбор `pcap` / `pcapng` через `Zeek`
- приведение всех источников к единой таблице `network_flows`
- запись журнала обработки в `etl_objects`
- формирование глобально уникального `event_id` для каждой flow-записи, включая записи из архивов

### Анализ

- сигнатурный анализ по Sigma-подобным YAML-правилам
- поведенческий анализ по унифицированным TCP-потокам
- консервативные детекторы с ужатыми условиями для снижения ложных срабатываний
- запись сработок и привязки к исходным flow-записям в `ClickHouse`
- отдельный контейнер `analysis`

## Формирование TCP-сессий

- `pcap` / `pcapng` передаются в `Zeek`
- ETL читает `conn.log`
- одна запись `conn.log` становится одной записью в `network_flows`
- `flow_start` берётся из `ts`
- `flow_end` вычисляется как `flow_start + duration_sec`
- `Kyoto 2006+`, `UNSW-NB15` и `BinetFlow` загружаются как уже готовые flow/session записи

## Поддержанные источники

- `UNSW-NB15`
- `Stratosphere IPS`
- `Kyoto 2006+`

### Kyoto 2006+

Для `Kyoto 2006+` ETL работает с `zip`-архивами. Внутри архивов лежат:

- каталоги по году и месяцу
- дневные `.txt`-файлы

Файлы `.txt` содержат tab-separated flow/session записи, а не `pcap`.

## Анализ данных

### Сигнатурный анализ

- правила лежат в `r-analysis/rules/signature`
- правила описываются в Sigma-подобном YAML-формате
- матчинг выполняется по unified flow-полям из `network_flows`

### Поведенческий анализ

Модуль строит агрегаты:

- по `src_ip` и временным окнам `5m`
- по парам `src_ip -> dst_ip:dst_port`

Дальше используются:

- `DBSCAN`
- `LOF`
- `Isolation Forest`

Сейчас реализованы детекторы:

- vertical port scan
- horizontal host scan
- HTTP brute force / directory fuzzing candidate
- SMB brute force candidate
- long-lived C2 session candidate

## Таблицы ClickHouse

### ETL

- `network_flows` — единая таблица потоков
- `etl_objects` — журнал обработки объектов из `S3`

### Analysis

- `analysis_runs` — журнал запусков анализа
- `analysis_detections` — summary-сработки
- `analysis_detection_events` — связь сработки с исходными flow-событиями

## UI

- `Shiny`-приложение поверх `ClickHouse`
- четыре вкладки: Обзор, Сработки, Детализация, Действия
- запуск ETL/analysis из UI через `docker compose run` (требует монтирования `docker.sock`)
- подробности в [r-ui/README.md](r-ui/README.md)

## Схема БД

`network_flows`:

- идентификация загрузки: `event_id`, `ingest_run_id`
- provenance: `source_dataset`, `source_key`, `source_file_name`, `source_format`, `handler_name`, `source_record_index`
- время: `flow_start`, `flow_end`, `duration_sec`
- адреса и порты: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `ip_version`
- протоколы и состояние: `transport_proto`, `app_proto`, `flow_state`, `direction`
- объём и пакеты: `packets_total`, `packets_src`, `packets_dst`, `bytes_total`, `bytes_src`, `bytes_dst`
- дополнительные сетевые поля: `src_ttl`, `dst_ttl`, `rtt_sec`, `synack_sec`, `ackdat_sec`
- разметка: `source_label`, `attack_category`, `is_malicious`
- dataset-specific payload: `attributes_json`

`etl_objects`:

- объект: `source_key`, `source_dataset`, `source_format`, `handler_name`
- объём и статус: `object_size`, `status`, `records_loaded`
- служебные поля: `ingest_run_id`, `processed_at`, `message`

`analysis_runs`:

- запуск: `analysis_run_id`, `started_at`, `finished_at`, `status`
- охват: `source_table`, `flow_rows_scanned`
- результат: `detections_total`, `signature_total`, `behavioral_total`
- служебное поле: `message`

`analysis_detections`:

- идентификация: `detection_id`, `analysis_run_id`, `detector_type`, `detector_name`
- правило: `rule_id`, `rule_name`, `severity`, `confidence_score`
- сущность: `entity_type`, `entity_value`
- сетевой контекст: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `transport_proto`, `app_proto`
- время и объём: `first_seen`, `last_seen`, `flow_count`
- данные для UI: `aggregation_key`, `title`, `description`, `tags_json`, `detail_json`, `created_at`

`analysis_detection_events`:

- связь со сработкой: `analysis_run_id`, `detection_id`, `detector_type`, `rule_id`
- связь с flow: `event_id`, `flow_id`, `flow_start`
- сетевой контекст: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `transport_proto`, `app_proto`
- provenance: `source_dataset`, `source_key`

## Структура репозитория

```text
RPRoject-ng/
├─ .env.example
├─ docker-compose.yml
├─ r-etl/
│  ├─ README.md
│  ├─ docker/
│  └─ R/
├─ r-analysis/
│  ├─ README.md
│  ├─ docker/
│  ├─ rules/
│  └─ R/
└─ r-ui/
   ├─ README.md
   ├─ docker/
   └─ R/
```
