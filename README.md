# RPRoject-ng

`RPRoject-ng` — проект IDC-системы на языке `R`.

Сейчас в репозитории реализована ETL-часть проекта: загрузка сетевых данных из
`S3`, нормализация в единый формат и запись в `ClickHouse`.

## Что уже сделано

- весь текущий проект поднимается из одного корневого `docker-compose.yml`
- ETL запускается как одноразовый контейнер `etl-init`
- пайплайн листит все объекты в `S3` по префиксу
- имена файлов не захардкожены
- все поддержанные источники скачиваются и обрабатываются автоматически
- данные из разных форматов приводятся к единой таблице `network_flows`
- происхождение каждой записи сохраняется в полях provenance
- статус обработки объектов сохраняется в таблице `etl_objects`
- подтверждён полный прогон `docker compose up --build etl-init` на данных из
  `S3`

## Поддержанные форматы

- `pcap`
- `pcapng`
- `binetflow`
- `csv`
- `zip`

Обработка:

- `pcap` / `pcapng` — через `Zeek`
- `binetflow` — прямой парсинг
- `csv` — обработчик `UNSW-NB15` и generic flow-CSV
- `zip` — обход всех вложенных файлов с запуском подходящих обработчиков

Проверенный набор источников:

- `Kyoto 2006+`
- `UNSW-NB15`
- `Stratosphere IPS` (`BinetFlow` и `pcap`)

## Формирование сессий

- `pcap` / `pcapng` ETL передаёт в `Zeek` и читает `conn.log`
- одна запись `conn.log` становится одной записью в `network_flows`
- в unified-вид маппятся `uid`, `ts`, `duration`, `id.orig_h`, `id.orig_p`,
  `id.resp_h`, `id.resp_p`, `proto`, `service`, `conn_state`, `orig_*`,
  `resp_*`
- `flow_start` берётся из `ts`, `flow_end` вычисляется как
  `flow_start + duration_sec`
- для `Kyoto`, `UNSW-NB15` и `BinetFlow` ETL не восстанавливает сессии из
  пакетов, а нормализует уже готовые flow/session записи

## Kyoto 2006+

Для `Kyoto 2006+` ETL работает с `zip`-архивами.

Внутри архивов находятся:

- каталоги по году и месяцу
- дневные файлы `.txt`

Файлы `.txt` содержат tab-separated flow/session записи. Это не `pcap`, а уже
агрегированные сетевые потоки с адресами, портами, временем, протоколом,
состоянием, объёмом трафика и label-полями.

## Таблицы ClickHouse

- `network_flows` — единая таблица потоков для всех источников
- `etl_objects` — журнал обработки объектов из `S3`

## Схема БД

`network_flows`:

- идентификация загрузки: `event_id`, `ingest_run_id`
- provenance: `source_dataset`, `source_key`, `source_file_name`,
  `source_format`, `handler_name`, `source_record_index`
- время: `flow_start`, `flow_end`, `duration_sec`
- адреса и порты: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `ip_version`
- протоколы и состояние: `transport_proto`, `app_proto`, `flow_state`,
  `direction`
- объём и пакеты: `packets_total`, `packets_src`, `packets_dst`, `bytes_total`,
  `bytes_src`, `bytes_dst`
- дополнительные сетевые поля: `src_ttl`, `dst_ttl`, `rtt_sec`, `synack_sec`,
  `ackdat_sec`
- разметка: `source_label`, `attack_category`, `is_malicious`
- dataset-specific payload: `attributes_json`

`etl_objects`:

- объект: `source_key`, `source_dataset`, `source_format`, `handler_name`
- объём и статус: `object_size`, `status`, `records_loaded`
- служебные поля: `ingest_run_id`, `processed_at`, `message`

## Provenance

Для каждой записи в `network_flows` сохраняются:

- `source_dataset`
- `source_key`
- `source_file_name`
- `source_format`
- `handler_name`
- `source_record_index`
- `ingest_run_id`

## Структура репозитория

```text
RPRoject-ng/
├─ .env.example
├─ docker-compose.yml
├─ doc/
└─ r-etl/
   ├─ README.md
   ├─ docker/
   │  └─ Dockerfile.etl
   └─ R/
      ├─ main.R
      ├─ utils.R
      ├─ normalization.R
      ├─ s3_io.R
      ├─ parsing.R
      ├─ tcp_sessions.R
      └─ clickhouse_io.R
```

## Запуск

```bash
cp .env.example .env
docker compose up --build etl-init
```

После завершения контейнера `etl-init` нормализованные данные лежат в
`ClickHouse`, а журнал обработки объектов — в `etl_objects`.
