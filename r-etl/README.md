# R ETL Init-Container

ETL-модуль на `R` для загрузки сетевых данных из `S3`, нормализации в единую
схему и записи в `ClickHouse`.

## Что делает

- листит все объекты в `S3` по префиксу
- скачивает все найденные файлы без хардкода имён
- выбирает обработчик по формату файла
- приводит данные к единой таблице `network_flows`
- пишет журнал обработки в `etl_objects`

## Поддержанные форматы

- `pcap`
- `pcapng`
- `binetflow`
- `csv`
- `zip`

Обработка:

- `pcap` / `pcapng` — через `Zeek`
- `binetflow` — прямой парсинг
- `csv` — `UNSW-NB15` и generic flow CSV
- `zip` — обход вложенных поддержанных файлов

## Формирование сессий

- `pcap` / `pcapng` ETL передаёт в `Zeek`
- ETL читает `conn.log`
- одна запись `conn.log` загружается как одна запись в `network_flows`
- `flow_start` берётся из `ts`
- `flow_end` вычисляется по `duration_sec`
- `Kyoto`, `UNSW-NB15` и `BinetFlow` нормализуются из готовых flow/session записей

## Поддержанные датасеты

- `UNSW-NB15`
- `Stratosphere IPS`
- `Kyoto 2006+`

## Таблицы

- `network_flows`
- `etl_objects`

## Запуск

```bash
cd ..
cp .env.example .env
docker compose up --build etl-init
```
