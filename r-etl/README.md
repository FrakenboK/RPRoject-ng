# R ETL Init-Container

ETL-пайплайн на `R`, который:

- листит все объекты в `S3` по заданному префиксу;
- скачивает каждый файл без хардкода имён;
- выбирает обработчик по типу файла;
- приводит сетевые данные к единой схеме `network_flows`;
- загружает результат в `ClickHouse`.
- проходит полный запуск через корневой `docker compose`

## Поддержанные форматы

- `pcap` / `pcapng` → разбираются через `Zeek` (`conn.log`)
- `binetflow`
- `csv` (`UNSW-NB15` и generic CSV с колонками src/dst/proto)
- `zip` (`Kyoto 2006+` и архивы с поддержанными вложенными файлами)

Проверено на:

- `Kyoto 2006+`
- `UNSW-NB15`
- `Stratosphere IPS`

## Формирование сессий

- `pcap` / `pcapng` разбираются через `Zeek`
- каждая запись `conn.log` загружается как одна запись в `network_flows`
- `flow_start` берётся из `ts`, `flow_end` вычисляется по `duration`
- `Kyoto`, `UNSW-NB15` и `BinetFlow` нормализуются из уже готовых flow/session
  записей

## Единая схема

Все источники сводятся в таблицу `network_flows` с общими полями:

- источник и provenance (`source_dataset`, `source_key`, `handler_name`)
- время потока (`flow_start`, `flow_end`, `duration_sec`)
- адреса и порты (`src_ip`, `src_port`, `dst_ip`, `dst_port`)
- протоколы и состояние (`transport_proto`, `app_proto`, `flow_state`)
- объёмы и пакеты (`bytes_*`, `packets_*`)
- label/attack metadata (`source_label`, `attack_category`, `is_malicious`)
- `attributes_json` для dataset-specific признаков

## Таблицы

- `network_flows`
- `etl_objects`

## Запуск

```bash
cd ..
cp .env.example .env
docker compose up --build etl-init
```

После завершения `etl-init` данные будут в таблицах:

- `network_flows`
- `etl_objects`
