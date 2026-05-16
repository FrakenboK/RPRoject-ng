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
./run.sh
```

UI доступен на `http://localhost:3838` (порт настраивается переменной `UI_PORT`).
`ClickHouse` наружу не публикуется и доступен только внутри docker-сети.

Скрипт `run.sh` автоматически:

- собирает образы `etl-init`, `analysis`, `ui`
- запускает `clickhouse`
- дожидается статуса `healthy`
- последовательно выполняет `etl-init` и `analysis`
- поднимает `ui`

Альтернативно тот же порядок можно выполнить вручную:

```bash
docker compose build etl-init analysis ui
docker compose up -d clickhouse
docker compose run --rm etl-init
docker compose run --rm analysis
docker compose up -d ui
```

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
- пять вкладок: Обзор, Сработки, Детализация, Трафик, Действия
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
├─ run.sh
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

---

# Sigma-правила: полное руководство с примерами

## Обзор

Модуль `r-analysis` реализует два метода детектирования аномалий в сетевом трафике:

1. **Сигнатурный анализ** — матчинг `network_flows` по Sigma-подобным YAML-правилам. Для каждого правила генерируется SQL-запрос, который фильтрует flow-записи, удовлетворяющие условиям правила. Совпавшие записи группируются по `src_ip + dst_ip + dst_port + transport_proto`, и для каждой группы создаётся одна сводная запись сработки.

2. **Поведенческий анализ** — агрегация flow-записей по временным окнам и парам `src-dst`, применение DBSCAN / LOF / Isolation Forest, и отбор выбросов по пороговым критериям.

Ниже подробно разбирается устройство Sigma-правил, процесс трансляции YAML → ClickHouse-SQL, и приводятся сквозные примеры для каждого из 14 правил на синтетических flow-данных.

---

## 1. Анатомия Sigma-правила

Каждое правило — YAML-файл в `r-analysis/rules/signature/` со следующей структурой:

```yaml
title: Название правила
id: уникальный-идентификатор
status: experimental | stable
description: Текстовое описание атаки или аномалии
author: team
logsource:
    category: network_connection
    product: idc
detection:
    selection_<имя>:
        <field_name>|модификатор: <значение>
        ...
    condition: <логическое выражение из имён selection>
level: high | medium | low | informational
tags:
    - attack.категория
    - attack.tXXXX
    - network
```

### 1.1. Секция `detection`

Содержит произвольное число именованных блоков `selection_*` и одно поле `condition`.

Блок `selection_*` описывает конкретный фильтр по полям таблицы `network_flows`. Каждый ключ внутри блока — это имя колонки с опциональным модификатором после `|`:

| Синтаксис поля | Значение |
|---|---|
| `field_name` | Равенство (по умолчанию `eq`) |
| `field_name\|eq` | Точное совпадение |
| `field_name\|contains` | Подстрока (через `positionCaseInsensitiveUTF8`) |
| `field_name\|startswith` | Начинается с |
| `field_name\|endswith` | Заканчивается на |
| `field_name\|re` | Регулярное выражение (через `match`) |
| `field_name\|gt` | Больше |
| `field_name\|gte` | Больше или равно |
| `field_name\|lt` | Меньше |
| `field_name\|lte` | Меньше или равно |
| `field_name\|cidr` | IP-адрес в CIDR-нотации (через `isIPAddressInRange`) |
| `field_name\|exists` | Проверка на IS NULL / IS NOT NULL |
| `field_name\|between` | BETWEEN (значение должно быть списком из двух элементов) |

Значение поля может быть:
- **Скаляром** — одно число или строка
- **Списком** — несколько значений, объединяются через `OR` (напр. `dst_port: [80, 443, 8080]`)
- **Списком с модификатором** — то же, но с применением модификатора к каждому элементу

### 1.2. Секция `condition`

Логическое выражение из имён selection-блоков и операторов `and`/`or`/`not`. Поддерживаются звёздочные шаблоны:

- `selection*` — разворачивается во все блоки, чьё имя начинается с `selection` (только для ближайшего префикса: напр. `selection_web*` матчит `selection_web_port`, `selection_web_state`, но не `selection_` сам по себе)
- `1 of selection*` — логическое `OR` всех блоков с данным префиксом
- `all of selection*` — логическое `AND` всех блоков с данным префиксом

### 1.3. Пример полного жизненного цикла правила

Возьмём правило `net_ssh_brute_force.yml`:

```yaml
detection:
    selection_proto:
        transport_proto: TCP
        dst_port: 22
    selection_state:
        flow_state:
            - INT
            - REQ
            - RST
    condition: selection_proto and selection_state
```

Парсер `build_sigma_sql()` обходит все selection-блоки:
- `selection_proto` → `(transport_proto = 'TCP' AND dst_port = 22)`
- `selection_state` → `(flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST')`

Затем подставляет их в `condition` → `(transport_proto = 'TCP' AND dst_port = 22) AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST')`

Итоговый SQL-запрос для ClickHouse:

```sql
SELECT event_id, flow_id, flow_start, flow_end,
       src_ip, src_port, dst_ip, dst_port,
       transport_proto, app_proto,
       source_dataset, source_key
FROM network_flows
WHERE (transport_proto = 'TCP' AND dst_port = 22)
  AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST')
```

Все записи, попавшие в результат, группируются по `src_ip|dst_ip||22|TCP`, и для каждой группы формируется запись в `analysis_detections`.

---

## 2. Сигнатурные правила: примеры с данными

Ниже для каждого из 14 правил приводится:
- Текст правила (YAML)
- Итоговый SQL, генерируемый парсером
- Несколько записей из гипотетической таблицы `network_flows`
- Какие записи матчатся и почему, какие — нет

### 2.1. `net_ssh_brute_force.yml`

**Правило (level: `high`)**:

```yaml
title: SSH Brute Force Candidate
id: net-ssh-brute-force
detection:
    selection_proto:
        transport_proto: TCP
        dst_port: 22
    selection_state:
        flow_state: [INT, REQ, RST]
    condition: selection_proto and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP' AND dst_port = 22)
  AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | flow_start | duration_sec | Комментарий |
|---|---|---|---|---|---|---|---|---|---|
| 1 | evt-001 | 10.0.1.5 | 192.168.1.10 | 22 | TCP | INT | 2026-05-15 08:02:01 | 0.2 | ✓ SSH-подключение прервано на стадии handshake |
| 2 | evt-002 | 10.0.1.5 | 192.168.1.10 | 22 | TCP | REQ | 2026-05-15 08:02:03 | 0.1 | ✓ Повторная попытка с неустановленным соединением |
| 3 | evt-003 | 10.0.1.5 | 192.168.1.10 | 22 | TCP | RST | 2026-05-15 08:02:05 | 0.1 | ✓ Сброс соединения без завершения handshake |
| 4 | evt-004 | 10.0.1.5 | 192.168.1.10 | 22 | TCP | CON | 2026-05-15 08:02:10 | 5.2 | ✗ CON — это успешно установленное соединение |
| 5 | evt-005 | 10.0.1.8 | 10.0.0.1 | 80 | TCP | INT | 2026-05-15 08:05:00 | 0.5 | ✗ Порт 80, не SSH |
| 6 | evt-006 | 10.0.1.9 | 10.0.0.2 | 22 | UDP | INT | 2026-05-15 08:06:00 | 0.1 | ✗ UDP, а не TCP |
| 7 | evt-007 | 10.0.1.5 | 192.168.1.10 | 22 | TCP | FIN | 2026-05-15 08:07:00 | 0.9 | ✗ FIN не входит в список flow_state |

**Результат матчинга**: записи 1, 2, 3.

Группировка: ключ `10.0.1.5|192.168.1.10||22|TCP`. В `analysis_detections` попадёт одна запись:

| Поле | Значение |
|---|---|
| `rule_name` | SSH Brute Force Candidate |
| `severity` | high |
| `entity_value` | `10.0.1.5\|192.168.1.10\|\|22\|TCP` |
| `first_seen` | 2026-05-15 08:02:01 |
| `last_seen` | 2026-05-15 08:02:05 |
| `flow_count` | 3 |

`analysis_detection_events` будет содержать 3 строки, по одной на каждый совпавший `event_id`.

**Практический смысл**: если за короткий промежуток к порту 22 летит много INT/REQ/RST — это с высокой вероятностью подбор паролей или сканирование.

---

### 2.2. `net_ftp_brute_force.yml`

**Правило (level: `medium`)**:

```yaml
title: FTP Brute Force Candidate
id: net-ftp-brute-force
detection:
    selection_proto:
        transport_proto: TCP
        dst_port: 21
    selection_state:
        flow_state: [INT, REQ, RST, CLO]
    condition: selection_proto and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP' AND dst_port = 21)
  AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST' OR flow_state = 'CLO')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | duration_sec | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-101 | 10.1.2.3 | 203.0.113.50 | 21 | TCP | RST | 0.05 | ✓ Сброс FTP-сессии |
| 2 | evt-102 | 10.1.2.3 | 203.0.113.50 | 21 | TCP | CLO | 0.12 | ✓ Закрытие без полного обмена данными |
| 3 | evt-103 | 10.1.2.3 | 203.0.113.50 | 21 | TCP | REQ | 0.03 | ✓ Запрос соединения без ответа |
| 4 | evt-104 | 10.1.2.3 | 203.0.113.50 | 21 | TCP | FIN | 1.20 | ✗ FIN — штатное завершение |
| 5 | evt-105 | 10.5.0.1 | 203.0.113.50 | 20 | TCP | INT | 0.15 | ✗ Порт 20 — FTP data, не control |
| 6 | evt-106 | 10.1.2.3 | 203.0.113.50 | 21 | TCP | INT | 0.07 | ✓ INT — неполное соединение |

**Результат матчинга**: записи 1, 2, 3, 6.

**Примечание**: в отличие от SSH, для FTP дополнительно включён `CLO` — FTP чаще оставляет «зависшие» сессии при неудачных попытках аутентификации.

---

### 2.3. `net_smb_failed_access.yml`

**Правило (level: `medium`)**: аналогично SSH Brute Force, но `dst_port: 445`, `flow_state: [INT, REQ, RST, CLO]`, `condition: selection_proto and selection_state`.

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | packets_total | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-201 | 172.16.0.5 | 172.16.0.254 | 445 | TCP | REQ | 1 | ✓ Первичный SMB-запрос отброшен |
| 2 | evt-202 | 172.16.0.5 | 172.16.0.254 | 445 | TCP | RST | 2 | ✓ RST после REQ |
| 3 | evt-203 | 172.16.0.5 | 172.16.0.254 | 445 | TCP | CLO | 1 | ✓ Закрытие без ответа сервера |
| 4 | evt-204 | 172.16.0.5 | 172.16.0.254 | 445 | TCP | CON | 15 | ✗ CON — сессия успешно установлена |
| 5 | evt-205 | 10.0.0.0 | 172.16.0.254 | 139 | TCP | RST | 1 | ✗ Порт 139 (NetBIOS), не SMB |

**Результат матчинга**: записи 1, 2, 3.

Сработка группируется как `172.16.0.5|172.16.0.254||445|TCP`.

**Практический смысл**: массовые RST/CLO на 445-й порт — классический признак попытки подбора SMB-учётных данных или атаки EternalBlue-подобных эксплойтов на стадии разведки.

---

### 2.4. `net_rdp_failed_access.yml`

**Правило (level: `medium`)**: аналогично SSH Brute Force, но `dst_port: 3389`, `flow_state: [INT, REQ, RST, CLO]`, `condition: selection_proto and selection_state`.

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | bytes_total | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-301 | 192.168.0.100 | 10.0.5.12 | 3389 | TCP | REQ | 66 | ✓ SYN-пакет без ответа |
| 2 | evt-302 | 192.168.0.100 | 10.0.5.12 | 3389 | TCP | RST | 60 | ✓ Пришёл RST в ответ |
| 3 | evt-303 | 192.168.0.100 | 10.0.5.12 | 3389 | TCP | CLO | 54 | ✓ Таймаут открытия |
| 4 | evt-304 | 192.168.0.100 | 10.0.5.12 | 3389 | TCP | CON | 2048 | ✗ CON — успешная RDP-сессия |
| 5 | evt-305 | 10.0.0.1 | 10.0.5.12 | 3389 | UDP | INT | 40 | ✗ UDP — RDP использует TCP |
| 6 | evt-306 | 192.168.0.100 | 10.0.5.15 | 3390 | TCP | REQ | 66 | ✗ Порт 3390, не стандартный RDP |

**Результат матчинга**: записи 1, 2, 3.

---

### 2.5. `net_suspicious_telnet_access.yml`

**Правило (level: `medium`)**:

```yaml
title: Telnet Failed Access Candidate
id: net-suspicious-telnet-access
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [23, 2323]
    selection_state:
        flow_state: [INT, REQ, RST, CLO]
    condition: selection_proto and selection_ports and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 23 OR dst_port = 2323)
  AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST' OR flow_state = 'CLO')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | Комментарий |
|---|---|---|---|---|---|---|---|
| 1 | evt-401 | 10.200.0.1 | 10.0.0.1 | 23 | TCP | INT | ✓ Неудачная попытка Telnet |
| 2 | evt-402 | 10.200.0.1 | 10.0.0.1 | 2323 | TCP | REQ | ✓ Альтернативный Telnet-порт |
| 3 | evt-403 | 10.200.0.2 | 10.1.1.1 | 23 | TCP | FIN | ✗ FIN — штатное завершение |
| 4 | evt-404 | 10.200.0.1 | 10.0.0.1 | 22 | TCP | REQ | ✗ Порт 22, это скорее SSH (перехватит другое правило) |

**Результат матчинга**: записи 1, 2.

---

### 2.6. `net_mysql_postgres_exposed.yml`

**Правило (level: `high`)**:

```yaml
title: Database Port Exposure
id: net-mysql-postgres-exposed
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [3306, 5432, 1433, 27017, 6379]
    condition: selection_proto and selection_ports
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 3306 OR dst_port = 5432 OR dst_port = 1433 OR dst_port = 27017 OR dst_port = 6379)
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | Комментарий |
|---|---|---|---|---|---|---|---|
| 1 | evt-501 | 198.51.100.5 | 10.0.0.15 | 3306 | TCP | CON | ✓ Внешний IP → MySQL |
| 2 | evt-502 | 198.51.100.6 | 10.0.0.16 | 5432 | TCP | CON | ✓ Внешний IP → PostgreSQL |
| 3 | evt-503 | 198.51.100.7 | 10.0.0.17 | 6379 | TCP | FIN | ✓ Внешний IP → Redis |
| 4 | evt-504 | 10.0.0.1 | 10.0.0.2 | 27017 | TCP | CON | ✗ Внутренний IP — легитимный трафик MongoDB |

**Результат матчинга**: записи 1, 2, 3.

**Важно**: правило не различает внутренний и внешний трафик — оно детектирует *любые* TCP-соединения к портам БД. Ключевая идея: открытые порты СУБД наружу — серьёзная уязвимость, даже если flow_state = CON.

---

### 2.7. `net_http_large_upload.yml`

**Правило (level: `medium`)**:

```yaml
title: Suspicious Large HTTP Upload
id: net-http-large-upload
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [80, 443, 8080]
    selection_bytes:
        bytes_src|gte: 1048576
    selection_state:
        flow_state: [FIN, CON]
    condition: selection_proto and selection_ports and selection_bytes and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 80 OR dst_port = 443 OR dst_port = 8080)
  AND (bytes_src >= 1048576)
  AND (flow_state = 'FIN' OR flow_state = 'CON')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | bytes_src | bytes_total | Комментарий |
|---|---|---|---|---|---|---|---|---|---|
| 1 | evt-601 | 10.0.1.100 | 203.0.113.80 | 443 | TCP | FIN | 5242880 | 5300000 | ✓ 5 МБ отправлено через HTTPS |
| 2 | evt-602 | 10.0.1.100 | 203.0.113.80 | 80 | TCP | CON | 2097152 | 2150000 | ✓ 2 МБ через HTTP с установленным соединением |
| 3 | evt-603 | 10.0.1.101 | 10.0.0.1 | 8080 | TCP | FIN | 1048576 | 1050000 | ✓ Ровно 1 МБ на порту 8080 |
| 4 | evt-604 | 10.0.1.102 | 203.0.113.80 | 443 | TCP | FIN | 500000 | 520000 | ✗ Меньше порога в 1 МБ |
| 5 | evt-605 | 10.0.1.103 | 203.0.113.80 | 443 | TCP | RST | 2000000 | 2050000 | ✗ RST — соединение разорвано, не FIN/CON |
| 6 | evt-606 | 10.0.1.104 | 203.0.113.80 | 25 | TCP | FIN | 2000000 | 2050000 | ✗ Порт 25 (SMTP), не HTTP |

**Результат матчинга**: записи 1, 2, 3.

**Практический смысл**: большой объём отправленных данных — признак эксфильтрации. Правило настроено на `bytes_src` (исходящие байты), а не `bytes_total`, что позволяет отличить закачку от скачивания.

---

### 2.8. `net_smtp_suspicious.yml`

**Правило (level: `low`)**:

```yaml
title: Suspicious SMTP Traffic
id: net-smtp-suspicious
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [25, 465, 587]
    selection_bytes:
        bytes_total|gte: 5000
    selection_state:
        flow_state: [FIN, CON]
    condition: selection_proto and selection_ports and selection_bytes and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 25 OR dst_port = 465 OR dst_port = 587)
  AND (bytes_total >= 5000)
  AND (flow_state = 'FIN' OR flow_state = 'CON')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | bytes_total | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-701 | 10.0.2.15 | 192.0.2.10 | 25 | TCP | FIN | 6800 | ✓ SMTP на 25-м порту с 6.8 КБ |
| 2 | evt-702 | 10.0.2.15 | 192.0.2.10 | 587 | TCP | CON | 12500 | ✓ SMTPS (submission) с 12.5 КБ |
| 3 | evt-703 | 10.0.2.15 | 192.0.2.10 | 465 | TCP | FIN | 5000 | ✓ Ровно порог в 5000 байт |
| 4 | evt-704 | 10.0.2.15 | 192.0.2.10 | 25 | TCP | FIN | 1200 | ✗ Менее 5000 байт |
| 5 | evt-705 | 10.0.2.15 | 192.0.2.10 | 25 | TCP | RST | 9000 | ✗ RST — не FIN/CON |

**Результат матчинга**: записи 1, 2, 3.

**Примечание**: уровень `low` означает, что правило даёт много сработок и предназначено для корреляции с другими сигналами. Легитимная почта тоже попадает под эти критерии.

---

### 2.9. `net_c2_common_listener_ports.yml`

**Правило (level: `high`)**:

```yaml
title: Common C2 Listener Ports
id: net-c2-common-listener-ports
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [1234, 1337, 2222, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 12345, 31337]
    selection_duration:
        duration_sec|gte: 30
    selection_bytes:
        bytes_total|gte: 500
    selection_state:
        flow_state: [FIN, CON]
    condition: selection_proto and selection_ports and selection_duration and selection_bytes and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 1234 OR dst_port = 1337 OR dst_port = 2222 OR dst_port = 4444
    OR dst_port = 5555 OR dst_port = 6666 OR dst_port = 6667 OR dst_port = 7777
    OR dst_port = 8888 OR dst_port = 9999 OR dst_port = 12345 OR dst_port = 31337)
  AND (duration_sec >= 30)
  AND (bytes_total >= 500)
  AND (flow_state = 'FIN' OR flow_state = 'CON')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | duration_sec | bytes_total | Комментарий |
|---|---|---|---|---|---|---|---|---|---|
| 1 | evt-801 | 10.0.5.222 | 198.51.100.99 | 4444 | TCP | CON | 180 | 15000 | ✓ Долгое соединение на 4444 |
| 2 | evt-802 | 10.0.5.222 | 198.51.100.99 | 31337 | TCP | FIN | 45 | 3200 | ✓ Back Orifice-порт, 45 секунд |
| 3 | evt-803 | 10.0.5.222 | 10.0.0.5 | 9999 | TCP | CON | 60 | 800 | ✓ Локальный 9999, длинная сессия |
| 4 | evt-804 | 10.0.5.222 | 198.51.100.99 | 4444 | TCP | CON | 10 | 2000 | ✗ duration_sec = 10, меньше порога 30 |
| 5 | evt-805 | 10.0.5.222 | 198.51.100.99 | 6666 | TCP | FIN | 120 | 200 | ✗ bytes_total = 200, меньше порога 500 |
| 6 | evt-806 | 10.0.5.222 | 198.51.100.99 | 31337 | TCP | REQ | 90 | 700 | ✗ REQ — не FIN и не CON |

**Результат матчинга**: записи 1, 2, 3.

Правило комбинирует три признака: нестандартный порт + длительность сессии + объём данных — чтобы отсечь короткие пробы и случайные совпадения.

---

### 2.10. `net_backdoor_known_ports.yml`

**Правило (level: `high`)**:

```yaml
title: Known Backdoor or RAT Ports
id: net-backdoor-known-ports
detection:
    selection_proto:
        transport_proto: TCP
    selection_ports:
        dst_port: [1234, 2222, 4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337, 54321, 65535]
    selection_state:
        flow_state: [FIN, CON]
    selection_duration:
        duration_sec|gte: 5
    condition: selection_proto and selection_ports and selection_state and selection_duration
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (dst_port = 1234 OR dst_port = 2222 OR dst_port = 4444 OR dst_port = 5555
    OR dst_port = 6666 OR dst_port = 7777 OR dst_port = 8888 OR dst_port = 9999
    OR dst_port = 12345 OR dst_port = 31337 OR dst_port = 54321 OR dst_port = 65535)
  AND (flow_state = 'FIN' OR flow_state = 'CON')
  AND (duration_sec >= 5)
```

**Отличие от `net_c2_common_listener_ports.yml`**: ниже пороги (`duration_sec >= 5` вместо 30, без порога на байты), добавлены порты 54321, 65535. Более широкий охват, больше ложных сработок.

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | flow_state | duration_sec | bytes_total | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-901 | 10.0.7.1 | 203.0.113.200 | 54321 | CON | 8 | 120 | ✓ Короткая, но завершённая сессия на 54321 |
| 2 | evt-902 | 10.0.7.1 | 203.0.113.200 | 65535 | FIN | 5 | 300 | ✓ Ровно на границе duration_sec = 5 |
| 3 | evt-903 | 10.0.7.1 | 203.0.113.200 | 8888 | RST | 10 | 500 | ✗ RST — не FIN/CON |
| 4 | evt-904 | 10.0.7.1 | 203.0.113.200 | 7777 | CON | 3 | 1000 | ✗ duration_sec = 3, меньше порога 5 |

**Результат матчинга**: записи 1, 2.

---

### 2.11. `net_dns_anomaly.yml`

**Правило (level: `medium`)**:

```yaml
title: DNS Anomaly Candidate
id: net-dns-anomaly
detection:
    selection_proto:
        transport_proto: UDP
        dst_port: 53
    selection_size:
        bytes_total|gte: 512
    condition: selection_proto and selection_size
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'UDP' AND dst_port = 53)
  AND (bytes_total >= 512)
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | bytes_total | packets_total | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-1001 | 10.0.1.5 | 8.8.8.8 | 53 | UDP | 1024 | 1 | ✓ DNS-ответ > 512 байт (возможно, Amplification) |
| 2 | evt-1002 | 10.0.1.5 | 8.8.4.4 | 53 | UDP | 4096 | 1 | ✓ Очень большой DNS-пакет |
| 3 | evt-1003 | 10.0.1.5 | 1.1.1.1 | 53 | UDP | 512 | 1 | ✓ Ровно на пороге |
| 4 | evt-1004 | 10.0.1.5 | 8.8.8.8 | 53 | UDP | 64 | 1 | ✗ Обычный DNS-запрос (60–100 байт) |
| 5 | evt-1005 | 10.0.1.5 | 8.8.8.8 | 53 | TCP | 800 | 1 | ✗ TCP, не UDP |
| 6 | evt-1006 | 10.0.1.5 | 8.8.8.8 | 5353 | UDP | 1024 | 1 | ✗ mDNS (порт 5353), не стандартный DNS |

**Результат матчинга**: записи 1, 2, 3.

---

### 2.12. `net_icmp_flood.yml`

**Правило (level: `medium`)**:

```yaml
title: ICMP Flood or Sweep Candidate
id: net-icmp-flood
detection:
    selection_proto:
        transport_proto: ICMP
    selection_packets:
        packets_total|gte: 100
    selection_duration:
        duration_sec|lte: 10
    condition: selection_proto and selection_packets and selection_duration
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'ICMP')
  AND (packets_total >= 100)
  AND (duration_sec <= 10)
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | transport_proto | packets_total | duration_sec | Комментарий |
|---|---|---|---|---|---|---|---|
| 1 | evt-1101 | 10.0.99.1 | 10.0.0.1 | ICMP | 200 | 5 | ✓ 200 ICMP-пакетов за 5 секунд |
| 2 | evt-1102 | 10.0.99.2 | 10.0.0.2 | ICMP | 100 | 10 | ✓ Ровно 100 пакетов за 10 секунд |
| 3 | evt-1103 | 10.0.99.3 | 10.0.0.3 | ICMP | 500 | 8 | ✓ Типичный ping-flood: 500 пакетов за 8 сек |
| 4 | evt-1104 | 10.0.99.4 | 10.0.0.4 | ICMP | 50 | 5 | ✗ Менее 100 пакетов |
| 5 | evt-1105 | 10.0.99.5 | 10.0.0.5 | ICMP | 200 | 60 | ✗ 200 пакетов за 60 секунд — это пинг-мониторинг |
| 6 | evt-1106 | 10.0.99.6 | 10.0.0.6 | UDP | 200 | 5 | ✗ UDP, не ICMP |

**Результат матчинга**: записи 1, 2, 3.

**Механика**: детектор ловит не отдельные ICMP-пакеты, а flow-записи, каждая из которых агрегирует *сессию* ICMP-трафика. Если flow-запись содержит 100+ пакетов за ≤10 секунд — это уже аномалия.

---

### 2.13. `net_udp_port_scan.yml`

**Правило (level: `medium`)**:

```yaml
title: UDP Port Scan Candidate
id: net-udp-port-scan
detection:
    selection_proto:
        transport_proto: UDP
    selection_bytes:
        bytes_src|lte: 128
    selection_state:
        flow_state: [REQ, INT]
    condition: selection_proto and selection_bytes and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'UDP')
  AND (bytes_src <= 128)
  AND (flow_state = 'REQ' OR flow_state = 'INT')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | bytes_src | flow_state | Комментарий |
|---|---|---|---|---|---|---|---|---|
| 1 | evt-1201 | 10.0.3.1 | 10.0.0.1 | 161 | UDP | 64 | REQ | ✓ SNMP-проб (UDP, короткий запрос) |
| 2 | evt-1202 | 10.0.3.1 | 10.0.0.1 | 162 | UDP | 48 | REQ | ✓ SNMP-trap-порт, маленький пакет |
| 3 | evt-1203 | 10.0.3.1 | 10.0.0.1 | 500 | UDP | 128 | INT | ✓ IKE/ISAKMP, ровно 128 байт |
| 4 | evt-1204 | 10.0.3.1 | 10.0.0.1 | 123 | UDP | 200 | REQ | ✗ bytes_src = 200 > 128 |
| 5 | evt-1205 | 10.0.3.1 | 10.0.0.1 | 53 | UDP | 80 | FIN | ✗ FIN не входит в список flow_state |

**Результат матчинга**: записи 1, 2, 3.

**Смысл**: UDP-сканеры посылают короткие зонды на множество портов; агрегация по числу уникальных dst_port — на уровне поведенческого детектора vertical port scan.

---

### 2.14. `net_high_failure_ratio_host.yml`

**Правило (level: `low`)**:

```yaml
title: High TCP Failure Ratio Host
id: net-high-failure-ratio-host
detection:
    selection_proto:
        transport_proto: TCP
    selection_state:
        flow_state: [INT, REQ, RST, CLO]
    condition: selection_proto and selection_state
```

**Сгенерированный SQL WHERE**:

```sql
(transport_proto = 'TCP')
  AND (flow_state = 'INT' OR flow_state = 'REQ' OR flow_state = 'RST' OR flow_state = 'CLO')
```

**Тестовые данные**:

| # | event_id | src_ip | dst_ip | dst_port | transport_proto | flow_state | Комментарий |
|---|---|---|---|---|---|---|---|
| 1 | evt-1301 | 10.100.0.1 | 172.16.1.10 | 80 | TCP | REQ | ✓ Неудачное HTTP-соединение |
| 2 | evt-1302 | 10.100.0.1 | 172.16.1.10 | 443 | TCP | RST | ✓ Сброс HTTPS |
| 3 | evt-1303 | 10.100.0.1 | 172.16.1.11 | 8080 | TCP | CLO | ✓ Закрытие без данных |
| 4 | evt-1304 | 10.100.0.1 | 172.16.1.12 | 22 | TCP | INT | ✓ В том числе SSH-неудачи |
| 5 | evt-1305 | 10.100.0.1 | 172.16.1.10 | 3306 | TCP | FIN | ✗ FIN — успешная сессия |
| 6 | evt-1306 | 10.100.0.1 | 172.16.1.10 | 80 | TCP | CON | ✗ CON — установленное соединение |

**Результат матчинга**: записи 1, 2, 3, 4.

**Назначение**: это широкое правило — «приёмник» всех TCP-сессий с признаками сбоя, независимо от порта. Уровень `low`, поскольку само по себе правило даёт много шума. Его ценность — в агрегации по хосту и временному окну в поведенческих детекторах (`failure_ratio`).

---

## 3. Механизм групп и привязки событий

После того как SQL-запрос возвращает совпавшие flow-записи, выполняется группировка:

```r
grouped[, detection_group := paste(src_ip, dst_ip, ifelse(is.na(dst_port), "", dst_port), transport_proto, sep = "|")]
```

Для каждой группы:
1. Создаётся уникальный `detection_id` (формат: `analysis_run_id-NNNNNN`)
2. Записывается одна строка в `analysis_detections` с полями `first_seen`, `last_seen`, `flow_count`, `src_ip/dst_ip/dst_port`
3. Все `event_id` из группы записываются в `analysis_detection_events`

**Пример группировки для правила SSH Brute Force** (продолжение примера из §2.1):

Из трёх совпавших записей образуется ровно одна группа:

```
detection_group = "10.0.1.5|192.168.1.10||22|TCP"
```

**`analysis_detections`** — одна строка:

| detection_id | rule_id | severity | src_ip | dst_ip | flow_count | first_seen | last_seen |
|---|---|---|---|---|---|---|---|
| analysis-20260515083001-000001 | net-ssh-brute-force | high | 10.0.1.5 | 192.168.1.10 | 3 | 2026-05-15 08:02:01 | 2026-05-15 08:02:05 |

**`analysis_detection_events`** — три строки:

| detection_id | event_id | src_ip | dst_ip | dst_port | transport_proto |
|---|---|---|---|---|---|
| analysis-...-000001 | evt-001 | 10.0.1.5 | 192.168.1.10 | 22 | TCP |
| analysis-...-000001 | evt-002 | 10.0.1.5 | 192.168.1.10 | 22 | TCP |
| analysis-...-000001 | evt-003 | 10.0.1.5 | 192.168.1.10 | 22 | TCP |

Таким образом, UI может показать сводную карточку сработки («SSH Brute Force Candidate, 3 события») и раскрыть её до отдельных flow-записей.

---

## 4. Поведенческий анализ: DBSCAN + LOF + Isolation Forest

Поведенческий модуль строит две таблицы агрегатов:

### 4.1. Агрегаты по `src_ip + window`

Из `network_flows` выбираются TCP-записи, группируются по `src_ip` в окнах по 5 минут. Для каждой группы считаются признаки:

| Признак | Описание |
|---|---|
| `flow_count` | Число flow-записей |
| `uniq_dst_ips` | Уникальных dst IP |
| `uniq_dst_ports` | Уникальных dst портов |
| `avg_duration_sec` | Средняя длительность сессии |
| `max_duration_sec` | Максимальная длительность |
| `bytes_total_sum` | Суммарный объём |
| `packets_total_sum` | Суммарное число пакетов |
| `failure_ratio` | Доля «сбойных» flow-состояний (INT, REQ, RST, CLO, S0, REJ, ...) |
| `web_ratio` | Доля web-портов (80, 443, 8000, 8080, 8443) |
| `smb_ratio` | Доля SMB-порта (445) |
| `remote_admin_ratio` | Доля портов удалённого администрирования (22, 23, 3389, ...) |
| `udp_flow_count` | Число UDP-потоков (уже учтено, что группировка TCP) |
| `icmp_flow_count` | Число ICMP-потоков |
| `ftp_ratio`, `ssh_ratio`, `smtp_ratio`, `db_ratio` | Доля специфичных портов |

Признаки нормализуются, и для отфильтрованной выборки (строки с `flow_count >= 10` или высокой вариативностью портов/адресов) запускаются три алгоритма:

1. **DBSCAN** — кластеризация по плотности; точки, не попавшие ни в один кластер, получают флаг `dbscan_noise = TRUE`
2. **LOF** (Local Outlier Factor) — коэффициент локальной аномальности; высокий LOF-score = точка сильно отличается от соседей
3. **Isolation Forest** — изоляционный лес; высокий score = точка легко изолируется (аномальна)

Итоговый ансамблевый score:

```
ensemble_score = mean(dbscan_noise_as_numeric, lof_percent_rank, iforest_percent_rank)
```

### 4.2. Детекторы на основе оконных агрегатов

После вычисления ensemble_score строки фильтруются по жёстким порогам:

**Vertical Port Scan** (`rule_id: behavior.portscan.vertical`):
```
flow_count >= 40 AND uniq_dst_ports >= 20 AND failure_ratio >= 0.50
AND avg_duration_sec <= 10 AND ensemble_score >= 0.80
```

**Horizontal Host Scan** (`rule_id: behavior.portscan.horizontal`):
```
flow_count >= 40 AND uniq_dst_ips >= 20 AND failure_ratio >= 0.50
AND avg_duration_sec <= 10 AND ensemble_score >= 0.80
```

**HTTP Brute Force / Directory Fuzzing** (`rule_id: behavior.http.bruteforce_or_fuzz`):
```
flow_count >= 50 AND web_ratio >= 0.90 AND uniq_dst_ports <= 3
AND uniq_dst_ips <= 10 AND failure_ratio >= 0.40
AND avg_duration_sec <= 10 AND ensemble_score >= 0.80
```

**SMB Brute Force** (`rule_id: behavior.smb.bruteforce`):
```
flow_count >= 30 AND smb_ratio >= 0.80 AND uniq_dst_ports <= 2
AND uniq_dst_ips <= 5 AND failure_ratio >= 0.40
AND avg_duration_sec <= 15 AND ensemble_score >= 0.80
```

**Slow Rate Scan** (`rule_id: behavioral-slow-scan`):
```
span_minutes >= 10 AND uniq_dst_ports >= 10 AND flow_count >= 20
AND (flow_count / span_minutes) < 5 AND ensemble_score >= 0.75
```

### 4.3. Пример оконного детектора: Vertical Port Scan

**Исходные данные** — окно для `src_ip = 10.0.99.99` за 08:00–08:05:

```
flow_count         = 87
uniq_dst_ips       = 1
uniq_dst_ports     = 45
avg_duration_sec   = 2.1
max_duration_sec   = 5.0
bytes_total_sum    = 13920
packets_total_sum  = 261
failure_ratio      = 0.92
web_ratio          = 0.00
smb_ratio          = 0.00
```

**Нормализация и ML**:
- Признаки подаются в DBSCAN/LOF/IF
- `dbscan_noise = TRUE` (точка не кластеризуется с нормальным трафиком)
- `lof_score = 3.8, lof_rank = 0.97`
- `iforest_score = 0.72, iforest_rank = 0.94`
- `ensemble_score = (1 + 0.97 + 0.94) / 3 = 0.97`

**Проверка порогов Vertical Port Scan**:
```
flow_count=87 >= 40 ✓
uniq_dst_ports=45 >= 20 ✓
failure_ratio=0.92 >= 0.50 ✓
avg_duration_sec=2.1 <= 10 ✓
ensemble_score=0.97 >= 0.80 ✓
```
→ Сработка создана.

**Итоговая запись в `analysis_detections`**:

```json
{
  "detection_id": "analysis-20260515120000-000005",
  "detector_type": "behavioral",
  "rule_id": "behavior.portscan.vertical",
  "rule_name": "Vertical Port Scan Candidate",
  "severity": "high",
  "confidence_score": 0.97,
  "entity_type": "src_ip_window",
  "entity_value": "10.0.99.99|2026-05-15 08:00:00",
  "src_ip": "10.0.99.99",
  "first_seen": "2026-05-15 08:00:00",
  "last_seen": "2026-05-15 08:05:00",
  "flow_count": 87,
  "detail_json": "{\"flow_count\":87,\"uniq_dst_ports\":45,\"failure_ratio\":0.92,\"ensemble_score\":0.97,\"lof_score\":3.8,\"iforest_score\":0.72,\"dbscan_noise\":true}"
}
```

### 4.4. Агрегаты по парам `src_ip -> dst_ip:dst_port` и детектор C2

Для каждой уникальной пары `src_ip → dst_ip:dst_port` (по TCP, минимум 3 flow-записи) считаются:

| Признак | Описание |
|---|---|
| `span_sec` | Размах по времени (от первой до последней записи) |
| `flow_count` | Число записей |
| `avg_duration_sec` | Средняя длительность |
| `max_duration_sec` | Максимальная длительность |
| `duration_stddev` | Стандартное отклонение длительности |
| `bytes_total_sum` | Суммарный объём |
| `bytes_stddev` | Стандартное отклонение объёма |
| `packets_total_sum` | Суммарное число пакетов |
| `failure_ratio` | Доля сбойных состояний |
| `avg_interarrival_sec` | Средний интервал между flow-записями |
| `bytes_per_second` | Скорость передачи |
| `src_dst_byte_ratio` | Соотношение отправленных и полученных байт |

**Long-Lived C2 Session Candidate** (`rule_id: behavior.long_lived_c2`):
```
flow_count >= 5 AND flow_count <= 200
AND span_sec >= 3600
AND avg_duration_sec >= 120
AND failure_ratio <= 0.15
AND dst_port NOT IN (стандартные сервисные порты)
AND app_proto NOT IN (стандартные протоколы)
AND ensemble_score >= 0.85
```

**Пример C2-кандидата**:

Пара `10.0.5.222 → 198.51.100.99:4444` (TCP):

```
flow_count          = 12
span_sec            = 7200    (2 часа)
avg_duration_sec    = 300     (5 минут средняя сессия)
max_duration_sec    = 420
failure_ratio       = 0.08
app_proto           = ""      (не опознан)
dst_port            = 4444    (не в списке исключённых)
ensemble_score      = 0.91    (LOF=0.94, IF=0.89, DBSCAN noise=TRUE)
```

Проверка порогов C2:
```
flow_count=12 между 5 и 200 ✓
span_sec=7200 >= 3600 ✓
avg_duration_sec=300 >= 120 ✓
failure_ratio=0.08 <= 0.15 ✓
dst_port=4444 не в списке исключений ✓
app_proto="" не в списке исключений ✓
ensemble_score=0.91 >= 0.85 ✓
```
→ Сработка C2 создана.

Ключевая логика детектора: долгоживущая (span ≥ 1 час) коммуникация на нестандартный порт без известного app_proto, с низким failure_ratio (соединение стабильно) и средней длительностью сессии ≥ 2 минуты — это один из самых сильных сигналов C2 в пассивном сетевом анализе.

---

## 5. Дополнительные поведенческие детекторы

### 5.1. UDP Flood

Прямой SQL-агрегат по UDP-потокам в 5-минутных окнах:

```sql
SELECT
  toStartOfInterval(flow_start, toIntervalMinute(5)) AS window_start,
  src_ip,
  count() AS flow_count,
  uniqExact(dst_ip) AS uniq_dst_ips,
  uniqExact(dst_port) AS uniq_dst_ports
FROM network_flows
WHERE flow_start IS NOT NULL
  AND src_ip != ''
  AND transport_proto = 'UDP'
GROUP BY window_start, src_ip
HAVING count() > 500 AND uniqExact(dst_ip) > 3
```

Порог: 500+ UDP-потоков от одного src_ip в одном 5-минутном окне.

### 5.2. TTL Spoofing / Multi-OS Candidate

Группировка по `src_ip` с анализом уникальных значений TTL:

```sql
SELECT
  src_ip,
  count() AS flow_count,
  uniqExact(src_ttl) AS uniq_src_ttl
FROM network_flows
WHERE src_ttl IS NOT NULL
GROUP BY src_ip
HAVING uniq_src_ttl > 2 AND count() >= 5
```

Если один IP использует ≥3 разных TTL — возможен IP-спуфинг или за хостом скрывается несколько устройств.

**Пример**: `src_ip = 10.0.99.100`, flow_count = 45, значения TTL: {32, 64, 128, 255} — 4 уникальных TTL при 45 flow-записях → сработка.

### 5.3. DNS Tunneling

Группировка по `src_ip` для UDP-трафика на порт 53:

```sql
SELECT
  src_ip,
  count() AS flow_count,
  avg(toFloat64(ifNull(bytes_total, 0))) AS avg_bytes_total
FROM network_flows
WHERE dst_port = 53 AND transport_proto = 'UDP'
GROUP BY src_ip
HAVING avg(bytes_total) > 300 AND count() > 50
```

DNS-туннелирование использует большие пакеты для кодирования данных в DNS-запросах/ответах. Средний легитимный DNS-пакет ~60–150 байт; среднее >300 при 50+ запросах аномально.

**Пример**: `src_ip = 10.0.5.222`, 200 DNS-запросов, `avg_bytes_total = 480` → сработка DNS Tunneling.

---

## 6. Полный жизненный цикл анализа: сквозной пример

Запуск `docker compose up --build analysis` выполняет последовательность:

### Шаг 1. Инициализация

```
[INFO] ClickHouse connection established
[INFO] Creating analysis tables if needed
[INFO] Marking stale runs as failed
```

Создаётся запись в `analysis_runs`:

| analysis_run_id | started_at | status | source_table | flow_rows_scanned |
|---|---|---|---|---|
| analysis-20260515120000 | 2026-05-15 12:00:00 | running | network_flows | 250000 |

### Шаг 2. Сканирование Sigma-правил

Парсер обходит 14 YAML-файлов. Для каждого генерируется SQL WHERE, выполняется запрос к `network_flows`.

Пример лога (сокращённо):

```
[INFO] Inserted 12 detection summary row(s) — SSH Brute Force
[INFO] Inserted 5 detection summary row(s) — FTP Brute Force
[INFO] Inserted 8 detection summary row(s) — SMB Failed Access
[INFO] Inserted 15 detection summary row(s) — High TCP Failure Ratio Host
...
```

### Шаг 3. Сканирование поведенческих детекторов

Строятся оконные агрегаты (`src_ip + 5m window`), выполняется DBSCAN/LOF/IF.

```
[INFO] Behavioral stage: 1840 source-window aggregate row(s) loaded
[INFO] Behavioral stage: 320 source-window row(s) selected for ML
[INFO] Behavioral stage: 4500 src-dst aggregate row(s) loaded
[INFO] Behavioral stage: 210 src-dst row(s) selected for ML
[INFO] Behavioral stage: 2 UDP flood candidate row(s) detected
[INFO] Behavioral stage: 3 TTL anomaly row(s) detected
[INFO] Behavioral stage: 1 DNS tunneling candidate row(s) detected
```

### Шаг 4. Фиксация результатов

Все сработки сохраняются в `analysis_detections`, все связи — в `analysis_detection_events`.

Запись `analysis_runs` обновляется:

| finished_at | status | detections_total | signature_total | behavioral_total |
|---|---|---|---|---|
| 2026-05-15 12:05:23 | completed | 145 | 98 | 47 |

Финальный лог:

```
[INFO] Analysis completed successfully: 145 total detections (98 signature, 47 behavioral)
```

---

## 7. Использование из UI

Вкладка **«Сработки»** в Shiny-интерфейсе позволяет:
- Фильтровать по `severity`, `detector_type` (signature/behavioral), `rule_name`, `src_ip`, `dst_ip`
- Видеть сводную карточку: название правила, уровень опасности, количество flow-событий, временной диапазон
- Раскрыть drill-down до таблицы `analysis_detection_events` — списка конкретных flow-записей, вызвавших сработку
- Экспортировать выборку в CSV

Вкладка **«Детализация»** отображает конкретный `event_id` из `network_flows` со всеми полями: provenance, тайминги, адреса, порты, объём, пакеты, метаданные.

Вкладка **«Обзор»** показывает агрегированную статистику по последнему `analysis_run`: общее число сработок, распределение по severity и detector_type.

---

## 8. Расширение набора правил

Чтобы добавить новое Sigma-правило:

1. Создать файл `r-analysis/rules/signature/net_<имя>.yml`
2. Заполнить поля `title`, `id`, `detection`, `condition`, `level`, `tags`
3. Поле в `detection.selection_*` может ссылаться на любую колонку из `network_flows`
4. Перезапустить `docker compose up --build analysis`

Пример минимального правила для детектирования DNS-over-HTTPS (DoH) на нестандартном порту:

```yaml
title: Potential DNS over HTTPS on Non-Standard Port
id: net-doh-nonstandard
status: experimental
description: Detects HTTPS-like traffic to non-443 ports that may indicate DoH.
author: team
logsource:
    category: network_connection
    product: idc
detection:
    selection_proto:
        transport_proto: TCP
        app_proto: ssl
    selection_port:
        dst_port|gt: 1024
    selection_state:
        flow_state: [FIN, CON]
    selection_duration:
        duration_sec|gte: 10
    condition: selection_proto and selection_port and selection_state and selection_duration
level: low
tags:
    - attack.command-and-control
    - network
```

---

## 9. Модификаторы правил и тонкая настройка

### 9.1. Логические операторы в condition

```yaml
# И — все selection должны совпасть
condition: selection_a and selection_b

# ИЛИ — достаточно одного
condition: selection_a or selection_b

# Исключение
condition: selection_a and not selection_b

# Комбинация
condition: (selection_a or selection_b) and not selection_c
```

### 9.2. Звёздочные шаблоны

```yaml
detection:
    selection_web_port:
        dst_port: [80, 443, 8080]
    selection_web_state:
        flow_state: [FIN, CON]
    selection_web_bytes:
        bytes_total|gte: 1000000
    condition: all of selection_web*
```

Развернётся в:

```sql
((dst_port = 80 OR dst_port = 443 OR dst_port = 8080))
  AND ((flow_state = 'FIN' OR flow_state = 'CON'))
  AND ((bytes_total >= 1000000))
```

А `1 of selection_web*` развернулось бы через OR — сработка при совпадении хотя бы одного из блоков.

### 9.3. Модификатор `exists`

```yaml
selection_has_label:
    source_label|exists: true           # source_label IS NOT NULL
selection_no_label:
    source_label|exists: false          # source_label IS NULL
```

Используется для фильтрации записей с разметкой или без.

### 9.4. Модификатор `contains`

```yaml
selection_suspicious:
    app_proto|contains: "suspicious"    # positionCaseInsensitiveUTF8(app_proto, 'suspicious') > 0
```

### 9.5. Модификатор `re`

```yaml
selection_user_agent:
    attributes_json|re: "Cobalt|Beacon|Meterpreter"  # match(attributes_json, 'Cobalt|Beacon|Meterpreter')
```

Регулярное выражение передаётся напрямую в ClickHouse-функцию `match`.

### 9.6. Модификатор `cidr`

```yaml
selection_external:
    src_ip|cidr: "192.168.0.0/16"       # isIPAddressInRange(src_ip, '192.168.0.0/16')
```

### 9.7. Модификаторы сравнения: `gt`, `gte`, `lt`, `lte`, `between`

```yaml
selection_large:
    bytes_total|gte: 1048576             # bytes_total >= 1048576
selection_small:
    duration_sec|lte: 5                  # duration_sec <= 5
selection_range:
    packets_total|between: [100, 1000]   # packets_total BETWEEN 100 AND 1000
```

---

## 10. Производительность и ограничения

1. **Sigma-правила** выполняются как прямые SQL-запросы к `network_flows`. Поскольку ClickHouse хранит данные колоночно и поддерживает индексацию по `ORDER BY`, запросы эффективны на объёмах до десятков миллионов строк.

2. **Поведенческие детекторы** ограничены по числу строк, подаваемых в ML:
   - Максимум 20 000 строк для оконных агрегатов
   - Максимум 15 000 строк для парных агрегатов
   При превышении выборка ужимается по activity_score.

3. **DBSCAN** использует `eps` на основе 95-го перцентиля kNN-расстояний, что делает его адаптивным к плотности данных.

4. **Isolation Forest** обучен на 200 деревьев с параметром `sample_size = min(n, 256)`.

5. Все агрегаты считаются на лету в ClickHouse, ML-модели обучаются в памяти R-процесса. При очень больших данных (>100 млн flow-записей) рекомендуется увеличить лимиты `max_window_ml_rows` / `max_pair_ml_rows` в коде `behavioral_detectors.R`.

---

## 11. Интерпретация результатов

При анализе сработок полезно учитывать несколько факторов:

- **Соотношение signature/behavioral**: преобладание сигнатурных сработок говорит о том, что трафик содержит известные паттерны (brute force, сканирование, C2-порты). Преобладание поведенческих — о сложных аномалиях, не описываемых простыми правилами.

- **Confidence score в behavioral-сработках**: ensemble_score ≥ 0.90 означает консенсус всех трёх алгоритмов (DBSCAN, LOF, Isolation Forest). Score 0.80–0.90 — согласие двух из трёх.

- **Корреляция сработок**: если один и тот же `src_ip` порождает одновременно SSH Brute Force (signature) + Vertical Port Scan (behavioral) + TTL Spoofing — это сильный индикатор атакующего.
- **Поле `description` в `analysis_detections`** содержит человекочитаемое описание и может использоваться для быстрого триажа в UI.

---

## Инкрементальный анализ и идемпотентность ETL

### Контекст изменений

В последних обновлениях проекта два ключевых модуля получили механизмы, позволяющие избегать повторной обработки уже загруженных данных:

- **ETL** научился пропускать объекты, которые уже были успешно загружены в предыдущем запуске — идентификация по `ETag` объекта в S3 или по `object_size` как fallback.
- **Analysis** научился анализировать только те `source_key`, которые были загружены ETL после последнего завершённого прогона анализа — инкрементальный режим через `pending_source_keys`.

Оба изменения работают независимо, но вместе создают полный цикл: ETL не дублирует строки в `network_flows`, analysis не дублирует сработки в `analysis_detections`.

---

### Идемпотентность ETL: `object_etag`

#### Что изменилось в схеме

В таблицу `etl_objects` добавлено поле `object_etag`:

```sql
ALTER TABLE etl_objects
ADD COLUMN IF NOT EXISTS object_etag String
```

Полная DDL `etl_objects` теперь:

```sql
CREATE TABLE IF NOT EXISTS etl_objects (
  ingest_run_id    String,
  source_key       String,
  source_dataset   LowCardinality(String),
  source_format    LowCardinality(String),
  handler_name     LowCardinality(String),
  object_size      Nullable(UInt64),
  object_etag      String,               -- ← новое поле
  status           LowCardinality(String),
  records_loaded   Nullable(UInt64),
  processed_at     DateTime,
  message          String
) ENGINE = MergeTree()
ORDER BY (processed_at, source_key)
```

`object_etag` заполняется из метаданных S3-объекта при листинге бакета. Для локальных файлов (`LOCAL_DATA_DIR`) ETag недоступен — в этом случае поле остаётся пустой строкой.

#### Логика проверки дублей

Функция `is_source_object_loaded()` проверяет, был ли объект уже успешно загружен, до того как ETL скачивает его и запускает handler:

```
Если object_etag непустой:
    SELECT count() FROM etl_objects
    WHERE source_key = <key>
      AND status = 'loaded'
      AND object_etag = <etag>

Если object_etag пустой (локальный файл):
    SELECT count() FROM etl_objects
    WHERE source_key = <key>
      AND status = 'loaded'
      AND ifNull(object_size, 0) = <size>
```

Если count > 0 — объект скипается, в `etl_objects` пишется запись со `status = 'skipped'` и `handler_name = 'already_loaded'`.

#### Поведение при повторном `docker compose up etl-init`

**Первый запуск:**

```
[INFO] Discovered 4 object(s) in bucket
[INFO] Processing dataset/unsw-nb15/part1.csv with handler csv
[INFO] Inserted 82002 row(s) into network_flows
[INFO] Processing dataset/stratosphere/capture.pcap with handler pcap_zeek
[INFO] Inserted 14400 row(s) into network_flows
[INFO] Processing dataset/kyoto/2011.zip with handler zip
[INFO] Inserted 210000 row(s) into network_flows
[INFO] ETL pipeline completed successfully
```

**Повторный запуск (без изменений в бакете):**

```
[INFO] Discovered 4 object(s) in bucket
[INFO] Skipping already loaded object: dataset/unsw-nb15/part1.csv
[INFO] Skipping already loaded object: dataset/stratosphere/capture.pcap
[INFO] Skipping already loaded object: dataset/kyoto/2011.zip
[INFO] ETL pipeline completed successfully
```

Ни одной новой строки в `network_flows`. `etl_objects` получит три новые записи со `status = 'skipped'`.

**Добавление нового объекта в бакет:**

```
[INFO] Discovered 5 object(s) in bucket
[INFO] Skipping already loaded object: dataset/unsw-nb15/part1.csv
[INFO] Skipping already loaded object: dataset/stratosphere/capture.pcap
[INFO] Skipping already loaded object: dataset/kyoto/2011.zip
[INFO] Processing dataset/unsw-nb15/part2.csv with handler csv
[INFO] Inserted 75430 row(s) into network_flows
[INFO] ETL pipeline completed successfully
```

Загружен только новый объект.

#### Как проверить статус объектов

```sql
SELECT
    source_key,
    object_etag,
    status,
    records_loaded,
    processed_at
FROM etl_objects
ORDER BY processed_at DESC
LIMIT 20;
```

Или только по статусам:

```sql
SELECT status, count() AS cnt
FROM etl_objects
GROUP BY status
ORDER BY cnt DESC;
```

Типичный результат после нескольких запусков:

| status | cnt |
|---|---|
| loaded | 4 |
| skipped | 8 |
| failed | 0 |

---

### Инкрементальный анализ: `pending_source_keys`

#### Проблема, которую решает механизм

До этого изменения `analysis` при каждом запуске сканировал **всю** таблицу `network_flows`. Если ETL добавил 50 000 новых строк к существующим 2 млн — `analysis` прогонял все 2 млн через каждое Sigma-правило и все поведенческие детекторы. Это создавало:

- дублирование сработок (одни и те же потоки детектировались повторно);
- избыточную нагрузку на ClickHouse;
- некорректное поле `flow_rows_scanned` в `analysis_runs`.

#### Как работает `fetch_pending_source_keys()`

При старте `run_analysis_pipeline()` вызывается `fetch_pending_source_keys()`:

```
1. Получить время последнего завершённого analysis_run:
   SELECT max(finished_at) FROM analysis_runs WHERE status = 'completed'

2. Если завершённых runs нет → вернуть все source_key из etl_objects WHERE status = 'loaded'

3. Если есть → вернуть только те source_key, у которых processed_at > max(finished_at)
   SELECT DISTINCT source_key FROM etl_objects
   WHERE status = 'loaded'
     AND processed_at > <last_finished_at>
```

Результат — список `pending_source_keys`: строки `source_key`, которые ещё не анализировались.

#### Влияние на Sigma-анализ

`run_signature_analysis()` теперь принимает `source_keys` и передаёт их в `build_source_key_clause()`. Каждый SQL-запрос правила получает дополнительный предикат:

```sql
-- Было:
SELECT * FROM network_flows
WHERE (transport_proto = 'TCP' AND dst_port = 22)
  AND (flow_state IN ('INT', 'REQ', 'RST'))

-- Стало:
SELECT * FROM network_flows
WHERE (transport_proto = 'TCP' AND dst_port = 22)
  AND (flow_state IN ('INT', 'REQ', 'RST'))
  AND source_key IN ('dataset/unsw-nb15/part2.csv')
```

Таким образом, правила физически не видят уже проанализированные потоки.

#### Влияние на поведенческий анализ

Аналогично `fetch_src_window_features()` и `fetch_src_dst_features()` получили параметр `source_keys`. Оконные агрегаты строятся только по новым объектам:

```sql
SELECT
  toStartOfInterval(flow_start, toIntervalMinute(5)) AS window_start,
  src_ip,
  transport_proto,
  count() AS flow_count,
  ...
FROM network_flows
WHERE flow_start IS NOT NULL
  AND src_ip != ''
  AND transport_proto = 'TCP'
  AND source_key IN ('dataset/unsw-nb15/part2.csv')  -- ← фильтр
GROUP BY window_start, src_ip, transport_proto
```

#### Поведение когда нечего анализировать

Если `pending_source_keys` пустой (все объекты уже проанализированы), `analysis` завершается досрочно без запуска Sigma и поведенческих детекторов:

```
[INFO] Analysis skipped: no new ETL objects found
```

В `analysis_runs` записывается:

| status | detections_total | message |
|---|---|---|
| completed | 0 | No new ETL objects found for analysis |

#### `flow_rows_scanned` теперь отражает реальный охват

Поле `flow_rows_scanned` в `analysis_runs` раньше было `SELECT count() FROM network_flows` — т.е. всегда полный размер таблицы. Теперь это `fetch_flow_count_for_source_keys(conn, pending_source_keys)`:

```sql
SELECT count() AS cnt
FROM network_flows
WHERE source_key IN (<pending_source_keys>)
```

Значение показывает именно то количество flow-записей, которое было обработано в данном конкретном прогоне.

---

### Новые фильтры в UI

#### Фильтрация сработок по источнику данных

Вкладка «Сработки» получила три новых фильтра:

| Фильтр | Тип | Описание |
|---|---|---|
| Source Format | Мультиселект | `pcap`, `csv`, `binetflow` — формат исходного файла |
| Source Dataset | Мультиселект | `UNSW-NB15`, `Stratosphere IPS`, `Kyoto 2006+` |
| Source Key Pattern | Текстовое поле | Подстрока из `source_key` (case-insensitive) |

Фильтры работают через JOIN `analysis_detection_events` → `network_flows`, потому что сама таблица `analysis_detections` не хранит provenance-поля напрямую. Subquery `build_detection_sources_subquery()` агрегирует уникальные значения `source_dataset`, `source_format`, `source_key`, `source_file_name` по каждому `detection_id`:

```sql
SELECT
  e.detection_id AS detection_id,
  arrayStringConcat(arraySort(groupUniqArray(
    ifNull(f.source_dataset, e.source_dataset)
  )), ', ') AS source_dataset,
  arrayStringConcat(arraySort(groupUniqArray(
    ifNull(f.source_format, '')
  )), ', ') AS source_format,
  arrayStringConcat(arraySort(groupUniqArray(
    ifNull(f.source_key, e.source_key)
  )), ', ') AS source_key,
  arrayStringConcat(arraySort(groupUniqArray(
    ifNull(f.source_file_name, '')
  )), ', ') AS source_file_name
FROM analysis_detection_events e
LEFT JOIN network_flows f ON f.event_id = e.event_id
GROUP BY e.detection_id
```

Результат — строка вида `"UNSW-NB15, Kyoto 2006+"` для сработки, которая захватила потоки из двух датасетов одновременно.

#### Фильтрация по дате: исправленное поведение

До изменений `date_from` и `date_to` форматировались хардкодом с `00:00:00` и `23:59:59`. Теперь `format_time_bound()` корректно обрабатывает как `Date`, так и `POSIXct`:

- Если передан `Date` — добавляет `00:00:00` для `date_from` и `23:59:59` для `date_to`
- Если передан `POSIXct` — использует точное время без усечения

Это позволяет UI фильтровать с точностью до секунды при работе с дашбордом в реальном времени.

---

### Полная картина жизненного цикла объекта

```
S3 / local_data
      │
      ▼
list_s3_objects() / list_local_objects()
      │ возвращает source_object{ key, size, etag, dataset, extension }
      ▼
is_source_object_loaded(conn, source_object)
      │ TRUE  → запись status='skipped' в etl_objects, пропуск
      │ FALSE ↓
      ▼
choose_handler(key) → pcap_zeek | binetflow | csv | zip
      │
      ▼
parse_*(path, source_object, ingest_run_id)
      │ возвращает data.frame network_flows
      ▼
insert_network_flows(conn, flows)
      │ строки в network_flows с source_key = <key>
      ▼
insert_etl_object_status(..., status='loaded', object_etag=<etag>)
      │
      ╔═══════════════════════╗
      ║  etl_objects          ║
      ║  status='loaded'      ║
      ║  object_etag=<etag>   ║
      ╚═══════════════════════╝
```

После завершения ETL:

```
fetch_pending_source_keys(conn)
      │ смотрит max(finished_at) из analysis_runs WHERE status='completed'
      │ возвращает source_key из etl_objects WHERE processed_at > last_finished
      ▼
run_signature_analysis(conn, ..., source_keys=pending)
run_behavioral_analysis(conn, ..., source_keys=pending)
      │
      ▼
analysis_detections   ← сработки только по новым source_key
analysis_detection_events ← привязка event_id к detection_id
      │
      ▼
finish_analysis_run(conn, ..., status='completed')
      │ обновляет finished_at → станет новым порогом для следующего запуска
```

---

### Как убедиться, что инкрементальность работает корректно

**1. Проверить pending_source_keys вручную:**

```sql
-- Время последнего завершённого analysis
SELECT max(finished_at) AS last_analysis
FROM analysis_runs
WHERE status = 'completed';

-- Объекты, загруженные после него
SELECT source_key, processed_at
FROM etl_objects
WHERE status = 'loaded'
  AND processed_at > (
    SELECT max(finished_at)
    FROM analysis_runs
    WHERE status = 'completed'
  )
ORDER BY processed_at;
```

Если запрос возвращает пустой результат — следующий запуск `analysis` завершится со статусом `completed` и `detections_total = 0`.

**2. Проверить, что сработки не дублируются:**

```sql
SELECT
    rule_id,
    src_ip,
    count() AS detection_count
FROM analysis_detections
GROUP BY rule_id, src_ip
HAVING detection_count > 1
ORDER BY detection_count DESC
LIMIT 20;
```

При корректной инкрементальности одна и та же пара `(rule_id, src_ip)` не должна появляться более одного раза для одного и того же `source_key`. Если дубли есть — скорее всего, `analysis_runs` не содержит завершённой записи с корректным `finished_at`.

**3. Проверить `flow_rows_scanned` в `analysis_runs`:**

```sql
SELECT
    analysis_run_id,
    started_at,
    status,
    flow_rows_scanned,
    detections_total,
    message
FROM analysis_runs
ORDER BY started_at DESC
LIMIT 5;
```

`flow_rows_scanned` должен совпадать с суммой `records_loaded` из `etl_objects` для соответствующих `pending_source_keys`, а не с полным `count()` таблицы `network_flows`.

---

### Обновлённая схема `etl_objects`

Полный список полей с описанием:

| Поле | Тип | Описание |
|---|---|---|
| `ingest_run_id` | String | UUID прогона ETL, в котором был обработан объект |
| `source_key` | String | S3-ключ или путь к локальному файлу |
| `source_dataset` | LowCardinality(String) | Имя датасета: `UNSW-NB15`, `Stratosphere IPS`, `Kyoto 2006+` |
| `source_format` | LowCardinality(String) | Формат: `pcap`, `csv`, `binetflow`, `zip` |
| `handler_name` | LowCardinality(String) | Имя handler-функции: `pcap_zeek`, `csv_unsw_nb15`, `binetflow`, `zip`, `already_loaded`, `unsupported` |
| `object_size` | Nullable(UInt64) | Размер объекта в байтах из S3-метаданных |
| `object_etag` | String | ETag из S3 (MD5 или multipart hash); пустая строка для локальных файлов |
| `status` | LowCardinality(String) | `loaded` / `skipped` / `failed` |
| `records_loaded` | Nullable(UInt64) | Количество строк, записанных в `network_flows` |
| `processed_at` | DateTime | Время записи статуса |
| `message` | String | Сообщение об ошибке или причине skip |

#### Значения `handler_name`

| Значение | Когда выставляется |
|---|---|
| `pcap_zeek` | PCAP/PCAPNG, обработан через Zeek `conn.log` |
| `csv_unsw_nb15` | CSV с заголовком UNSW-NB15 или без заголовка с нужным числом колонок |
| `binetflow` | BiNetFlow (argus-формат) |
| `zip` | ZIP-архив с вложенными файлами (Kyoto 2006+) |
| `already_loaded` | Объект уже загружен в предыдущем прогоне (идемпотентность) |
| `unsupported` | Расширение файла не распознано |

---

### Обновлённая схема `analysis_runs`

Поле `flow_rows_scanned` изменило семантику:

| Поле | Было | Стало |
|---|---|---|
| `flow_rows_scanned` | `SELECT count() FROM network_flows` — всегда полный размер таблицы | `SELECT count() FROM network_flows WHERE source_key IN (<pending>)` — только новые объекты |
| `message` | Всегда пустая строка | Заполняется при skip (`"No new ETL objects found for analysis"`) или ошибке |

Поле `message` теперь используется для двух случаев:
- `"No new ETL objects found for analysis"` — нет новых объектов, анализ пропущен
- Текст исключения — при падении `run_analysis_pipeline()` в `on.exit` обработчике

---

### FAQ

**Q: ETL завершился успешно, но `analysis` говорит "no new source objects". Почему?**

A: `analysis` смотрит на `processed_at` в `etl_objects`. Если время завершения последнего `analysis_run` (`finished_at`) новее, чем `processed_at` всех загруженных объектов — pending-список пуст. Убедитесь, что ETL-прогон действительно добавил новые объекты:

```sql
SELECT source_key, processed_at, status
FROM etl_objects
ORDER BY processed_at DESC
LIMIT 5;
```

**Q: Хочу переанализировать все данные с нуля. Как?**

A: Удалите все записи из `analysis_runs` и `analysis_detections`:

```sql
TRUNCATE TABLE analysis_detections;
TRUNCATE TABLE analysis_detection_events;
TRUNCATE TABLE analysis_runs;
```

После этого следующий запуск `analysis` воспримет все `etl_objects` со `status = 'loaded'` как pending и проанализирует полный объём `network_flows`.

**Q: Можно ли принудительно запустить анализ для конкретного `source_key`?**

A: Напрямую через переменные окружения — нет. Workaround: удалить запись из `analysis_runs` для нужного временного диапазона или временно выставить `finished_at` заведомо раньше `processed_at` нужного объекта:

```sql
-- Сдвинуть finished_at последнего run назад
ALTER TABLE analysis_runs UPDATE
  finished_at = toDateTime('2000-01-01 00:00:00')
WHERE analysis_run_id = '<run_id>';
```

После этого `fetch_pending_source_keys()` вернёт нужные объекты.

**Q: ETag объекта в S3 изменился (файл был заменён). ETL загрузит новую версию?**

A: Да. `is_source_object_loaded()` при наличии ETag проверяет точное совпадение `object_etag`. Если ETag изменился — объект считается новым и загружается заново. Это приведёт к дублированию строк в `network_flows` если старые строки не были удалены — учитывайте при замене файлов в бакете.

**Q: Как мониторить прогресс ETL в реальном времени?**

Следите за логами контейнера:

```bash
docker compose logs -f etl-init
```

Параллельно можно смотреть на накопление строк в ClickHouse:

```bash
watch -n 2 'docker compose exec clickhouse clickhouse-client \
  --user $CLICKHOUSE_USER --password $CLICKHOUSE_PASSWORD \
  --database $CLICKHOUSE_DATABASE \
  --query "SELECT count() FROM network_flows"'
```

