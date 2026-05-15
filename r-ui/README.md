# R UI (Shiny)

Веб-интерфейс на `R Shiny` поверх `ClickHouse` той же `docker-compose`-сети.

## Что внутри

- **Обзор** — KPI, разбивка сработок по severity, потоки по дням, последние ETL-объекты и analysis-раны
- **Сработки** — таблица `analysis_detections` с фильтрами по `detector_type`, `severity`, `src_ip`, `dst_ip`, периоду
- **Детализация** — клик по сработке → связанные строки `analysis_detection_events` → сырая запись из `network_flows`
- **Действия** — кнопки запуска `etl-init` и `analysis` через `docker compose run --rm` + хвост лога

## Запуск

```bash
cd ..
cp .env.example .env
docker compose up --build ui
```

UI доступен на `http://localhost:3838` (или `UI_PORT` из `.env`).

## Как работает запуск контейнеров

UI вызывает `docker compose run --rm <service>` через docker CLI внутри контейнера.
Для этого:

- в контейнер монтируется `/var/run/docker.sock`
- корень репозитория монтируется в `/compose` только для чтения
- активные job-процессы регистрируются через `processx`, лог пишется в `/tmp/r-ui-jobs/`

**Важно:** монтирование `docker.sock` фактически даёт `root` на хосте. Это
приемлемо для локального / учебного запуска, но не для прода.

## Переменные окружения

- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE`
- `COMPOSE_PROJECT_DIR` — путь к корню репозитория внутри контейнера (по умолчанию `/compose`)
- `COMPOSE_PROJECT_NAME` — имя docker-compose проекта (по умолчанию `rproject-ng`)
- `UI_PORT` — порт хоста для проброса (по умолчанию `3838`)
