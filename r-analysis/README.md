# R Analysis Container

Модуль анализа на `R`, который работает поверх уже загруженной таблицы
`network_flows` в `ClickHouse`.

## Что делает

- выполняет сигнатурный анализ по Sigma-подобным YAML-правилам
- выполняет поведенческий анализ по TCP-потокам
- использует консервативные условия с приоритетом на снижение фолзов
- сохраняет summary-сработки и связь с исходными flow-записями в `ClickHouse`

## Сигнатурный анализ

- правила лежат в `rules/signature`
- формат правил — Sigma-подобный YAML
- матчинг выполняется по unified flow-полям

## Поведенческий анализ

Агрегации:

- `src_ip` + временное окно
- `src_ip -> dst_ip:dst_port`

Алгоритмы:

- `DBSCAN`
- `LOF`
- `Isolation Forest`

Текущие детекторы:

- vertical port scan
- horizontal host scan
- HTTP brute force / directory fuzzing candidate
- SMB brute force candidate
- long-lived C2 session candidate

## Таблицы

- `analysis_runs`
- `analysis_detections`
- `analysis_detection_events`

## Запуск

```bash
cd ..
cp .env.example .env
docker compose up --build analysis
```
