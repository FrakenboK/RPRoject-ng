#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

COMPOSE_CMD=(docker compose)

log() {
  printf '[run.sh] %s\n' "$*"
}

fail() {
  printf '[run.sh] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Не найдена команда: $1"
}

wait_for_clickhouse() {
  local container_id
  local status
  local attempt
  local max_attempts=60

  container_id="$("${COMPOSE_CMD[@]}" ps -q clickhouse)"
  [[ -n "$container_id" ]] || fail "Не удалось получить container id для clickhouse"

  for attempt in $(seq 1 "$max_attempts"); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      log "clickhouse healthy"
      return 0
    fi

    log "Ожидание clickhouse: попытка ${attempt}/${max_attempts}, статус=${status:-unknown}"
    sleep 2
  done

  fail "clickhouse не перешел в состояние healthy"
}

require_command docker

"${COMPOSE_CMD[@]}" version >/dev/null 2>&1 || fail "Команда 'docker compose' недоступна"
[[ -f .env ]] || fail "Файл .env не найден"
[[ -f docker-compose.yml ]] || fail "Файл docker-compose.yml не найден"

log "Сборка образов приложения"
"${COMPOSE_CMD[@]}" build etl-init analysis ui

log "Запуск clickhouse"
"${COMPOSE_CMD[@]}" up -d clickhouse
wait_for_clickhouse

log "Запуск ETL"
"${COMPOSE_CMD[@]}" run --rm etl-init

log "Запуск анализа"
"${COMPOSE_CMD[@]}" run --rm analysis

log "Запуск UI"
"${COMPOSE_CMD[@]}" up -d ui

log "Итоговый статус сервисов"
"${COMPOSE_CMD[@]}" ps

ui_port="${UI_PORT:-3838}"
log "Готово. UI должен быть доступен на http://localhost:${ui_port}"
