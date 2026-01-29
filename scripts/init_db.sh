#!/usr/bin/env bash
set -euo pipefail

HOST="${DB_HOST:-${1:-}}"
PORT="${DB_PORT:-${2:-3306}}"
USER="${DB_USER:-${3:-}}"
PASS="${DB_PASSWORD:-${4:-}}"
DB="${DB_NAME:-${5:-}}"

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCHEMA_DIR}/schema.sql"

if [[ -z "${HOST}" || -z "${USER}" || -z "${DB}" ]]; then
  echo "Missing DB_HOST, DB_USER, or DB_NAME (or pass args)." >&2
  exit 1
fi

if [[ ! -f "${SCHEMA_FILE}" ]]; then
  echo "schema.sql not found at ${SCHEMA_FILE}" >&2
  exit 1
fi

MYSQL_PWD="${PASS}" mysql --host "${HOST}" --port "${PORT}" --user "${USER}" "${DB}" < "${SCHEMA_FILE}"
