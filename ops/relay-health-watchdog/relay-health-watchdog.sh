#!/usr/bin/env bash
#
# Read-only external safety check for the codex2api Relay guardian stack.
# The script intentionally has no account-management, restart, or database-write
# operations. Every output line is a JSON object suitable for journald ingestion.

set -uo pipefail

readonly COMPONENT="codex2api-relay-health-watchdog"
readonly HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8090/health}"
readonly LOCK_FILE="${LOCK_FILE:-/run/codex2api-relay-health-watchdog.lock}"
readonly CODEX_CONTAINER="${CODEX_CONTAINER:-codex2api}"
readonly POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-codex2api-postgres}"
readonly REDIS_CONTAINER="${REDIS_CONTAINER:-codex2api-redis}"
readonly SUB2_CONTAINER="${SUB2_CONTAINER:-sub2api}"
readonly SUB2_POSTGRES_CONTAINER="${SUB2_POSTGRES_CONTAINER:-sub2api-postgres}"
readonly BRIDGE_ACCOUNT_ID="${BRIDGE_ACCOUNT_ID:-7692}"
readonly CURL_BIN="${CURL_BIN:-curl}"
readonly DOCKER_BIN="${DOCKER_BIN:-docker}"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"
readonly FLOCK_BIN="${FLOCK_BIN:-flock}"

exit_code=0
checks_ok=0
checks_skipped=0
checks_degraded=0
checks_critical=0

json_escape() {
  local value="${1-}"
  local char
  local escaped
  local code
  local out=""
  local i
  local LC_ALL=C

  # Bash variables cannot contain NUL. Escape every other JSON C0 control byte
  # generically instead of relying on a partial newline/tab replacement list.
  for ((i = 0; i < ${#value}; i++)); do
    char="${value:i:1}"
    case "$char" in
      '"')
        out+='\"'
        ;;
      \\)
        out+='\\'
        ;;
      *)
        printf -v code '%d' "'$char"
        if (( code < 32 )); then
          printf -v escaped '\\u%04x' "$code"
          out+="$escaped"
        else
          out+="$char"
        fi
        ;;
    esac
  done

  printf '%s' "$out"
}

json_quote() {
  printf '"%s"' "$(json_escape "${1-}")"
}

emit_event() {
  local check="$1"
  local status="$2"
  local message="$3"
  local details="${4-}"
  if [[ -z "$details" ]]; then
    details='{}'
  fi
  printf '{"timestamp":%s,"component":%s,"check":%s,"status":%s,"message":%s,"details":%s}\n' \
    "$(json_quote "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')")" \
    "$(json_quote "$COMPONENT")" \
    "$(json_quote "$check")" \
    "$(json_quote "$status")" \
    "$(json_quote "$message")" \
    "$details"
}

record_event() {
  local check="$1"
  local status="$2"
  local message="$3"
  local details="${4-}"
  if [[ -z "$details" ]]; then
    details='{}'
  fi

  case "$status" in
    ok)
      checks_ok=$((checks_ok + 1))
      ;;
    skipped)
      checks_skipped=$((checks_skipped + 1))
      ;;
    degraded)
      checks_degraded=$((checks_degraded + 1))
      if (( exit_code < 1 )); then
        exit_code=1
      fi
      ;;
    critical)
      checks_critical=$((checks_critical + 1))
      if (( exit_code < 2 )); then
        exit_code=2
      fi
      ;;
  esac

  emit_event "$check" "$status" "$message" "$details"
}

emit_summary() {
  local final_code="${1:-$exit_code}"
  local message="${2:-check_complete}"
  local summary_status="ok"
  if (( final_code == 1 )); then
    summary_status="degraded"
  elif (( final_code >= 2 )); then
    summary_status="critical"
  fi

  emit_event "summary" "$summary_status" "$message" \
    "$(printf '{"exit_code":%s,"checks_ok":%s,"checks_skipped":%s,"checks_degraded":%s,"checks_critical":%s}' \
      "$(json_quote "$final_code")" "$(json_quote "$checks_ok")" \
      "$(json_quote "$checks_skipped")" "$(json_quote "$checks_degraded")" \
      "$(json_quote "$checks_critical")")"
}

finish_with_summary() {
  local final_code="$1"
  local message="${2:-check_complete}"
  exit_code="$final_code"
  emit_summary "$final_code" "$message"
  exit "$final_code"
}

command_exists() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]]
  else
    command -v "$candidate" >/dev/null 2>&1
  fi
}

for dependency in "$CURL_BIN" "$DOCKER_BIN" "$PYTHON_BIN" "$FLOCK_BIN"; do
  if ! command_exists "$dependency"; then
    record_event "bootstrap" "critical" "required_command_missing" \
      "$(printf '{"command":%s}' "$(json_quote "$dependency")")"
    finish_with_summary 3 "bootstrap_failed"
  fi
done

if [[ ! "$BRIDGE_ACCOUNT_ID" =~ ^[0-9]+$ ]]; then
  record_event "bootstrap" "critical" "bridge_account_id_must_be_numeric" \
    "$(printf '{"account_id":%s}' "$(json_quote "$BRIDGE_ACCOUNT_ID")")"
  finish_with_summary 3 "bootstrap_failed"
fi

HEALTH_LOG_ENDPOINT="$("$PYTHON_BIN" -c '
from urllib.parse import urlsplit
import sys

try:
    parsed = urlsplit(sys.argv[1])
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    port = parsed.port
    authority = host + ((":" + str(port)) if port is not None else "")
    path = parsed.path or "/"
    print((authority + path) if authority else "configured-health-endpoint")
except Exception:
    print("configured-health-endpoint")
' "$HEALTH_URL" 2>/dev/null)"
if [[ -z "$HEALTH_LOG_ENDPOINT" ]]; then
  HEALTH_LOG_ENDPOINT="configured-health-endpoint"
fi
readonly HEALTH_LOG_ENDPOINT

if ! { exec 9>"$LOCK_FILE"; } 2>/dev/null; then
  record_event "lock" "critical" "lock_file_open_failed" \
    "$(printf '{"path":%s}' "$(json_quote "$LOCK_FILE")")"
  finish_with_summary 3 "lock_failed"
fi

if ! "$FLOCK_BIN" --nonblock 9; then
  record_event "lock" "skipped" "already_running" \
    "$(printf '{"path":%s}' "$(json_quote "$LOCK_FILE")")"
  finish_with_summary 0 "overlap_skipped"
fi

check_container() {
  local name="$1"
  local require_health="$2"
  local output
  local rc
  local state
  local restarting
  local restart_count
  local health

  output="$("$DOCKER_BIN" inspect --format \
    '{{.State.Status}}|{{.State.Restarting}}|{{.RestartCount}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$name" 2>&1)"
  rc=$?
  if (( rc != 0 )); then
    record_event "container" "critical" "inspect_failed" \
      "$(printf '{"name":%s}' "$(json_quote "$name")")"
    return
  fi

  IFS='|' read -r state restarting restart_count health <<< "$output"
  local details
  details="$(printf '{"name":%s,"state":%s,"restarting":%s,"restart_count":%s,"health":%s}' \
    "$(json_quote "$name")" "$(json_quote "$state")" "$(json_quote "$restarting")" \
    "$(json_quote "$restart_count")" "$(json_quote "$health")")"

  if [[ "$state" != "running" || "$restarting" == "true" ]]; then
    record_event "container" "critical" "container_not_stably_running" "$details"
  elif [[ "$require_health" == "true" && "$health" != "healthy" ]]; then
    record_event "container" "critical" "container_healthcheck_failed" "$details"
  else
    record_event "container" "ok" "container_running" "$details"
  fi
}

check_container "$CODEX_CONTAINER" "false"
check_container "$POSTGRES_CONTAINER" "true"
check_container "$REDIS_CONTAINER" "true"
check_container "$SUB2_CONTAINER" "true"
check_container "$SUB2_POSTGRES_CONTAINER" "true"

if "$DOCKER_BIN" exec "$POSTGRES_CONTAINER" sh -lc \
  'exec pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
  record_event "postgres" "ok" "postgres_reachable" \
    "$(printf '{"container":%s}' "$(json_quote "$POSTGRES_CONTAINER")")"
else
  record_event "postgres" "critical" "postgres_unreachable" \
    "$(printf '{"container":%s}' "$(json_quote "$POSTGRES_CONTAINER")")"
fi

redis_ping="$("$DOCKER_BIN" exec "$REDIS_CONTAINER" redis-cli --raw ping 2>&1)"
redis_rc=$?
if [[ "$redis_ping" == "PONG" ]]; then
  record_event "redis" "ok" "redis_reachable" \
    "$(printf '{"container":%s,"authentication":%s}' \
      "$(json_quote "$REDIS_CONTAINER")" "$(json_quote "not_required")")"
elif [[ "$redis_ping" == *"NOAUTH"* ]]; then
  # An unauthenticated NOAUTH reply proves the local Redis server is reachable
  # without making the watchdog read or carry the Redis password.
  record_event "redis" "ok" "redis_reachable_auth_required" \
    "$(printf '{"container":%s,"authentication":%s}' \
      "$(json_quote "$REDIS_CONTAINER")" "$(json_quote "required_not_read")")"
else
  record_event "redis" "critical" "redis_unreachable" \
    "$(printf '{"container":%s,"command_exit":%s}' \
      "$(json_quote "$REDIS_CONTAINER")" "$(json_quote "$redis_rc")")"
fi

health_ok=false
health_status="__missing__"
health_available="__missing__"
health_total="__missing__"
guardian_enabled="__missing__"
guardian_mode="__missing__"
guardian_status="__missing__"
guardian_heartbeat="__missing__"
guardian_interval="__missing__"
relay_configured="__missing__"
relay_enabled="__missing__"
relay_schedulable="__missing__"
relay_quarantined="__missing__"
relay_probation="__missing__"

health_body="$("$CURL_BIN" --fail --silent --show-error --max-time 5 "$HEALTH_URL" 2>&1)"
health_rc=$?
if (( health_rc != 0 )); then
  record_event "http_health" "critical" "health_endpoint_unreachable" \
    "$(printf '{"endpoint":%s,"command_exit":%s}' \
      "$(json_quote "$HEALTH_LOG_ENDPOINT")" "$(json_quote "$health_rc")")"
else
  health_parsed="$(printf '%s' "$health_body" | "$PYTHON_BIN" -c '
import json
import sys

payload = json.load(sys.stdin)
paths = (
    ("status",),
    ("available",),
    ("total",),
    ("guardian", "enabled"),
    ("guardian", "mode"),
    ("guardian", "status"),
    ("guardian", "heartbeat_at"),
    ("guardian", "scan_interval_seconds"),
    ("relay", "configured"),
    ("relay", "enabled"),
    ("relay", "schedulable"),
    ("relay", "quarantined"),
    ("relay", "probation"),
)

for path in paths:
    value = payload
    for key in path:
        if not isinstance(value, dict) or key not in value:
            value = "__missing__"
            break
        value = value[key]
    if value is None:
        value = "__missing__"
    elif isinstance(value, bool):
        value = "true" if value else "false"
    print(value)
' 2>/dev/null)"
  parse_rc=$?
  if (( parse_rc != 0 )); then
    record_event "http_health" "critical" "health_payload_invalid_json" \
      "$(printf '{"endpoint":%s}' "$(json_quote "$HEALTH_LOG_ENDPOINT")")"
  else
    mapfile -t health_fields <<< "$health_parsed"
    if (( ${#health_fields[@]} < 13 )); then
      record_event "http_health" "critical" "health_payload_incomplete_parse" \
        "$(printf '{"endpoint":%s}' "$(json_quote "$HEALTH_LOG_ENDPOINT")")"
    else
      health_ok=true
      health_status="${health_fields[0]}"
      health_available="${health_fields[1]}"
      health_total="${health_fields[2]}"
      guardian_enabled="${health_fields[3]}"
      guardian_mode="${health_fields[4]}"
      guardian_status="${health_fields[5]}"
      guardian_heartbeat="${health_fields[6]}"
      guardian_interval="${health_fields[7]}"
      relay_configured="${health_fields[8]}"
      relay_enabled="${health_fields[9]}"
      relay_schedulable="${health_fields[10]}"
      relay_quarantined="${health_fields[11]}"
      relay_probation="${health_fields[12]}"

      health_details="$(printf '{"endpoint":%s,"service_status":%s,"available":%s,"total":%s}' \
        "$(json_quote "$HEALTH_LOG_ENDPOINT")" "$(json_quote "$health_status")" \
        "$(json_quote "$health_available")" "$(json_quote "$health_total")")"

      if [[ "$health_status" != "ok" ]]; then
        record_event "http_health" "critical" "service_health_not_ok" "$health_details"
      elif [[ ! "$health_available" =~ ^[0-9]+$ || ! "$health_total" =~ ^[0-9]+$ ]]; then
        record_event "http_health" "degraded" "account_counts_invalid" "$health_details"
      elif (( health_available == 0 )); then
        record_event "http_health" "critical" "no_available_accounts" "$health_details"
      else
        record_event "http_health" "ok" "service_health_ok" "$health_details"
      fi
    fi
  fi
fi

if [[ "$health_ok" == "true" && "$guardian_enabled" != "__missing__" ]]; then
  guardian_event_status="ok"
  guardian_message="guardian_healthy"
  heartbeat_age="__missing__"

  if [[ "$guardian_enabled" == "true" ]]; then
    if [[ "$guardian_status" != "ok" ]]; then
      guardian_event_status="degraded"
      guardian_message="guardian_status_not_ok"
    fi

    if [[ "$guardian_heartbeat" == "__missing__" ]]; then
      guardian_event_status="degraded"
      guardian_message="guardian_heartbeat_missing"
    else
      heartbeat_age="$("$PYTHON_BIN" -c '
from datetime import datetime, timezone
import re
import sys

raw = sys.argv[1].strip()
# Go emits RFC3339Nano timestamps with up to nine fractional digits, while
# Python 3.10 accepts at most six. Truncate only the excess precision.
raw = re.sub(r"(\.\d{6})\d+(?=(?:Z|[+-]\d{2}:\d{2})$)", r"\1", raw)
if raw.endswith("Z"):
    raw = raw[:-1] + "+00:00"
stamp = datetime.fromisoformat(raw)
if stamp.tzinfo is None:
    stamp = stamp.replace(tzinfo=timezone.utc)
print(int((datetime.now(timezone.utc) - stamp.astimezone(timezone.utc)).total_seconds()))
' "$guardian_heartbeat" 2>/dev/null)"
      heartbeat_rc=$?
      if (( heartbeat_rc != 0 )) || [[ ! "$heartbeat_age" =~ ^-?[0-9]+$ ]]; then
        guardian_event_status="degraded"
        guardian_message="guardian_heartbeat_invalid"
        heartbeat_age="__invalid__"
      elif (( heartbeat_age < 0 )); then
        guardian_event_status="degraded"
        guardian_message="guardian_heartbeat_in_future"
      else
        stale_after=180
        if [[ "$guardian_interval" =~ ^[0-9]+$ ]] && (( guardian_interval > 0 )); then
          calculated_stale_after=$((guardian_interval * 3))
          if (( calculated_stale_after > stale_after )); then
            stale_after=$calculated_stale_after
          fi
        fi
        if (( heartbeat_age > stale_after )); then
          guardian_event_status="degraded"
          guardian_message="guardian_heartbeat_stale"
        fi
      fi
    fi
  else
    guardian_message="guardian_disabled"
  fi

  guardian_details="$(printf '{"enabled":%s,"mode":%s,"guardian_status":%s,"heartbeat_at":%s,"heartbeat_age_seconds":%s,"scan_interval_seconds":%s}' \
    "$(json_quote "$guardian_enabled")" "$(json_quote "$guardian_mode")" \
    "$(json_quote "$guardian_status")" "$(json_quote "$guardian_heartbeat")" \
    "$(json_quote "$heartbeat_age")" "$(json_quote "$guardian_interval")")"
  record_event "guardian" "$guardian_event_status" "$guardian_message" "$guardian_details"
else
  record_event "guardian" "skipped" "health_summary_fields_absent" \
    '{"fallback":"service_and_database_checks_only"}'
fi

relay_source="health"
if [[ "$relay_schedulable" == "__missing__" ]]; then
  relay_source="database_fallback"
  relay_query="
WITH relay_group AS (
  SELECT prompt_filter_cyb_relay_group_id AS group_id
  FROM system_settings
  ORDER BY id
  LIMIT 1
),
relay_accounts AS (
  SELECT a.*
  FROM relay_group rg
  JOIN account_group_members gm ON gm.group_id = rg.group_id
  JOIN accounts a ON a.id = gm.account_id
  WHERE LOWER(BTRIM(COALESCE(a.credentials ->> 'upstream_type', ''))) = 'openai_responses'
    AND BTRIM(COALESCE(a.credentials ->> 'base_url', '')) <> ''
    AND BTRIM(COALESCE(a.credentials ->> 'api_key', '')) <> ''
)
SELECT
  COUNT(a.id) FILTER (WHERE a.deleted_at IS NULL),
  COUNT(a.id) FILTER (
    WHERE a.deleted_at IS NULL
      AND COALESCE(a.enabled, FALSE)
  ),
  COUNT(a.id) FILTER (
    WHERE a.deleted_at IS NULL
      AND COALESCE(a.enabled, FALSE)
      AND a.status = 'active'
      AND (a.cooldown_until IS NULL OR a.cooldown_until <= NOW())
  )
FROM relay_accounts a;
"
  relay_counts="$("$DOCKER_BIN" exec "$POSTGRES_CONTAINER" sh -lc \
    'export PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=5000"; exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$1"' \
    sh "$relay_query" 2>/dev/null)"
  relay_query_rc=$?
  if (( relay_query_rc != 0 )); then
    record_event "relay_pool" "degraded" "relay_summary_and_database_fallback_unavailable" \
      '{"source":"database_fallback"}'
  else
    IFS='|' read -r relay_configured relay_enabled relay_schedulable <<< "$relay_counts"
  fi
fi

if [[ "$relay_schedulable" != "__missing__" ]]; then
  relay_details="$(printf '{"source":%s,"configured":%s,"enabled":%s,"schedulable":%s,"quarantined":%s,"probation":%s}' \
    "$(json_quote "$relay_source")" "$(json_quote "$relay_configured")" \
    "$(json_quote "$relay_enabled")" "$(json_quote "$relay_schedulable")" \
    "$(json_quote "$relay_quarantined")" "$(json_quote "$relay_probation")")"
  if [[ ! "$relay_schedulable" =~ ^[0-9]+$ ]]; then
    record_event "relay_pool" "degraded" "relay_schedulable_count_invalid" "$relay_details"
  elif (( relay_schedulable == 0 )); then
    record_event "relay_pool" "critical" "no_schedulable_relay_accounts" "$relay_details"
  elif [[ "$relay_source" == "database_fallback" ]]; then
    record_event "relay_pool" "degraded" "live_state_unknown" "$relay_details"
  else
    record_event "relay_pool" "ok" "relay_accounts_schedulable" "$relay_details"
  fi
fi

bridge_query="
SELECT
  id,
  COALESCE(status, ''),
  COALESCE(schedulable, FALSE),
  (deleted_at IS NULL)
FROM accounts
WHERE id = ${BRIDGE_ACCOUNT_ID}
LIMIT 1;
"
bridge_row="$("$DOCKER_BIN" exec "$SUB2_POSTGRES_CONTAINER" sh -lc \
  'export PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=5000"; exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$1"' \
  sh "$bridge_query" 2>/dev/null)"
bridge_query_rc=$?
if (( bridge_query_rc != 0 )); then
  record_event "bridge_account" "critical" "bridge_state_query_failed" \
    "$(printf '{"account_id":%s}' "$(json_quote "$BRIDGE_ACCOUNT_ID")")"
elif [[ -z "$bridge_row" ]]; then
  record_event "bridge_account" "critical" "bridge_account_missing" \
    "$(printf '{"account_id":%s}' "$(json_quote "$BRIDGE_ACCOUNT_ID")")"
else
  IFS='|' read -r bridge_id bridge_status bridge_schedulable bridge_not_deleted <<< "$bridge_row"
  bridge_details="$(printf '{"account_id":%s,"status":%s,"schedulable":%s,"not_deleted":%s}' \
    "$(json_quote "$bridge_id")" "$(json_quote "$bridge_status")" \
    "$(json_quote "$bridge_schedulable")" "$(json_quote "$bridge_not_deleted")")"
  if [[ "$bridge_status" == "active" && "$bridge_schedulable" == "t" && "$bridge_not_deleted" == "t" ]]; then
    record_event "bridge_account" "ok" "bridge_account_schedulable" "$bridge_details"
  else
    record_event "bridge_account" "critical" "bridge_account_not_schedulable" "$bridge_details"
  fi
fi

finish_with_summary "$exit_code" "check_complete"
