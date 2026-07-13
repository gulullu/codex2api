#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly GROUP_NAME="${GROUP_NAME:-codex-pro}"
readonly BRIDGE_ACCOUNT_ID="${BRIDGE_ACCOUNT_ID:-7692}"
readonly HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8090/health}"
readonly SUB2_ADMIN_BASE_URL="${SUB2_ADMIN_BASE_URL:-http://127.0.0.1:18082}"
readonly SUB2_POSTGRES_CONTAINER="${SUB2_POSTGRES_CONTAINER:-sub2api-postgres}"
readonly SUB2_REDIS_CONTAINER="${SUB2_REDIS_CONTAINER:-sub2api-redis}"
readonly CODEX_POSTGRES_CONTAINER="${CODEX_POSTGRES_CONTAINER:-codex2api-postgres}"
readonly DOCKER_BIN="${DOCKER_BIN:-docker}"
readonly CURL_BIN="${CURL_BIN:-curl}"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"
readonly FLOCK_BIN="${FLOCK_BIN:-flock}"
readonly TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
readonly BACKUP_OPEN_PARALLELISM="${BACKUP_OPEN_PARALLELISM:-4}"
readonly SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS="${SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS:-5}"
readonly BACKUP_OPEN_BATCH_TIMEOUT_SECONDS="${BACKUP_OPEN_BATCH_TIMEOUT_SECONDS:-120}"
readonly RECOVERY_CONFIRMATIONS="${RECOVERY_CONFIRMATIONS:-3}"
readonly FAILOVER_MIN_HOLD_SECONDS="${FAILOVER_MIN_HOLD_SECONDS:-180}"
readonly RECOVERY_CLEAN_SECONDS="${RECOVERY_CLEAN_SECONDS:-120}"
readonly RECOVERY_RELAY_SUCCESSES="${RECOVERY_RELAY_SUCCESSES:-20}"
readonly ROUTE_UNAVAILABLE_WINDOW_SECONDS="${ROUTE_UNAVAILABLE_WINDOW_SECONDS:-15}"
readonly ROUTE_UNAVAILABLE_DETECTION_SECONDS="${ROUTE_UNAVAILABLE_DETECTION_SECONDS:-60}"
readonly ROUTE_UNAVAILABLE_THRESHOLD="${ROUTE_UNAVAILABLE_THRESHOLD:-2}"
readonly ROUTE_UNAVAILABLE_SPARSE_THRESHOLD="${ROUTE_UNAVAILABLE_SPARSE_THRESHOLD:-3}"
readonly RELAY_AVAILABILITY_WINDOW_SECONDS="${RELAY_AVAILABILITY_WINDOW_SECONDS:-15}"
readonly RELAY_AVAILABILITY_DETECTION_SECONDS="${RELAY_AVAILABILITY_DETECTION_SECONDS:-60}"
readonly RELAY_AVAILABILITY_THRESHOLD="${RELAY_AVAILABILITY_THRESHOLD:-2}"
readonly TELEMETRY_FAILURE_CONFIRMATIONS="${TELEMETRY_FAILURE_CONFIRMATIONS:-2}"
readonly SNAPSHOT_CONFIRMATIONS="${SNAPSHOT_CONFIRMATIONS:-2}"
readonly SNAPSHOT_TIMEOUT_SECONDS="${SNAPSHOT_TIMEOUT_SECONDS:-20}"
readonly SNAPSHOT_POLL_SECONDS="${SNAPSHOT_POLL_SECONDS:-1}"
readonly DRAIN_TIMEOUT_SECONDS="${DRAIN_TIMEOUT_SECONDS:-600}"
readonly DRAIN_POLL_SECONDS="${DRAIN_POLL_SECONDS:-5}"
readonly LOCK_WAIT_SECONDS="${LOCK_WAIT_SECONDS:-30}"
readonly STATE_DIR="${STATE_DIRECTORY:-${FAILOVER_STATE_DIR:-/var/lib/codex2api-sub2-codex-pro-failover}}"
readonly RUNTIME_DIR="${RUNTIME_DIRECTORY:-${FAILOVER_RUNTIME_DIR:-/run/codex2api-sub2-codex-pro-failover}}"
readonly STATE_FILE="$STATE_DIR/state.json"
readonly MAINTENANCE_FILE="$STATE_DIR/maintenance.json"
readonly LOCK_FILE="$RUNTIME_DIR/controller.lock"
readonly TEST_BACKEND="${FAILOVER_TEST_BACKEND:-}"

GROUP_ID=""
HEALTH_SERVICE_STATUS="unknown"
HEALTH_AVAILABLE="-1"
HEALTH_RELAY_SCHEDULABLE="-1"
HEALTH_RELAY_NORMAL_SCHEDULABLE="-1"
HEALTH_RELAY_ENABLED="-1"
HEALTH_RELAY_GROUP_ID="0"
HEALTH_RELAY_EFFECTIVE_SLOTS="-1"
HEALTH_RELAY_SUSPECT="-1"
HEALTH_RELAY_RECOVERY_ONLY="-1"
HEALTH_RELAY_CIRCUIT_OPEN="-1"
HEALTH_RELAY_LAST_RESORT="-1"
HEALTH_GUARDIAN_STATUS="unknown"
STATE_MODE="normal"
STATE_HEALTHY_STREAK=0
STATE_LAST_REASON="startup"
STATE_PROOF_AFTER=""
STATE_TAKEOVER_STARTED_AT=""
STATE_LAST_TRIGGER_AT=""
STATE_HEALTHY_SINCE=""
STATE_LAST_UNAVAILABLE_ID=0
STATE_LAST_UNAVAILABLE_AT=""
STATE_LAST_AVAILABILITY_ID=0
STATE_LAST_AVAILABILITY_AT=""
STATE_TELEMETRY_ERRORS=0
STATE_EFFECTIVE_ZERO_STREAK=0
STATE_REQUIRES_REBUILD=false
CURRENT_CONDITION="unknown"
SIGNALS_FETCHED=false
SIGNALS_HEALTH_OK=false
SIGNALS_EVIDENCE_OK=false
SCHEDULABLE_WRITE_PERFORMED=false
RELAY_UNAVAILABLE_15S=0
RELAY_UNAVAILABLE_120S=0
RELAY_LATEST_UNAVAILABLE_ID=0
RELAY_LATEST_UNAVAILABLE_AT=""
RELAY_SUCCESSES_AFTER_PROOF=0
RELAY_AVAILABILITY_15S=0
RELAY_AVAILABILITY_120S=0
RELAY_LATEST_AVAILABILITY_ID=0
RELAY_LATEST_AVAILABILITY_AT=""
RELAY_UNAVAILABLE_NEW_BURST=false
RELAY_AVAILABILITY_NEW_BURST=false
ACTIVE_HEADER_FILE=""
ACTIVE_RESPONSE_FILE=""
declare -a ACTIVE_BATCH_PIDS=()

declare -a MEMBER_IDS=()
declare -a BACKUP_IDS=()
declare -A MEMBER_NAME_B64=()
declare -A MEMBER_STATUS=()
declare -A MEMBER_SCHEDULABLE=()
declare -A MEMBER_NOT_DELETED=()
declare -A MEMBER_RUNTIME_READY=()

cleanup_backup_children() {
  local pid
  for pid in "${ACTIVE_BATCH_PIDS[@]:-}"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${ACTIVE_BATCH_PIDS[@]:-}"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    wait "$pid" 2>/dev/null || true
  done
  ACTIVE_BATCH_PIDS=()
}

cleanup_backup_child_files() {
  if [[ -n "$ACTIVE_RESPONSE_FILE" ]]; then
    rm -f -- "$ACTIVE_RESPONSE_FILE"
    ACTIVE_RESPONSE_FILE=""
  fi
}

cleanup_current_sensitive_files() {
  cleanup_backup_children
  if [[ -n "$ACTIVE_HEADER_FILE" ]]; then
    rm -f -- "$ACTIVE_HEADER_FILE"
    ACTIVE_HEADER_FILE=""
  fi
  if [[ -n "$ACTIVE_RESPONSE_FILE" ]]; then
    rm -f -- "$ACTIVE_RESPONSE_FILE"
    ACTIVE_RESPONSE_FILE=""
  fi
}

cleanup_stale_sensitive_files() {
  local stale
  shopt -s nullglob
  for stale in "$RUNTIME_DIR"/admin-header.* "$RUNTIME_DIR"/response.*; do
    rm -f -- "$stale"
  done
  shopt -u nullglob
}

trap cleanup_current_sensitive_files EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
  emit_event "critical" "bootstrap" "$1" '{}'
  exit 3
}

json_quote() {
  "$PYTHON_BIN" -c 'import json,sys; print(json.dumps(sys.argv[1], ensure_ascii=False))' "$1"
}

emit_event() {
  local status="$1"
  local action="$2"
  local reason="$3"
  local details="${4-}"
  [[ -n "$details" ]] || details='{}'
  printf '{"event_time":%s,"component":"sub2_codex_pro_failover","status":%s,"action":%s,"reason":%s,"group_id":%s,"bridge_account_id":%s,"details":%s}\n' \
    "$(json_quote "$(date --iso-8601=seconds)")" \
    "$(json_quote "$status")" \
    "$(json_quote "$action")" \
    "$(json_quote "$reason")" \
    "$(json_quote "${GROUP_ID:-unknown}")" \
    "$(json_quote "$BRIDGE_ACCOUNT_ID")" \
    "$details"
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "${name}_must_be_positive_integer"
}

for pair in \
  "BRIDGE_ACCOUNT_ID:$BRIDGE_ACCOUNT_ID" \
  "BACKUP_OPEN_PARALLELISM:$BACKUP_OPEN_PARALLELISM" \
  "SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS:$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS" \
  "BACKUP_OPEN_BATCH_TIMEOUT_SECONDS:$BACKUP_OPEN_BATCH_TIMEOUT_SECONDS" \
  "RECOVERY_CONFIRMATIONS:$RECOVERY_CONFIRMATIONS" \
  "FAILOVER_MIN_HOLD_SECONDS:$FAILOVER_MIN_HOLD_SECONDS" \
  "RECOVERY_CLEAN_SECONDS:$RECOVERY_CLEAN_SECONDS" \
  "RECOVERY_RELAY_SUCCESSES:$RECOVERY_RELAY_SUCCESSES" \
  "ROUTE_UNAVAILABLE_WINDOW_SECONDS:$ROUTE_UNAVAILABLE_WINDOW_SECONDS" \
  "ROUTE_UNAVAILABLE_DETECTION_SECONDS:$ROUTE_UNAVAILABLE_DETECTION_SECONDS" \
  "ROUTE_UNAVAILABLE_THRESHOLD:$ROUTE_UNAVAILABLE_THRESHOLD" \
  "ROUTE_UNAVAILABLE_SPARSE_THRESHOLD:$ROUTE_UNAVAILABLE_SPARSE_THRESHOLD" \
  "RELAY_AVAILABILITY_WINDOW_SECONDS:$RELAY_AVAILABILITY_WINDOW_SECONDS" \
  "RELAY_AVAILABILITY_DETECTION_SECONDS:$RELAY_AVAILABILITY_DETECTION_SECONDS" \
  "RELAY_AVAILABILITY_THRESHOLD:$RELAY_AVAILABILITY_THRESHOLD" \
  "TELEMETRY_FAILURE_CONFIRMATIONS:$TELEMETRY_FAILURE_CONFIRMATIONS" \
  "SNAPSHOT_CONFIRMATIONS:$SNAPSHOT_CONFIRMATIONS" \
  "SNAPSHOT_TIMEOUT_SECONDS:$SNAPSHOT_TIMEOUT_SECONDS" \
  "SNAPSHOT_POLL_SECONDS:$SNAPSHOT_POLL_SECONDS" \
  "DRAIN_TIMEOUT_SECONDS:$DRAIN_TIMEOUT_SECONDS" \
  "DRAIN_POLL_SECONDS:$DRAIN_POLL_SECONDS" \
  "LOCK_WAIT_SECONDS:$LOCK_WAIT_SECONDS"; do
  validate_positive_integer "${pair%%:*}" "${pair#*:}"
done

install -d -m 0700 "$STATE_DIR" "$RUNTIME_DIR"
exec 9>"$LOCK_FILE"

backend_call() {
  [[ -n "$TEST_BACKEND" ]] || return 127
  "$TEST_BACKEND" "$@"
}

credential_file() {
  if [[ -n "${CREDENTIALS_DIRECTORY:-}" && -r "${CREDENTIALS_DIRECTORY}/sub2api_admin_key" ]]; then
    printf '%s\n' "${CREDENTIALS_DIRECTORY}/sub2api_admin_key"
    return 0
  fi
  if [[ -n "${SUB2_ADMIN_KEY_FILE:-}" && -r "$SUB2_ADMIN_KEY_FILE" ]]; then
    printf '%s\n' "$SUB2_ADMIN_KEY_FILE"
    return 0
  fi
  if (( EUID == 0 )) && [[ -r /root/.sub2api_admin.key ]]; then
    printf '%s\n' /root/.sub2api_admin.key
    return 0
  fi
  return 1
}

read_admin_key() {
  local path
  path="$(credential_file)" || return 1
  local key
  key="$(<"$path")"
  [[ -n "$key" ]] || return 1
  printf '%s' "$key"
}

make_admin_header_file() {
  local key
  key="$(read_admin_key)" || return 1
  ACTIVE_HEADER_FILE="$(mktemp "$RUNTIME_DIR/admin-header.XXXXXX")"
  printf 'X-Api-Key: %s\n' "$key" >"$ACTIVE_HEADER_FILE"
  chmod 0600 "$ACTIVE_HEADER_FILE"
}

db_query() {
  local sql="$1"
  "$DOCKER_BIN" exec "$SUB2_POSTGRES_CONTAINER" sh -lc \
    'export PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=5000"; exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -AtF "|" -c "$1"' \
    sh "$sql"
}

codex_db_query() {
  local sql="$1"
  "$DOCKER_BIN" exec "$CODEX_POSTGRES_CONTAINER" sh -lc \
    'export PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=3000"; exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -AtF "|" -c "$1"' \
    sh "$sql"
}

discover_group() {
  [[ "$GROUP_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || {
    emit_event "critical" "discover_group" "group_name_invalid" '{}'
    return 1
  }
  local rows
  if [[ -n "$TEST_BACKEND" ]]; then
    rows="$(backend_call discover-group "$GROUP_NAME")" || return 1
  else
    rows="$(db_query "SELECT id, name, status FROM groups WHERE name='${GROUP_NAME}' AND deleted_at IS NULL ORDER BY id;")" || return 1
  fi

  local count=0
  local id=""
  local name=""
  local status=""
  local matched_name=""
  local matched_status=""
  while IFS='|' read -r id name status; do
    [[ -n "$id" ]] || continue
    count=$((count + 1))
    GROUP_ID="$id"
    matched_name="$name"
    matched_status="$status"
  done <<<"$rows"

  if (( count != 1 )) || [[ ! "$GROUP_ID" =~ ^[1-9][0-9]*$ ]] || [[ "$matched_name" != "$GROUP_NAME" ]] || [[ "$matched_status" != "active" ]]; then
    GROUP_ID=""
    emit_event "critical" "discover_group" "active_group_not_unique" \
      "$(printf '{"matching_groups":%s,"group_name":%s}' "$count" "$(json_quote "$GROUP_NAME")")"
    return 1
  fi
  return 0
}

query_members() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call list-members "$GROUP_ID"
    return
  fi
  db_query "
SELECT
  a.id,
  translate(encode(convert_to(a.name, 'UTF8'), 'base64'), E'\\n', ''),
  COALESCE(a.status, ''),
  COALESCE(a.schedulable, FALSE),
  (a.deleted_at IS NULL),
  (
    a.deleted_at IS NULL
    AND a.status = 'active'
    AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW())
    AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= NOW())
    AND (a.overload_until IS NULL OR a.overload_until <= NOW())
    AND (NOT COALESCE(a.auto_pause_on_expired, FALSE) OR a.expires_at IS NULL OR a.expires_at > NOW())
  )
FROM account_groups ag
JOIN accounts a ON a.id = ag.account_id
WHERE ag.group_id = ${GROUP_ID}
ORDER BY ag.priority, a.priority, a.id;"
}

load_members() {
  MEMBER_IDS=()
  BACKUP_IDS=()
  MEMBER_NAME_B64=()
  MEMBER_STATUS=()
  MEMBER_SCHEDULABLE=()
  MEMBER_NOT_DELETED=()
  MEMBER_RUNTIME_READY=()

  local rows
  rows="$(query_members)" || return 1
  local id name_b64 status schedulable not_deleted runtime_ready
  while IFS='|' read -r id name_b64 status schedulable not_deleted runtime_ready; do
    [[ "$id" =~ ^[1-9][0-9]*$ ]] || continue
    MEMBER_IDS+=("$id")
    MEMBER_NAME_B64["$id"]="$name_b64"
    MEMBER_STATUS["$id"]="$status"
    MEMBER_SCHEDULABLE["$id"]="$schedulable"
    MEMBER_NOT_DELETED["$id"]="$not_deleted"
    MEMBER_RUNTIME_READY["$id"]="$runtime_ready"
    if [[ "$id" != "$BRIDGE_ACCOUNT_ID" && "$status" == "active" && "$not_deleted" == "t" ]]; then
      BACKUP_IDS+=("$id")
    fi
  done <<<"$rows"

  return 0
}

primary_is_group_member() {
  [[ -n "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]+x}" ]]
}

account_name() {
  local id="$1"
  local encoded="${MEMBER_NAME_B64[$id]:-}"
  if [[ -z "$encoded" ]]; then
    printf 'account-%s' "$id"
    return
  fi
  printf '%s' "$encoded" | base64 --decode 2>/dev/null || printf 'account-%s' "$id"
}

query_outbox_count() {
  local id="$1"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call outbox-count "$id" account_changed
    return
  fi
  db_query "SELECT COUNT(*) FROM scheduler_outbox WHERE account_id=${id} AND event_type='account_changed';"
}

redis_raw() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call redis "$@"
    return
  fi
  local output
  output="$("$DOCKER_BIN" exec "$SUB2_REDIS_CONTAINER" env -u REDISCLI_AUTH \
    redis-cli -e --raw "$@" 2>&1)" || return 2
  # `-e` promotes RESP errors to a non-zero process exit. Keep the prefix fence
  # as defense in depth for older redis-cli behavior. All commands used here
  # return bucket names, numeric values or JSON, so these prefixes are invalid.
  case "$output" in
    ERR\ *|WRONGTYPE\ *|NOAUTH\ *|NOPERM\ *|AUTH\ *|LOADING\ *|BUSY\ *|NOSCRIPT\ *|OOM\ *|MISCONF\ *|READONLY\ *|MASTERDOWN\ *|NOREPLICAS\ *|CLUSTERDOWN\ *|CROSSSLOT\ *|TRYAGAIN\ *|'(error)'*)
      return 2
      ;;
  esac
  printf '%s\n' "$output"
}

ready_openai_buckets() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call buckets "$GROUP_ID"
    return
  fi
  local members
  members="$(redis_raw SMEMBERS sched:buckets)" || return 2
  local bucket ready
  while IFS= read -r bucket; do
    [[ -n "$bucket" ]] || continue
    [[ "$bucket" == "${GROUP_ID}:openai:"* ]] || continue
    ready="$(redis_raw GET "sched:ready:${bucket}")" || return 2
    case "$ready" in
      1) printf '%s\n' "$bucket" ;;
      0|'') ;;
      *) return 2 ;;
    esac
  done <<<"$members"
}

bucket_snapshot_key() {
  local bucket="$1"
  local version
  version="$(redis_raw GET "sched:active:${bucket}")" || return 2
  [[ "$version" =~ ^[0-9]+$ ]] || return 2
  printf 'sched:%s:v%s\n' "$bucket" "$version"
}

bucket_ready_active() {
  local bucket="$1"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call bucket-ready "$GROUP_ID" "$bucket"
    return
  fi
  local ready
  ready="$(redis_raw GET "sched:ready:${bucket}")" || return 2
  [[ "$ready" == "1" ]] || return 2
  local snapshot_key
  snapshot_key="$(bucket_snapshot_key "$bucket")" || return 2
  local exists
  exists="$(redis_raw EXISTS "$snapshot_key")" || return 2
  [[ "$exists" == "1" ]] || return 2
}

bucket_contains_account() {
  local bucket="$1"
  local account_id="$2"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call bucket-contains "$GROUP_ID" "$bucket" "$account_id"
    return
  fi
  bucket_ready_active "$bucket" || return 2
  local snapshot_key
  snapshot_key="$(bucket_snapshot_key "$bucket")" || return 2
  local score
  score="$(redis_raw ZSCORE "$snapshot_key" "$account_id")" || return 2
  [[ -n "$score" ]]
}

meta_projection() {
  local account_id="$1"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call meta "$account_id"
    return
  fi
  local lua
  read -r -d '' lua <<'LUA' || true
local raw = redis.call('GET', KEYS[1])
if not raw then return '' end
local ok, a = pcall(cjson.decode, raw)
if not ok then return '' end
return cjson.encode({
  Status = a.Status,
  Schedulable = a.Schedulable,
  RateLimitResetAt = a.RateLimitResetAt,
  OverloadUntil = a.OverloadUntil,
  TempUnschedulableUntil = a.TempUnschedulableUntil,
  ExpiresAt = a.ExpiresAt,
  AutoPauseOnExpired = a.AutoPauseOnExpired
})
LUA
  redis_raw EVAL "$lua" 1 "sched:meta:${account_id}"
}

meta_matches() {
  local account_id="$1"
  local expected="$2"
  local projection
  projection="$(meta_projection "$account_id")" || return 1
  [[ -n "$projection" ]] || return 1
  printf '%s' "$projection" | "$PYTHON_BIN" -c '
import datetime as dt, json, sys
expected = sys.argv[1] == "true"
try:
    a = json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
if a.get("Status") != "active" or bool(a.get("Schedulable")) is not expected:
    raise SystemExit(1)
if not expected:
    raise SystemExit(0)
now = dt.datetime.now(dt.timezone.utc)
def future(value):
    if not value:
        return False
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        stamp = dt.datetime.fromisoformat(raw)
    except ValueError:
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp.astimezone(dt.timezone.utc) > now
if future(a.get("RateLimitResetAt")) or future(a.get("OverloadUntil")) or future(a.get("TempUnschedulableUntil")):
    raise SystemExit(1)
if a.get("AutoPauseOnExpired") and a.get("ExpiresAt") and not future(a.get("ExpiresAt")):
    raise SystemExit(1)
' "$expected"
}

all_buckets_contain_account() {
  local account_id="$1"
  local buckets
  buckets="$(ready_openai_buckets)" || return 1
  [[ -n "$buckets" ]] || return 1
  local bucket
  while IFS= read -r bucket; do
    [[ -n "$bucket" ]] || continue
    bucket_ready_active "$bucket" || return 2
    bucket_contains_account "$bucket" "$account_id" || return $?
  done <<<"$buckets"
}

all_buckets_exclude_account() {
  local account_id="$1"
  local buckets
  buckets="$(ready_openai_buckets)" || return 1
  [[ -n "$buckets" ]] || return 1
  local bucket
  while IFS= read -r bucket; do
    [[ -n "$bucket" ]] || continue
    bucket_ready_active "$bucket" || return 2
    if bucket_contains_account "$bucket" "$account_id"; then
      return 1
    else
      local rc=$?
      (( rc == 1 )) || return 2
    fi
  done <<<"$buckets"
}

backups_ready_in_all_buckets() {
  load_members || return 1
  local -a candidates=()
  local id
  for id in "${BACKUP_IDS[@]}"; do
    if [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" && "${MEMBER_RUNTIME_READY[$id]}" == "t" ]] && meta_matches "$id" true; then
      candidates+=("$id")
    fi
  done
  (( ${#candidates[@]} > 0 )) || return 1

  local buckets
  buckets="$(ready_openai_buckets)" || return 1
  [[ -n "$buckets" ]] || return 1
  local bucket found
  while IFS= read -r bucket; do
    [[ -n "$bucket" ]] || continue
    bucket_ready_active "$bucket" || return 2
    found=false
    for id in "${candidates[@]}"; do
      if bucket_contains_account "$bucket" "$id"; then
        found=true
        break
      else
        local rc=$?
        (( rc == 1 )) || return 2
      fi
    done
    [[ "$found" == true ]] || return 1
  done <<<"$buckets"
}

wait_for_backups_ready() {
  local deadline=$((SECONDS + SNAPSHOT_TIMEOUT_SECONDS))
  local confirmations=0
  while (( SECONDS < deadline )); do
    if backups_ready_in_all_buckets; then
      confirmations=$((confirmations + 1))
      if (( confirmations >= SNAPSHOT_CONFIRMATIONS )); then
        return 0
      fi
    else
      confirmations=0
    fi
    sleep "$SNAPSHOT_POLL_SECONDS"
  done
  return 1
}

wait_for_account_snapshot() {
  local account_id="$1"
  local expected="$2"
  local deadline=$((SECONDS + SNAPSHOT_TIMEOUT_SECONDS))
  local confirmations=0
  while (( SECONDS < deadline )); do
    local db_ok=false outbox_ok=false meta_ok=false bucket_ok=false
    if load_members && [[ "${MEMBER_SCHEDULABLE[$account_id]:-}" == "$([[ "$expected" == true ]] && printf t || printf f)" ]]; then
      db_ok=true
    fi
    if [[ "$(query_outbox_count "$account_id" 2>/dev/null || printf 1)" == "0" ]]; then
      outbox_ok=true
    fi
    if meta_matches "$account_id" "$expected"; then
      meta_ok=true
    fi
    if [[ "$expected" == true ]]; then
      all_buckets_contain_account "$account_id" && bucket_ok=true
    else
      all_buckets_exclude_account "$account_id" && bucket_ok=true
    fi
    if [[ "$db_ok" == true && "$outbox_ok" == true && "$meta_ok" == true && "$bucket_ok" == true ]]; then
      confirmations=$((confirmations + 1))
      if (( confirmations >= SNAPSHOT_CONFIRMATIONS )); then
        return 0
      fi
    else
      confirmations=0
    fi
    sleep "$SNAPSHOT_POLL_SECONDS"
  done
  return 1
}

api_set_schedulable_with_header() {
  local account_id="$1"
  local desired="$2"
  local header_file="${3:-}"
  local request_timeout="${4:-$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS}"
  if [[ -n "$TEST_BACKEND" ]]; then
    "$TIMEOUT_BIN" --signal=TERM --kill-after=1s "${request_timeout}s" \
      "$TEST_BACKEND" set-schedulable "$account_id" "$desired"
    return
  fi
  [[ -r "$header_file" ]] || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
    --connect-timeout 2 --max-time "$request_timeout" -X POST \
    --header "@$header_file" -H 'Content-Type: application/json' \
    --data "{\"schedulable\":${desired}}" \
    "$SUB2_ADMIN_BASE_URL/api/v1/admin/accounts/$account_id/schedulable")" || {
      rm -f -- "$ACTIVE_RESPONSE_FILE"
      ACTIVE_RESPONSE_FILE=""
      return 1
    }
  rm -f -- "$ACTIVE_RESPONSE_FILE"
  ACTIVE_RESPONSE_FILE=""
  [[ "$code" == "200" ]]
}

api_set_schedulable() {
  local account_id="$1"
  local desired="$2"
  if [[ -n "$TEST_BACKEND" ]]; then
    api_set_schedulable_with_header "$account_id" "$desired" "" "$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS"
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  local header_file="$ACTIVE_HEADER_FILE"
  local rc=0
  api_set_schedulable_with_header "$account_id" "$desired" "$header_file" \
    "$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS" || rc=$?
  cleanup_current_sensitive_files
  return "$rc"
}

api_get_account() {
  local account_id="$1"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call get-account "$account_id"
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' --max-time 15 \
    --header "@$ACTIVE_HEADER_FILE" "$SUB2_ADMIN_BASE_URL/api/v1/admin/accounts/$account_id")" || {
      cleanup_current_sensitive_files
      return 1
    }
  [[ "$code" == "200" ]] || {
    cleanup_current_sensitive_files
    return 1
  }
  local normalized
  normalized="$("$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
a=p.get('data',p)
print('|'.join((
    str(a.get('status') or ''),
    'true' if bool(a.get('schedulable')) else 'false',
    str(int(a.get('current_concurrency') or 0)),
    'true' if a.get('deleted_at') is None else 'false',
)))
PY
)" || {
    cleanup_current_sensitive_files
    return 1
  }
  cleanup_current_sensitive_files
  printf '%s\n' "$normalized"
}

set_schedulable_guarded() {
  local account_id="$1"
  local desired="$2"
  local expected_primary_row_version="${3:-}"
  SCHEDULABLE_WRITE_PERFORMED=false
  load_members || return 1
  [[ "${MEMBER_STATUS[$account_id]:-}" == "active" && "${MEMBER_NOT_DELETED[$account_id]:-}" == "t" ]] || {
    emit_event "critical" "set_schedulable" "account_not_active_or_deleted" \
      "$(printf '{"account_id":%s,"desired":%s}' "$(json_quote "$account_id")" "$desired")"
    return 1
  }
  if [[ "$account_id" != "$BRIDGE_ACCOUNT_ID" ]]; then
    local found=false id
    for id in "${BACKUP_IDS[@]}"; do
      [[ "$id" == "$account_id" ]] && found=true
    done
    [[ "$found" == true ]] || return 1
  fi

  if [[ -n "$expected_primary_row_version" ]]; then
    [[ "$account_id" == "$BRIDGE_ACCOUNT_ID" && "$desired" == true ]] || {
      emit_event "critical" "set_schedulable" "row_version_fence_used_for_invalid_write" \
        "$(printf '{\"account_id\":%s,\"desired\":%s}' "$(json_quote "$account_id")" "$desired")"
      return 1
    }
    verify_primary_disabled_version "$expected_primary_row_version" || {
      emit_event "critical" "set_schedulable" "primary_row_version_changed_before_restore_write" \
        "$(printf '{\"expected_xmin\":%s}' "$(json_quote "$expected_primary_row_version")")"
      return 1
    }
  fi

  local current="${MEMBER_SCHEDULABLE[$account_id]}"
  local expected_db="$([[ "$desired" == true ]] && printf t || printf f)"
  if [[ "$current" == "$expected_db" ]]; then
    if wait_for_account_snapshot "$account_id" "$desired"; then
      return 0
    fi
    # A fresh maintenance run must never turn an externally paused primary
    # into controller-owned state merely by repeating the same admin write.
    # If its exclusion proof is ambiguous, keep standbys open and stop.
    if [[ "$account_id" == "$BRIDGE_ACCOUNT_ID" && "$desired" == false ]]; then
      emit_event "critical" "set_schedulable" "primary_already_paused_snapshot_unconfirmed" '{}'
      return 1
    fi
  fi

  api_set_schedulable "$account_id" "$desired" || {
    emit_event "critical" "set_schedulable" "admin_api_failed" \
      "$(printf '{"account_id":%s,"desired":%s}' "$(json_quote "$account_id")" "$desired")"
    return 1
  }
  SCHEDULABLE_WRITE_PERFORMED=true
  wait_for_account_snapshot "$account_id" "$desired" || {
    emit_event "critical" "set_schedulable" "scheduler_snapshot_not_confirmed" \
      "$(printf '{"account_id":%s,"desired":%s}' "$(json_quote "$account_id")" "$desired")"
    return 1
  }
  load_members || true
	emit_event "ok" "set_schedulable" "account_schedulable_updated" \
	  "$(printf '{"account_id":%s,"account_name":%s,"desired":%s}' \
		  "$(json_quote "$account_id")" "$(json_quote "$(account_name "$account_id")")" "$desired")"
}

open_backups() {
	load_members || return 1
	local id
	local eligible="${#BACKUP_IDS[@]}"
	local attempted=0
	local failed=0
	local deadline_exhausted=0
	local inventory_skipped=0
	local ineligible_skipped=0
	local -a ready_first=()
	local -a deferred=()
	local -a targets=()
	for id in "${BACKUP_IDS[@]}"; do
		# BACKUP_IDS is built from this single live inventory snapshot and contains
		# only active, non-deleted members other than BRIDGE_ACCOUNT_ID. Never turn
		# an inactive/deleted row into an eligible standby and never write status.
		if [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]]; then
			continue
		fi
		if [[ "${MEMBER_RUNTIME_READY[$id]}" == "t" ]]; then
			ready_first+=("$id")
		else
			deferred+=("$id")
		fi
	done
	targets=("${ready_first[@]}" "${deferred[@]}")
	(( eligible > 0 )) || {
		emit_event "critical" "open_backups" "no_active_backup_accounts" '{}'
		return 1
	}

	# Reuse one read-only credential header for the bounded batch. Each child owns
	# a unique response file and an EXIT cleanup trap; the parent alone owns and
	# removes the shared header after every child has been reaped.
	local shared_header=""
	if (( ${#targets[@]} > 0 )) && [[ -z "$TEST_BACKEND" ]]; then
		cleanup_current_sensitive_files
		if ! make_admin_header_file; then
			failed="${#targets[@]}"
			emit_event "critical" "open_backups" "admin_credential_unavailable" \
			  "$(printf '{"eligible_backups":%s,"pending_updates":%s}' "$eligible" "${#targets[@]}")"
			targets=()
		else
			shared_header="$ACTIVE_HEADER_FILE"
		fi
	fi

	local batch_deadline=$((SECONDS + BACKUP_OPEN_BATCH_TIMEOUT_SECONDS))
	local next=0
	local total="${#targets[@]}"
	while (( next < total )); do
		if (( SECONDS >= batch_deadline )); then
			deadline_exhausted=$((total - next))
			failed=$((failed + deadline_exhausted))
			break
		fi
		# Revalidate the next batch against fresh live membership. The initial
		# snapshot defines the work set, but an operator may pause/delete/remove a
		# member while a prior batch is in flight. Never submit a stale enable for
		# an account that is no longer active, non-deleted, in-group and non-primary.
		if ! load_members; then
			inventory_skipped=$((total - next))
			failed=$((failed + inventory_skipped))
			emit_event "critical" "open_backups" "backup_inventory_revalidation_failed" \
			  "$(printf '{"unattempted_backups":%s}' "$inventory_skipped")"
			break
		fi
		if (( SECONDS >= batch_deadline )); then
			deadline_exhausted=$((total - next))
			failed=$((failed + deadline_exhausted))
			break
		fi
		local remaining=$((batch_deadline - SECONDS))
		local request_timeout="$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS"
		if (( request_timeout > remaining )); then
			request_timeout="$remaining"
		fi
		(( request_timeout > 0 )) || request_timeout=1

		local -a batch_ids=()
		local -a batch_pids=()
		ACTIVE_BATCH_PIDS=()
		local slot=0
		while (( slot < BACKUP_OPEN_PARALLELISM && next < total )); do
			id="${targets[$next]}"
			next=$((next + 1))
			if [[ "$id" == "$BRIDGE_ACCOUNT_ID" ||
			      "${MEMBER_STATUS[$id]:-}" != "active" ||
			      "${MEMBER_NOT_DELETED[$id]:-}" != "t" ]]; then
				ineligible_skipped=$((ineligible_skipped + 1))
				emit_event "degraded" "open_backups" "backup_became_ineligible_before_submit" \
				  "$(printf '{"account_id":%s,"account_name":%s}' \
					  "$(json_quote "$id")" "$(json_quote "$(account_name "$id")")")"
				continue
			fi
			if [[ "${MEMBER_SCHEDULABLE[$id]:-}" == "t" ]]; then
				continue
			fi
			slot=$((slot + 1))
			attempted=$((attempted + 1))
			batch_ids+=("$id")
			(
				# Do not let a background EXIT trap remove the parent's shared header.
				ACTIVE_HEADER_FILE=""
				ACTIVE_RESPONSE_FILE=""
				ACTIVE_BATCH_PIDS=()
				trap cleanup_backup_child_files EXIT
				trap 'exit 143' TERM
				api_set_schedulable_with_header "$id" true "$shared_header" "$request_timeout"
			) &
			batch_pids+=("$!")
			ACTIVE_BATCH_PIDS+=("$!")
		done

		local index
		for index in "${!batch_pids[@]}"; do
			id="${batch_ids[$index]}"
			if wait "${batch_pids[$index]}"; then
				emit_event "ok" "open_backups" "backup_schedulable_requested" \
				  "$(printf '{"account_id":%s,"account_name":%s}' \
					  "$(json_quote "$id")" "$(json_quote "$(account_name "$id")")")"
			else
				failed=$((failed + 1))
				emit_event "degraded" "open_backups" "backup_admin_api_failed" \
				  "$(printf '{"account_id":%s,"account_name":%s}' \
					  "$(json_quote "$id")" "$(json_quote "$(account_name "$id")")")"
			fi
		done
		ACTIVE_BATCH_PIDS=()
	done
	cleanup_current_sensitive_files
	if (( deadline_exhausted > 0 )); then
		emit_event "degraded" "open_backups" "backup_batch_deadline_exhausted" \
		  "$(printf '{"unattempted_backups":%s,"deadline_seconds":%s}' \
			  "$deadline_exhausted" "$BACKUP_OPEN_BATCH_TIMEOUT_SECONDS")"
	fi

	# Reload once after all write submissions, then use the existing aggregate
	# database/outbox/Redis bucket proof. Per-account convergence waits would make
	# one stale or cooled-down member serialize and block every later standby.
	load_members || return 1
	wait_for_backups_ready || {
		emit_event "critical" "open_backups" "no_backup_reached_scheduler_snapshot" \
		  "$(printf '{"eligible_backups":%s,"attempted_backups":%s,"failed_updates":%s,"deadline_skipped":%s,"inventory_skipped":%s,"ineligible_skipped":%s}' \
			  "$eligible" "$attempted" "$failed" "$deadline_exhausted" "$inventory_skipped" "$ineligible_skipped")"
		return 1
	}
	emit_event "ok" "open_backups" "backups_ready" \
	  "$(printf '{"eligible_backups":%s,"attempted_backups":%s,"failed_updates":%s,"deadline_skipped":%s,"inventory_skipped":%s,"ineligible_skipped":%s}' \
		  "$eligible" "$attempted" "$failed" "$deadline_exhausted" "$inventory_skipped" "$ineligible_skipped")"
}

recovery_conditions_hold() {
  SIGNALS_FETCHED=false
  if ! evaluate_condition; then
    return 1
  fi
  if ! recovery_business_proven; then
    CURRENT_CONDITION="recovery_business_unproven"
    return 1
  fi
  return 0
}

close_backups() {
  load_members || return 1
  local id
  for id in "${BACKUP_IDS[@]}"; do
    if [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]]; then
      if ! recovery_conditions_hold; then
        local changed_reason="$CURRENT_CONDITION"
        emit_event "degraded" "close_backups" "recovery_condition_changed_backups_held" \
          "$(printf '{"trigger":%s,"next_account_id":%s}' "$(json_quote "$changed_reason")" "$(json_quote "$id")")"
        if open_backups; then
          emit_event "degraded" "close_backups" "partially_closed_backups_reopened" \
            "$(printf '{"trigger":%s}' "$(json_quote "$changed_reason")")"
        else
          emit_event "critical" "close_backups" "mid_close_change_and_reopen_failed" \
            "$(printf '{"trigger":%s}' "$(json_quote "$changed_reason")")"
        fi
        return 1
      fi
      if ! set_schedulable_guarded "$id" false; then
        if open_backups; then
          emit_event "degraded" "close_backups" "backups_reopened_after_close_write_failure" \
            "$(printf '{"account_id":%s}' "$(json_quote "$id")")"
        else
          emit_event "critical" "close_backups" "close_write_failure_and_reopen_failed" \
            "$(printf '{"account_id":%s}' "$(json_quote "$id")")"
        fi
        return 1
      fi
    fi
  done
  if ! recovery_conditions_hold; then
    local flipped_reason="$CURRENT_CONDITION"
    emit_event "critical" "close_backups" "post_close_health_changed" \
      "$(printf '{"trigger":%s}' "$(json_quote "$flipped_reason")")"
    if open_backups; then
      emit_event "degraded" "close_backups" "backups_reopened_after_post_close_change" \
        "$(printf '{"trigger":%s}' "$(json_quote "$flipped_reason")")"
    else
      emit_event "critical" "close_backups" "post_close_change_and_reopen_failed" \
        "$(printf '{"trigger":%s}' "$(json_quote "$flipped_reason")")"
    fi
    return 1
  fi
  emit_event "ok" "close_backups" "active_backups_paused" '{}'
}

fetch_health() {
  local normalized
  if [[ -n "$TEST_BACKEND" ]]; then
    normalized="$(backend_call health)" || return 1
  else
    local body
    body="$("$CURL_BIN" -fsS --max-time 5 "$HEALTH_URL")" || return 1
    normalized="$(printf '%s' "$body" | "$PYTHON_BIN" -c '
import json,sys
p=json.load(sys.stdin)
r=p.get("relay") or {}
g=p.get("guardian") or {}
legacy=r.get("schedulable")
normal=r.get("normal_schedulable")
if not isinstance(normal,(int,float)):
    normal=legacy
print("|".join((
    str(p.get("status") or "unknown"),
    str(int(p.get("available") if isinstance(p.get("available"), (int,float)) else -1)),
    str(int(legacy if isinstance(legacy, (int,float)) else -1)),
    str(int(normal if isinstance(normal, (int,float)) else -1)),
    str(int(r.get("enabled") if isinstance(r.get("enabled"), (int,float)) else -1)),
    str(int(r.get("group_id") if isinstance(r.get("group_id"), (int,float)) else 0)),
    str(int(r.get("effective_available_slots") if isinstance(r.get("effective_available_slots"), (int,float)) else -1)),
    str(int(r.get("suspect") if isinstance(r.get("suspect"), (int,float)) else -1)),
    str(int(r.get("recovery_only") if isinstance(r.get("recovery_only"), (int,float)) else -1)),
    str(int(r.get("circuit_open") if isinstance(r.get("circuit_open"), (int,float)) else -1)),
    str(int(r.get("last_resort") if isinstance(r.get("last_resort"), (int,float)) else -1)),
    str(g.get("status") or "unknown"),
)))
')" || return 1
  fi
  IFS='|' read -r HEALTH_SERVICE_STATUS HEALTH_AVAILABLE HEALTH_RELAY_SCHEDULABLE \
    HEALTH_RELAY_NORMAL_SCHEDULABLE HEALTH_RELAY_ENABLED HEALTH_RELAY_GROUP_ID \
    HEALTH_RELAY_EFFECTIVE_SLOTS HEALTH_RELAY_SUSPECT HEALTH_RELAY_RECOVERY_ONLY \
    HEALTH_RELAY_CIRCUIT_OPEN HEALTH_RELAY_LAST_RESORT HEALTH_GUARDIAN_STATUS <<<"$normalized"
  [[ "$HEALTH_AVAILABLE" =~ ^-?[0-9]+$ && "$HEALTH_RELAY_SCHEDULABLE" =~ ^-?[0-9]+$ &&
     "$HEALTH_RELAY_NORMAL_SCHEDULABLE" =~ ^-?[0-9]+$ && "$HEALTH_RELAY_ENABLED" =~ ^-?[0-9]+$ &&
     "$HEALTH_RELAY_GROUP_ID" =~ ^[0-9]+$ && "$HEALTH_RELAY_EFFECTIVE_SLOTS" =~ ^-?[0-9]+$ &&
     "$HEALTH_RELAY_SUSPECT" =~ ^-?[0-9]+$ && "$HEALTH_RELAY_RECOVERY_ONLY" =~ ^-?[0-9]+$ &&
     "$HEALTH_RELAY_CIRCUIT_OPEN" =~ ^-?[0-9]+$ && "$HEALTH_RELAY_LAST_RESORT" =~ ^-?[0-9]+$ ]]
}

fetch_relay_evidence() {
  local proof_after="${STATE_PROOF_AFTER:-1970-01-01T00:00:00Z}"
  [[ "$proof_after" =~ ^[0-9TZ:+.-]+$ ]] || return 1
  local normalized
  if [[ -n "$TEST_BACKEND" ]]; then
    normalized="$(backend_call relay-evidence "$HEALTH_RELAY_GROUP_ID" "$proof_after")" || return 1
  else
    (( HEALTH_RELAY_GROUP_ID > 0 )) || return 1
    normalized="$(codex_db_query "
WITH ranked AS (
  SELECT id, created_at, logical_request_id, status_code,
         COALESCE(account_id, 0) AS account_id,
         COALESCE(upstream_error_kind, '') AS upstream_error_kind,
         COALESCE(route_class, '') AS route_class,
         COALESCE(route_source, '') AS route_source,
         COALESCE(route_group_id, 0) AS route_group_id,
         COALESCE(upstream_account_type, '') AS upstream_account_type,
         ROW_NUMBER() OVER (PARTITION BY logical_request_id ORDER BY created_at DESC, id DESC) AS row_rank
  FROM usage_logs
  WHERE created_at >= NOW() - INTERVAL '10 minutes'
    AND created_at <= NOW()
    AND NOT COALESCE(guardian_attempt_only, FALSE)
    AND logical_request_id <> ''
), finals AS (
  SELECT * FROM ranked WHERE row_rank = 1
), unavailable AS (
  SELECT id, created_at, logical_request_id
  FROM finals
  WHERE route_class = 'cyb_relay'
    AND route_group_id = ${HEALTH_RELAY_GROUP_ID}
    AND LOWER(upstream_error_kind) = 'relay_route_unavailable'
    AND LOWER(route_source) <> 'probe'
), latest_unavailable AS (
  SELECT id, created_at
  FROM unavailable
  ORDER BY created_at DESC, id DESC
  LIMIT 1
), latest_burst AS (
  SELECT COUNT(DISTINCT logical_request_id) AS failures
  FROM unavailable event
  CROSS JOIN latest_unavailable latest
  WHERE latest.created_at >= NOW() - INTERVAL '${ROUTE_UNAVAILABLE_DETECTION_SECONDS} seconds'
    AND event.created_at >= latest.created_at - INTERVAL '${ROUTE_UNAVAILABLE_WINDOW_SECONDS} seconds'
    AND event.created_at <= latest.created_at
), availability_failures AS (
  SELECT id, created_at, logical_request_id
  FROM finals
  WHERE route_class = 'cyb_relay'
    AND route_group_id = ${HEALTH_RELAY_GROUP_ID}
    AND upstream_account_type = 'openai_responses'
    AND LOWER(route_source) <> 'probe'
    AND (
      LOWER(upstream_error_kind) = 'relay_route_unavailable'
      OR (
        status_code IN (502, 503, 504)
        AND LOWER(upstream_error_kind) NOT IN (
          'cyber_policy', 'content_policy', 'content_filter', 'safety', 'policy_violation'
        )
      )
      OR (
        status_code = 429
        AND account_id > 0
        AND LOWER(upstream_error_kind) IN (
          'rate_limited', 'rate_limited_5h', 'rate_limited_7d',
          'usage_limit', 'rate_limited_model', 'model_capacity'
        )
      )
      OR (
        status_code = 598
        AND LOWER(upstream_error_kind) IN ('transport', 'timeout')
      )
    )
), latest_availability AS (
  SELECT id, created_at
  FROM availability_failures
  ORDER BY created_at DESC, id DESC
  LIMIT 1
), latest_availability_burst AS (
  SELECT COUNT(DISTINCT logical_request_id) AS failures
  FROM availability_failures event
  CROSS JOIN latest_availability latest
  WHERE latest.created_at >= NOW() - INTERVAL '${RELAY_AVAILABILITY_DETECTION_SECONDS} seconds'
    AND event.created_at >= latest.created_at - INTERVAL '${RELAY_AVAILABILITY_WINDOW_SECONDS} seconds'
    AND event.created_at <= latest.created_at
), cutoff AS (
  SELECT GREATEST(
    TIMESTAMPTZ '${proof_after}',
    COALESCE((SELECT MAX(created_at) FROM unavailable), TIMESTAMPTZ 'epoch'),
    COALESCE((SELECT MAX(created_at) FROM availability_failures), TIMESTAMPTZ 'epoch')
  ) AS at
)
SELECT
  COALESCE((SELECT failures FROM latest_burst), 0),
  (SELECT COUNT(*) FROM unavailable WHERE created_at >= NOW() - INTERVAL '${RECOVERY_CLEAN_SECONDS} seconds'),
  COALESCE((SELECT id FROM latest_unavailable), 0),
  COALESCE(TO_CHAR((SELECT created_at FROM latest_unavailable), 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF'), ''),
  (SELECT COUNT(*) FROM finals, cutoff
    WHERE finals.created_at > cutoff.at
      AND finals.route_class = 'cyb_relay'
      AND finals.route_group_id = ${HEALTH_RELAY_GROUP_ID}
      AND finals.upstream_account_type = 'openai_responses'
      AND LOWER(finals.route_source) <> 'probe'
      AND finals.status_code BETWEEN 200 AND 399),
  COALESCE((SELECT failures FROM latest_availability_burst), 0),
  (SELECT COUNT(DISTINCT logical_request_id) FROM availability_failures
    WHERE created_at >= NOW() - INTERVAL '${RECOVERY_CLEAN_SECONDS} seconds'),
  COALESCE((SELECT id FROM latest_availability), 0),
  COALESCE(TO_CHAR((SELECT created_at FROM latest_availability), 'YYYY-MM-DD"T"HH24:MI:SS.USOF'), '');" )" || return 1
  fi
  IFS='|' read -r RELAY_UNAVAILABLE_15S RELAY_UNAVAILABLE_120S RELAY_LATEST_UNAVAILABLE_ID \
    RELAY_LATEST_UNAVAILABLE_AT RELAY_SUCCESSES_AFTER_PROOF RELAY_AVAILABILITY_15S \
    RELAY_AVAILABILITY_120S RELAY_LATEST_AVAILABILITY_ID RELAY_LATEST_AVAILABILITY_AT <<<"$normalized"
  # Older test backends and rollback fixtures returned only the original five
  # fields. Production SQL always emits all nine fields.
  RELAY_AVAILABILITY_15S="${RELAY_AVAILABILITY_15S:-0}"
  RELAY_AVAILABILITY_120S="${RELAY_AVAILABILITY_120S:-0}"
  RELAY_LATEST_AVAILABILITY_ID="${RELAY_LATEST_AVAILABILITY_ID:-0}"
  RELAY_LATEST_AVAILABILITY_AT="${RELAY_LATEST_AVAILABILITY_AT:-}"
  [[ "$RELAY_UNAVAILABLE_15S" =~ ^[0-9]+$ && "$RELAY_UNAVAILABLE_120S" =~ ^[0-9]+$ &&
     "$RELAY_LATEST_UNAVAILABLE_ID" =~ ^[0-9]+$ && "$RELAY_SUCCESSES_AFTER_PROOF" =~ ^[0-9]+$ &&
     "$RELAY_AVAILABILITY_15S" =~ ^[0-9]+$ && "$RELAY_AVAILABILITY_120S" =~ ^[0-9]+$ &&
     "$RELAY_LATEST_AVAILABILITY_ID" =~ ^[0-9]+$ ]]
}

relay_event_is_new() {
  local latest_at="$1"
  local latest_id="$2"
  local watermark_at="$3"
  local watermark_id="$4"
  "$PYTHON_BIN" - "$latest_at" "$latest_id" "$watermark_at" "$watermark_id" <<'PY'
import datetime as dt,sys
latest_at,latest_id,watermark_at,watermark_id=sys.argv[1:]
try:
    latest_id=int(latest_id)
    watermark_id=int(watermark_id)
except ValueError:
    raise SystemExit(2)
if latest_id <= 0:
    raise SystemExit(1)
def parse(value):
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:
        parsed=parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)
try:
    latest_stamp=parse(latest_at)
except Exception:
    raise SystemExit(2)
if not watermark_at:
    raise SystemExit(0 if latest_id > watermark_id else 1)
try:
    watermark_stamp=parse(watermark_at)
except Exception:
    raise SystemExit(2)
raise SystemExit(0 if (latest_stamp,latest_id) > (watermark_stamp,watermark_id) else 1)
PY
}

refresh_runtime_signals() {
  if [[ "$SIGNALS_FETCHED" == true ]]; then
    [[ "$SIGNALS_HEALTH_OK" == true && "$SIGNALS_EVIDENCE_OK" == true ]]
    return
  fi
  SIGNALS_FETCHED=true
  SIGNALS_HEALTH_OK=false
  SIGNALS_EVIDENCE_OK=false
  RELAY_UNAVAILABLE_NEW_BURST=false
  RELAY_AVAILABILITY_NEW_BURST=false
  if fetch_health; then
    SIGNALS_HEALTH_OK=true
    if (( HEALTH_RELAY_EFFECTIVE_SLOTS == 0 )); then
      STATE_EFFECTIVE_ZERO_STREAK=$((STATE_EFFECTIVE_ZERO_STREAK + 1))
    elif (( HEALTH_RELAY_EFFECTIVE_SLOTS > 0 )); then
      STATE_EFFECTIVE_ZERO_STREAK=0
    fi
    if fetch_relay_evidence; then
      SIGNALS_EVIDENCE_OK=true
    fi
  fi
  if [[ "$SIGNALS_HEALTH_OK" == true && "$SIGNALS_EVIDENCE_OK" == true ]]; then
    if (( RELAY_LATEST_UNAVAILABLE_ID > 0 )); then
      if relay_event_is_new "$RELAY_LATEST_UNAVAILABLE_AT" "$RELAY_LATEST_UNAVAILABLE_ID" \
          "$STATE_LAST_UNAVAILABLE_AT" "$STATE_LAST_UNAVAILABLE_ID"; then
        if (( RELAY_UNAVAILABLE_15S >= ROUTE_UNAVAILABLE_THRESHOLD ||
              RELAY_UNAVAILABLE_120S >= ROUTE_UNAVAILABLE_SPARSE_THRESHOLD )); then
          RELAY_UNAVAILABLE_NEW_BURST=true
        fi
        STATE_LAST_UNAVAILABLE_ID="$RELAY_LATEST_UNAVAILABLE_ID"
        STATE_LAST_UNAVAILABLE_AT="$RELAY_LATEST_UNAVAILABLE_AT"
      else
        local watermark_rc=$?
        if (( watermark_rc != 1 )); then
          SIGNALS_EVIDENCE_OK=false
          STATE_TELEMETRY_ERRORS=$((STATE_TELEMETRY_ERRORS + 1))
          return 1
        fi
      fi
    fi
    if (( RELAY_LATEST_AVAILABILITY_ID > 0 )); then
      if relay_event_is_new "$RELAY_LATEST_AVAILABILITY_AT" "$RELAY_LATEST_AVAILABILITY_ID" \
          "$STATE_LAST_AVAILABILITY_AT" "$STATE_LAST_AVAILABILITY_ID"; then
        if (( RELAY_AVAILABILITY_15S >= RELAY_AVAILABILITY_THRESHOLD )); then
          RELAY_AVAILABILITY_NEW_BURST=true
        fi
        STATE_LAST_AVAILABILITY_ID="$RELAY_LATEST_AVAILABILITY_ID"
        STATE_LAST_AVAILABILITY_AT="$RELAY_LATEST_AVAILABILITY_AT"
      else
        local availability_watermark_rc=$?
        if (( availability_watermark_rc != 1 )); then
          SIGNALS_EVIDENCE_OK=false
          STATE_TELEMETRY_ERRORS=$((STATE_TELEMETRY_ERRORS + 1))
          return 1
        fi
      fi
    fi
    STATE_TELEMETRY_ERRORS=0
    return 0
  fi
  if [[ "$SIGNALS_HEALTH_OK" == true ]]; then
    STATE_TELEMETRY_ERRORS=$((STATE_TELEMETRY_ERRORS + 1))
  else
    # Health loss is an immediate takeover signal, not one sample in the
    # auxiliary evidence-query debounce streak.
    STATE_TELEMETRY_ERRORS=0
  fi
  return 1
}

read_state() {
  STATE_MODE="normal"
  STATE_HEALTHY_STREAK=0
  STATE_LAST_REASON="startup"
  STATE_PROOF_AFTER=""
  STATE_TAKEOVER_STARTED_AT=""
  STATE_LAST_TRIGGER_AT=""
  STATE_HEALTHY_SINCE=""
  STATE_LAST_UNAVAILABLE_ID=0
  STATE_LAST_UNAVAILABLE_AT=""
  STATE_LAST_AVAILABILITY_ID=0
  STATE_LAST_AVAILABILITY_AT=""
  STATE_TELEMETRY_ERRORS=0
  STATE_EFFECTIVE_ZERO_STREAK=0
  STATE_REQUIRES_REBUILD=false
  [[ -s "$STATE_FILE" ]] || {
    STATE_REQUIRES_REBUILD=true
    return 0
  }
  local normalized
  normalized="$("$PYTHON_BIN" - "$STATE_FILE" <<'PY'
import datetime as dt,json,sys
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
except Exception:
    raise SystemExit(1)
try:
    schema=int(p['schema_version'])
except Exception:
    raise SystemExit(1)
if schema not in (1,2,3):
    raise SystemExit(1)
if str(p.get('mode') or '') not in ('normal','failover','maintenance','recovery_pending'):
    raise SystemExit(1)
for key in ('proof_after','takeover_started_at','last_trigger_at','healthy_since','last_unavailable_at','last_availability_at'):
    value=p.get(key)
    if not value:
        continue
    try:
        parsed=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
    except Exception:
        raise SystemExit(1)
    if parsed.tzinfo is None:
        raise SystemExit(1)
print('|'.join((
    str(p.get('mode') or 'normal'),
    str(int(p.get('healthy_streak') or 0)),
    str(p.get('last_reason') or 'unknown'),
    str(p.get('proof_after') or ''),
    str(p.get('takeover_started_at') or ''),
    str(p.get('last_trigger_at') or ''),
    str(p.get('healthy_since') or ''),
    str(int(p.get('last_unavailable_id') or 0)),
    str(p.get('last_unavailable_at') or ''),
    str(int(p.get('last_availability_id') or 0)),
    str(p.get('last_availability_at') or ''),
    str(int(p.get('telemetry_error_streak') or 0)),
    str(int(p.get('effective_zero_streak') or 0)),
)))
PY
)" || return 1
  IFS='|' read -r STATE_MODE STATE_HEALTHY_STREAK STATE_LAST_REASON STATE_PROOF_AFTER \
    STATE_TAKEOVER_STARTED_AT STATE_LAST_TRIGGER_AT STATE_HEALTHY_SINCE \
    STATE_LAST_UNAVAILABLE_ID STATE_LAST_UNAVAILABLE_AT STATE_LAST_AVAILABILITY_ID \
    STATE_LAST_AVAILABILITY_AT STATE_TELEMETRY_ERRORS \
    STATE_EFFECTIVE_ZERO_STREAK <<<"$normalized"
  [[ "$STATE_HEALTHY_STREAK" =~ ^[0-9]+$ && "$STATE_LAST_UNAVAILABLE_ID" =~ ^[0-9]+$ &&
     "$STATE_LAST_AVAILABILITY_ID" =~ ^[0-9]+$ && "$STATE_TELEMETRY_ERRORS" =~ ^[0-9]+$ &&
     "$STATE_EFFECTIVE_ZERO_STREAK" =~ ^[0-9]+$ ]]
}

rebuild_state_fail_open() {
  local reason="$1"
  local mode="failover"
  [[ -e "$MAINTENANCE_FILE" ]] && mode="maintenance"
  emit_event "critical" "reconcile" "${reason}_fail_open" '{}'
  open_backups || return 2
  local now
  now="$(now_rfc3339)"
  STATE_TAKEOVER_STARTED_AT="$now"
  STATE_LAST_TRIGGER_AT="$now"
  STATE_HEALTHY_SINCE=""
  STATE_HEALTHY_STREAK=0
  STATE_PROOF_AFTER="$now"
  STATE_LAST_REASON="$reason"
  write_state "$mode" 0 "$reason" "$STATE_PROOF_AFTER" || return 2
  emit_event "degraded" "reconcile" "${reason}_standbys_open_state_rebuilt" \
    "$(printf '{"mode":%s}' "$(json_quote "$mode")")"
}

write_state() {
  local mode="$1"
  local healthy_streak="$2"
  local last_reason="$3"
  local proof_after="${4:-}"
  local tmp
  tmp="$(mktemp "$STATE_DIR/state.XXXXXX")"
  "$PYTHON_BIN" - "$tmp" "$STATE_FILE" "$mode" "$healthy_streak" "$last_reason" "$proof_after" \
    "$STATE_TAKEOVER_STARTED_AT" "$STATE_LAST_TRIGGER_AT" "$STATE_HEALTHY_SINCE" \
    "$STATE_LAST_UNAVAILABLE_ID" "$STATE_LAST_UNAVAILABLE_AT" "$STATE_LAST_AVAILABILITY_ID" \
    "$STATE_LAST_AVAILABILITY_AT" "$STATE_TELEMETRY_ERRORS" \
    "$STATE_EFFECTIVE_ZERO_STREAK" <<'PY'
import datetime as dt,json,os,sys
tmp,path,mode,streak,reason,proof_after,takeover,last_trigger,healthy_since,last_unavailable_id,last_unavailable_at,last_availability_id,last_availability_at,telemetry_errors,effective_zero_streak=sys.argv[1:]
p={
  'schema_version':3,
  'mode':mode,
  'healthy_streak':int(streak),
  'last_reason':reason,
  'proof_after':proof_after or None,
  'takeover_started_at':takeover or None,
  'last_trigger_at':last_trigger or None,
  'healthy_since':healthy_since or None,
  'last_unavailable_id':int(last_unavailable_id),
  'last_unavailable_at':last_unavailable_at or None,
  'last_availability_id':int(last_availability_id),
  'last_availability_at':last_availability_at or None,
  'telemetry_error_streak':int(telemetry_errors),
  'effective_zero_streak':int(effective_zero_streak),
  'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),
}
with open(tmp,'w',encoding='utf-8') as f:
    json.dump(p,f,ensure_ascii=False,sort_keys=True)
    f.write('\n')
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp,0o600)
os.replace(tmp,path)
fd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

write_maintenance_marker() {
  local reason="$1"
  local primary_owned="$2"
  local primary_row_version="${3:-}"
  local pending_primary_row_version="${4:-}"
  local tmp
  tmp="$(mktemp "$STATE_DIR/maintenance.XXXXXX")"
  "$PYTHON_BIN" - "$tmp" "$MAINTENANCE_FILE" "$reason" "$primary_owned" \
    "$primary_row_version" "$pending_primary_row_version" <<'PY'
import datetime as dt,json,os,sys
tmp,path,reason,owned,row_version,pending_row_version=sys.argv[1:]
p={
  'schema_version':2,
  'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),
  'reason':reason,
  'primary_disabled_by_maintenance':owned == 'true',
  'primary_row_version':row_version or None,
  'pending_primary_row_version':pending_row_version or None,
}
with open(tmp,'w',encoding='utf-8') as f:
    json.dump(p,f,ensure_ascii=False,sort_keys=True)
    f.write('\n')
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp,0o600)
os.replace(tmp,path)
fd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

remove_maintenance_marker() {
  "$PYTHON_BIN" - "$MAINTENANCE_FILE" <<'PY'
import os,sys
path=sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
fd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

read_maintenance_ownership() {
  [[ -s "$MAINTENANCE_FILE" ]] || {
    printf 'false||\n'
    return
  }
  "$PYTHON_BIN" - "$MAINTENANCE_FILE" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
owned=bool(p.get('primary_disabled_by_maintenance'))
version=str(p.get('primary_row_version') or '')
pending=str(p.get('pending_primary_row_version') or '')
print('|'.join(('true' if owned else 'false',version,pending)))
PY
}

primary_maintenance_snapshot() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call primary-snapshot "$BRIDGE_ACCOUNT_ID"
    return
  fi
  db_query "
SELECT
  COALESCE(status, ''),
  COALESCE(schedulable, FALSE),
  (deleted_at IS NULL),
  (
    deleted_at IS NULL
    AND status = 'active'
    AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= NOW())
    AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at <= NOW())
    AND (overload_until IS NULL OR overload_until <= NOW())
    AND (NOT COALESCE(auto_pause_on_expired, FALSE) OR expires_at IS NULL OR expires_at > NOW())
  ),
  xmin::text
FROM accounts
WHERE id = ${BRIDGE_ACCOUNT_ID};"
}

capture_primary_disabled_version() {
  local row status schedulable not_deleted runtime_ready row_version
  row="$(primary_maintenance_snapshot)" || return 1
  IFS='|' read -r status schedulable not_deleted runtime_ready row_version <<<"$row"
  [[ "$status" == "active" && "$schedulable" == "f" && "$not_deleted" == "t" &&
     "$runtime_ready" == "t" && "$row_version" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$row_version"
}

verify_primary_disabled_version() {
  local expected="$1"
  [[ "$expected" =~ ^[0-9]+$ ]] || return 1
  local current
  current="$(capture_primary_disabled_version)" || return 1
  [[ "$current" == "$expected" ]]
}

now_rfc3339() {
  date --iso-8601=seconds
}

timestamp_age_at_least() {
  local value="$1"
  local seconds="$2"
  [[ -n "$value" ]] || return 1
  "$PYTHON_BIN" - "$value" "$seconds" <<'PY'
import datetime as dt,sys
try:
    value=dt.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'))
    if value.tzinfo is None:
        value=value.replace(tzinfo=dt.timezone.utc)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if (dt.datetime.now(dt.timezone.utc)-value).total_seconds() >= int(sys.argv[2]) else 1)
PY
}

required_normal_relay_count() {
  if (( HEALTH_RELAY_ENABLED <= 1 )); then
    printf '1\n'
  else
    printf '2\n'
  fi
}

recovery_business_proven() {
  [[ "$SIGNALS_HEALTH_OK" == true && "$SIGNALS_EVIDENCE_OK" == true ]] || return 1
  local required
  required="$(required_normal_relay_count)"
  (( HEALTH_RELAY_NORMAL_SCHEDULABLE >= required )) || return 1
  (( HEALTH_RELAY_EFFECTIVE_SLOTS > 0 )) || return 1
  (( HEALTH_RELAY_SUSPECT == 0 )) || return 1
  (( HEALTH_RELAY_RECOVERY_ONLY == 0 )) || return 1
  (( HEALTH_RELAY_CIRCUIT_OPEN == 0 )) || return 1
  (( HEALTH_RELAY_LAST_RESORT == 0 )) || return 1
  (( RELAY_UNAVAILABLE_120S == 0 )) || return 1
  (( RELAY_AVAILABILITY_120S == 0 )) || return 1
  (( RELAY_SUCCESSES_AFTER_PROOF >= RECOVERY_RELAY_SUCCESSES )) || return 1
  primary_success_proven "$STATE_PROOF_AFTER"
}

record_failover_trigger() {
  local trigger="$1"
  local now
  now="$(now_rfc3339)"
  if [[ -z "$STATE_TAKEOVER_STARTED_AT" ]]; then
    STATE_TAKEOVER_STARTED_AT="$now"
  fi
  STATE_LAST_TRIGGER_AT="$now"
  STATE_HEALTHY_SINCE=""
  STATE_HEALTHY_STREAK=0
  if [[ -z "$STATE_PROOF_AFTER" ]]; then
    STATE_PROOF_AFTER="$now"
  fi
  STATE_LAST_REASON="$trigger"
}

active_backup_count() {
  load_members || return 1
  local count=0 id
  for id in "${BACKUP_IDS[@]}"; do
    [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]] && count=$((count + 1))
  done
  printf '%s\n' "$count"
}

primary_success_proven() {
  local proof_after="$1"
  [[ -n "$proof_after" && "$proof_after" =~ ^[0-9TZ:+.-]+$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call primary-proof "$BRIDGE_ACCOUNT_ID" "$proof_after"
    return
  fi
  local result
  result="$(db_query "
WITH p AS (
  SELECT TIMESTAMPTZ '${proof_after}' AS proof_after
), errors AS (
  SELECT MAX(e.created_at) AS last_error
  FROM ops_error_logs e
  WHERE e.account_id=${BRIDGE_ACCOUNT_ID}
), cutoff AS (
  SELECT GREATEST(p.proof_after, COALESCE(errors.last_error, TIMESTAMPTZ 'epoch')) AS at
  FROM p CROSS JOIN errors
), facts AS (
  SELECT
    (SELECT COUNT(*) FROM usage_logs u, cutoff
      WHERE u.account_id=${BRIDGE_ACCOUNT_ID} AND u.created_at > cutoff.at) AS success_count_after_cutoff,
    (SELECT COUNT(*) FROM ops_error_logs e
      WHERE e.account_id=${BRIDGE_ACCOUNT_ID}
        AND e.created_at > NOW() - INTERVAL '60 seconds'
        AND COALESCE(NULLIF(e.upstream_status_code, 0), e.status_code, 0) >= 500) AS recent_5xx
)
SELECT success_count_after_cutoff, recent_5xx
FROM facts;")" || return 1
  local success_count recent_5xx
  IFS='|' read -r success_count recent_5xx <<<"$result"
  [[ "$success_count" =~ ^[0-9]+$ && "$recent_5xx" =~ ^[0-9]+$ ]] || return 1
  (( success_count >= 2 )) && (( recent_5xx == 0 ))
}

evaluate_condition() {
  load_members || {
    CURRENT_CONDITION="inventory_unavailable"
    return 1
  }
  if ! primary_is_group_member; then
    CURRENT_CONDITION="primary_not_in_group"
    return 1
  fi
  if [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}" != "active" || "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    CURRENT_CONDITION="primary_not_active"
    return 1
  fi
  if [[ "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    CURRENT_CONDITION="primary_unschedulable"
    return 1
  fi
  if [[ "${MEMBER_RUNTIME_READY[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    CURRENT_CONDITION="primary_runtime_blocked"
    return 1
  fi
  if ! meta_matches "$BRIDGE_ACCOUNT_ID" true || ! all_buckets_contain_account "$BRIDGE_ACCOUNT_ID"; then
    CURRENT_CONDITION="primary_scheduler_not_ready"
    return 1
  fi
  refresh_runtime_signals || true
  # An authoritative health response is sufficient to prove current service or
  # Relay capacity loss. A failure in the auxiliary logical-outcome query must
  # not hide that signal behind the telemetry debounce window.
  if [[ "$SIGNALS_HEALTH_OK" != true ]]; then
    CURRENT_CONDITION="health_unavailable"
    return 1
  fi
  if [[ "$HEALTH_SERVICE_STATUS" != "ok" || "$HEALTH_AVAILABLE" -le 0 ]]; then
    CURRENT_CONDITION="service_unhealthy"
    return 1
  fi
  if (( HEALTH_RELAY_EFFECTIVE_SLOTS < 0 || HEALTH_RELAY_SUSPECT < 0 ||
        HEALTH_RELAY_RECOVERY_ONLY < 0 || HEALTH_RELAY_CIRCUIT_OPEN < 0 ||
        HEALTH_RELAY_LAST_RESORT < 0 )); then
    CURRENT_CONDITION="relay_capacity_telemetry_unavailable"
    return 1
  fi
  if (( HEALTH_RELAY_NORMAL_SCHEDULABLE <= 0 )); then
    CURRENT_CONDITION="relay_zero"
    return 1
  fi
  if (( HEALTH_RELAY_EFFECTIVE_SLOTS == 0 )); then
    if (( STATE_EFFECTIVE_ZERO_STREAK >= 2 )); then
      CURRENT_CONDITION="relay_effective_slots_zero"
    else
      CURRENT_CONDITION="relay_effective_slots_zero_unconfirmed"
    fi
    return 1
  fi
  if [[ "$SIGNALS_EVIDENCE_OK" != true ]]; then
    if (( STATE_TELEMETRY_ERRORS >= TELEMETRY_FAILURE_CONFIRMATIONS )); then
      CURRENT_CONDITION="telemetry_unavailable"
    else
      CURRENT_CONDITION="telemetry_unavailable_unconfirmed"
    fi
    return 1
  fi
  if [[ "$RELAY_UNAVAILABLE_NEW_BURST" == true ]]; then
    CURRENT_CONDITION="relay_user_visible_unavailable"
    return 1
  fi
  if [[ "$RELAY_AVAILABILITY_NEW_BURST" == true ]]; then
    CURRENT_CONDITION="relay_user_visible_availability_failure"
    return 1
  fi
  if [[ -n "$STATE_PROOF_AFTER" ]] && ! primary_success_proven "$STATE_PROOF_AFTER"; then
    CURRENT_CONDITION="primary_success_unproven"
    return 1
  fi
  CURRENT_CONDITION="healthy"
  return 0
}

reconcile() {
  discover_group || return 2
  read_state || {
    rebuild_state_fail_open "state_invalid_or_incompatible" || return 2
    return 0
  }
  if [[ "$STATE_REQUIRES_REBUILD" == true ]]; then
    rebuild_state_fail_open "state_missing" || return 2
    return 0
  fi
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    open_backups || return 2
    write_state "maintenance" 0 "maintenance_marker_present" "$STATE_PROOF_AFTER"
    emit_event "ok" "reconcile" "maintenance_backups_held_open" '{}'
    return 0
  fi

  local schedulable_backups
  schedulable_backups="$(active_backup_count)" || return 2
  local failover_active=false
  if (( schedulable_backups > 0 )) || [[ -n "$STATE_TAKEOVER_STARTED_AT" || "$STATE_MODE" == "failover" || "$STATE_MODE" == "recovery_pending" ]]; then
    failover_active=true
  fi

  if ! evaluate_condition; then
    if [[ "$CURRENT_CONDITION" == "telemetry_unavailable_unconfirmed" && "$failover_active" != true ]]; then
      STATE_HEALTHY_STREAK=0
      STATE_HEALTHY_SINCE=""
      write_state "normal" 0 "$CURRENT_CONDITION" "$STATE_PROOF_AFTER"
      emit_event "degraded" "reconcile" "telemetry_failure_confirmation_pending" \
        "$(printf '{"failures":%s,"required":%s}' "$STATE_TELEMETRY_ERRORS" "$TELEMETRY_FAILURE_CONFIRMATIONS")"
      return 0
    fi
    if [[ "$CURRENT_CONDITION" == "relay_effective_slots_zero_unconfirmed" ]]; then
      STATE_HEALTHY_STREAK=0
      STATE_HEALTHY_SINCE=""
      if [[ "$failover_active" == true ]]; then
        open_backups || return 2
        write_state "recovery_pending" 0 "$CURRENT_CONDITION" "$STATE_PROOF_AFTER"
        emit_event "degraded" "reconcile" "effective_slots_zero_confirmation_pending_backups_held" \
          "$(printf '{"samples":%s,"required":2}' "$STATE_EFFECTIVE_ZERO_STREAK")"
      else
        write_state "normal" 0 "$CURRENT_CONDITION" "$STATE_PROOF_AFTER"
        emit_event "degraded" "reconcile" "effective_slots_zero_confirmation_pending" \
          "$(printf '{"samples":%s,"required":2}' "$STATE_EFFECTIVE_ZERO_STREAK")"
      fi
      return 0
    fi
    record_failover_trigger "$CURRENT_CONDITION"
    open_backups || return 2
    write_state "failover" 0 "$CURRENT_CONDITION" "$STATE_PROOF_AFTER"
    emit_event "degraded" "reconcile" "standby_takeover_active" \
      "$(printf '{"trigger":%s,"guardian_status":%s,"relay_unavailable_15s":%s,"relay_availability_15s":%s,"normal_relay":%s}' \
        "$(json_quote "$CURRENT_CONDITION")" "$(json_quote "$HEALTH_GUARDIAN_STATUS")" \
        "$RELAY_UNAVAILABLE_15S" "$RELAY_AVAILABILITY_15S" "$HEALTH_RELAY_NORMAL_SCHEDULABLE")"
    return 0
  fi

  if [[ "$failover_active" != true ]]; then
    STATE_TAKEOVER_STARTED_AT=""
    STATE_LAST_TRIGGER_AT=""
    STATE_HEALTHY_SINCE=""
    STATE_HEALTHY_STREAK=0
    STATE_PROOF_AFTER=""
    write_state "normal" "$RECOVERY_CONFIRMATIONS" "healthy" ""
    emit_event "ok" "reconcile" "normal_primary_preferred" \
      "$(printf '{"healthy_streak":%s,"guardian_status":%s}' "$RECOVERY_CONFIRMATIONS" "$(json_quote "$HEALTH_GUARDIAN_STATUS")")"
    return 0
  fi

  if [[ -z "$STATE_TAKEOVER_STARTED_AT" ]]; then
    STATE_TAKEOVER_STARTED_AT="$(now_rfc3339)"
  fi
  if [[ -z "$STATE_PROOF_AFTER" ]]; then
    STATE_PROOF_AFTER="$STATE_TAKEOVER_STARTED_AT"
    # A standby discovered outside a recorded failover must start a fresh
    # recovery cohort; the normal-mode healthy streak is not proof after it.
    STATE_HEALTHY_STREAK=0
    STATE_HEALTHY_SINCE=""
    SIGNALS_FETCHED=false
    refresh_runtime_signals || true
  fi
  open_backups || return 2

  if ! recovery_business_proven; then
    STATE_HEALTHY_STREAK=0
    STATE_HEALTHY_SINCE=""
    write_state "recovery_pending" 0 "recovery_proof_pending" "$STATE_PROOF_AFTER"
    emit_event "ok" "reconcile" "recovery_proof_pending" \
      "$(printf '{"normal_relay":%s,"required_normal":%s,"effective_slots":%s,"suspect":%s,"recovery_only":%s,"circuit_open":%s,"last_resort":%s,"relay_unavailable_120s":%s,"relay_availability_120s":%s,"relay_successes":%s,"required_successes":%s}' \
        "$HEALTH_RELAY_NORMAL_SCHEDULABLE" "$(required_normal_relay_count)" \
        "$HEALTH_RELAY_EFFECTIVE_SLOTS" "$HEALTH_RELAY_SUSPECT" "$HEALTH_RELAY_RECOVERY_ONLY" \
        "$HEALTH_RELAY_CIRCUIT_OPEN" "$HEALTH_RELAY_LAST_RESORT" "$RELAY_UNAVAILABLE_120S" "$RELAY_AVAILABILITY_120S" \
        "$RELAY_SUCCESSES_AFTER_PROOF" "$RECOVERY_RELAY_SUCCESSES")"
    return 0
  fi

  if [[ -z "$STATE_HEALTHY_SINCE" ]]; then
    STATE_HEALTHY_SINCE="$(now_rfc3339)"
  fi
  STATE_HEALTHY_STREAK=$((STATE_HEALTHY_STREAK + 1))
  if (( STATE_HEALTHY_STREAK < RECOVERY_CONFIRMATIONS )) ||
     ! timestamp_age_at_least "$STATE_TAKEOVER_STARTED_AT" "$FAILOVER_MIN_HOLD_SECONDS" ||
     ! timestamp_age_at_least "$STATE_HEALTHY_SINCE" "$RECOVERY_CLEAN_SECONDS"; then
    write_state "recovery_pending" "$STATE_HEALTHY_STREAK" "recovery_confirmation_pending" "$STATE_PROOF_AFTER"
    emit_event "ok" "reconcile" "recovery_confirmation_pending" \
      "$(printf '{"healthy_streak":%s,"required":%s,"minimum_hold_seconds":%s,"clean_seconds":%s}' \
        "$STATE_HEALTHY_STREAK" "$RECOVERY_CONFIRMATIONS" "$FAILOVER_MIN_HOLD_SECONDS" "$RECOVERY_CLEAN_SECONDS")"
    return 0
  fi

  close_backups || return 2
  STATE_TAKEOVER_STARTED_AT=""
  STATE_LAST_TRIGGER_AT=""
  STATE_HEALTHY_SINCE=""
  STATE_PROOF_AFTER=""
  STATE_TELEMETRY_ERRORS=0
  write_state "normal" "$RECOVERY_CONFIRMATIONS" "healthy" ""
  emit_event "ok" "reconcile" "normal_primary_preferred" \
    "$(printf '{"healthy_streak":%s,"guardian_status":%s}' "$RECOVERY_CONFIRMATIONS" "$(json_quote "$HEALTH_GUARDIAN_STATUS")")"
}

wait_for_primary_drain() {
  local deadline=$((SECONDS + DRAIN_TIMEOUT_SECONDS))
  local zero_samples=0
  while (( SECONDS < deadline )); do
    local row status sched concurrency not_deleted
    row="$(api_get_account "$BRIDGE_ACCOUNT_ID")" || return 1
    IFS='|' read -r status sched concurrency not_deleted <<<"$row"
    [[ "$status" == "active" && "$not_deleted" == "true" && "$concurrency" =~ ^[0-9]+$ ]] || return 1
    if [[ "$sched" == "false" && "$concurrency" == "0" ]]; then
      zero_samples=$((zero_samples + 1))
      (( zero_samples >= 2 )) && return 0
    else
      zero_samples=0
    fi
    sleep "$DRAIN_POLL_SECONDS"
  done
  return 1
}

prepare_maintenance() {
  discover_group || return 2
  local existing_owned=false
  local existing_version=""
  local pending_version=""
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    local ownership
    ownership="$(read_maintenance_ownership)" || return 2
    IFS='|' read -r existing_owned existing_version pending_version <<<"$ownership"
  fi
  write_maintenance_marker "planned_codex2api_maintenance" "$existing_owned" \
    "$existing_version" "$pending_version"
  open_backups || {
    emit_event "critical" "prepare_maintenance" "backup_takeover_not_ready_primary_unchanged" '{}'
    return 2
  }
  load_members || return 2
  if ! primary_is_group_member; then
    emit_event "critical" "prepare_maintenance" "primary_not_in_group_backups_left_open" '{}'
    return 2
  fi
  if [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}" != "active" || "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    emit_event "critical" "prepare_maintenance" "primary_not_active_primary_unchanged" '{}'
    return 2
  fi

  local primary_schedulable="${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}"
  if [[ "$existing_owned" == true || -n "$pending_version" ]]; then
    if [[ "$primary_schedulable" != "f" ]]; then
      emit_event "critical" "prepare_maintenance" "primary_ownership_changed_backups_left_open" '{}'
      return 2
    fi
    if [[ "$existing_owned" == true ]]; then
      verify_primary_disabled_version "$existing_version" || {
        emit_event "critical" "prepare_maintenance" "primary_row_version_changed_backups_left_open" \
          "$(printf '{"expected_xmin":%s}' "$(json_quote "$existing_version")")"
        return 2
      }
    fi
  elif [[ "$primary_schedulable" == "t" ]]; then
    set_schedulable_guarded "$BRIDGE_ACCOUNT_ID" false || return 2
    if [[ "$SCHEDULABLE_WRITE_PERFORMED" == true ]]; then
      pending_version="$(capture_primary_disabled_version)" || {
        emit_event "critical" "prepare_maintenance" "primary_disable_version_not_captured_backups_left_open" '{}'
        return 2
      }
      write_maintenance_marker "planned_codex2api_maintenance" false "" "$pending_version"
    else
      emit_event "degraded" "prepare_maintenance" "primary_already_paused_not_owned" '{}'
    fi
  fi
  wait_for_primary_drain || {
    emit_event "critical" "prepare_maintenance" "primary_drain_timeout_backups_left_open" '{}'
    return 2
  }
  if [[ -n "$pending_version" ]]; then
    local drained_version
    drained_version="$(capture_primary_disabled_version)" || {
      emit_event "critical" "prepare_maintenance" "primary_disabled_snapshot_invalid_after_drain" '{}'
      return 2
    }
    existing_owned=true
    existing_version="$drained_version"
    pending_version=""
    write_maintenance_marker "planned_codex2api_maintenance" true "$existing_version" ""
  elif [[ "$existing_owned" == true ]]; then
    verify_primary_disabled_version "$existing_version" || {
      emit_event "critical" "prepare_maintenance" "primary_row_version_changed_during_drain" \
        "$(printf '{"expected_xmin":%s}' "$(json_quote "$existing_version")")"
      return 2
    }
  fi
  write_state "maintenance" 0 "maintenance_prepared" "$(now_rfc3339)"
  emit_event "ok" "prepare_maintenance" "maintenance_ready" \
    "$(printf '{"primary_owned":%s}' "$existing_owned")"
}

finish_maintenance() {
  discover_group || return 2
  [[ -e "$MAINTENANCE_FILE" ]] || {
    emit_event "critical" "finish_maintenance" "maintenance_marker_missing" '{}'
    return 2
  }
  if ! fetch_health || [[ "$HEALTH_SERVICE_STATUS" != "ok" || "$HEALTH_AVAILABLE" -le 0 ]]; then
    emit_event "critical" "finish_maintenance" "service_not_healthy_backups_left_open" '{}'
    return 2
  fi

  local ownership owned owned_version pending_version
  ownership="$(read_maintenance_ownership)" || return 2
  IFS='|' read -r owned owned_version pending_version <<<"$ownership"
  if [[ -n "$pending_version" ]]; then
    emit_event "critical" "finish_maintenance" "primary_ownership_pending_run_prepare_again" \
      "$(printf '{"pending_xmin":%s}' "$(json_quote "$pending_version")")"
    return 2
  fi
  if [[ "$owned" == true ]]; then
    verify_primary_disabled_version "$owned_version" || {
      emit_event "critical" "finish_maintenance" "primary_ownership_version_changed_backups_left_open" \
        "$(printf '{"expected_xmin":%s}' "$(json_quote "$owned_version")")"
      return 2
    }
    set_schedulable_guarded "$BRIDGE_ACCOUNT_ID" true "$owned_version" || {
      emit_event "critical" "finish_maintenance" "primary_restore_failed_backups_left_open" '{}'
      return 2
    }
    write_maintenance_marker "primary_restored" false "" ""
  fi

  local backups_ready=true
  if ! open_backups; then
    backups_ready=false
    if [[ "$owned" != true ]]; then
      emit_event "critical" "finish_maintenance" "no_primary_ownership_and_no_ready_backup" '{}'
      return 2
    fi
  fi
  remove_maintenance_marker

  if (( HEALTH_RELAY_NORMAL_SCHEDULABLE <= 0 )); then
    write_state "failover" 0 "relay_zero_after_maintenance" "$(now_rfc3339)"
    if [[ "$backups_ready" == true ]]; then
      emit_event "degraded" "finish_maintenance" "primary_restored_relay_zero_backups_held" '{}'
      return 0
    fi
    emit_event "critical" "finish_maintenance" "primary_restored_but_relay_zero_and_no_ready_backup" '{}'
    return 2
  fi

  if [[ "$backups_ready" != true ]]; then
    write_state "normal" 0 "maintenance_finished_primary_only" ""
    emit_event "ok" "finish_maintenance" "primary_restored_no_active_backup_needed" '{}'
    return 0
  fi

  write_state "recovery_pending" 0 "maintenance_finished" "$(now_rfc3339)"
  emit_event "ok" "finish_maintenance" "primary_restored_recovery_confirmation_started" \
    "$(printf '{"required_confirmations":%s}' "$RECOVERY_CONFIRMATIONS")"
}

status_command() {
  discover_group || return 2
  load_members || return 2
  if ! primary_is_group_member; then
    emit_event "critical" "status" "primary_not_in_group" '{}'
    return 2
  fi
  read_state || return 2
  if fetch_health; then
    fetch_relay_evidence || true
  fi
  local active_backups=0 id
  for id in "${BACKUP_IDS[@]}"; do
    [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]] && active_backups=$((active_backups + 1))
  done
  emit_event "ok" "status" "status_snapshot" \
    "$(printf '{"mode":%s,"healthy_streak":%s,"maintenance":%s,"primary_status":%s,"primary_schedulable":%s,"eligible_backups":%s,"schedulable_backups":%s,"service_status":%s,"relay_schedulable":%s,"relay_normal_schedulable":%s,"relay_effective_slots":%s,"relay_suspect":%s,"relay_recovery_only":%s,"relay_circuit_open":%s,"relay_last_resort":%s,"effective_zero_streak":%s,"relay_unavailable_15s":%s,"relay_unavailable_120s":%s,"relay_availability_15s":%s,"relay_availability_120s":%s,"relay_successes_after_proof":%s,"guardian_status":%s}' \
      "$(json_quote "$STATE_MODE")" "$STATE_HEALTHY_STREAK" \
      "$([[ -e "$MAINTENANCE_FILE" ]] && printf true || printf false)" \
      "$(json_quote "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}")" \
      "$([[ "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}" == t ]] && printf true || printf false)" \
      "${#BACKUP_IDS[@]}" "$active_backups" \
      "$(json_quote "$HEALTH_SERVICE_STATUS")" "$HEALTH_RELAY_SCHEDULABLE" "$HEALTH_RELAY_NORMAL_SCHEDULABLE" \
      "$HEALTH_RELAY_EFFECTIVE_SLOTS" "$HEALTH_RELAY_SUSPECT" "$HEALTH_RELAY_RECOVERY_ONLY" \
      "$HEALTH_RELAY_CIRCUIT_OPEN" "$HEALTH_RELAY_LAST_RESORT" "$STATE_EFFECTIVE_ZERO_STREAK" \
      "$RELAY_UNAVAILABLE_15S" "$RELAY_UNAVAILABLE_120S" "$RELAY_AVAILABILITY_15S" \
      "$RELAY_AVAILABILITY_120S" "$RELAY_SUCCESSES_AFTER_PROOF" \
      "$(json_quote "$HEALTH_GUARDIAN_STATUS")")"
}

usage() {
  printf 'usage: %s {reconcile|status|prepare-maintenance|finish-maintenance}\n' "$0" >&2
}

command="${1:-reconcile}"
case "$command" in
  reconcile|status|prepare-maintenance|finish-maintenance) ;;
  *) usage; exit 64 ;;
esac

case "$command" in
  prepare-maintenance|finish-maintenance)
    if ! "$FLOCK_BIN" --wait "$LOCK_WAIT_SECONDS" 9; then
      emit_event "critical" "$command" "controller_lock_timeout" \
        "$(printf '{"wait_seconds":%s}' "$LOCK_WAIT_SECONDS")"
      exit 75
    fi
    ;;
  reconcile|status)
    if ! "$FLOCK_BIN" --nonblock 9; then
      emit_event "skipped" "$command" "controller_already_running" '{}'
      exit 0
    fi
    ;;
esac

# Exclusive controller ownership means no matching temp file can still be in
# use by another controller process. Remove crash leftovers only after the lock
# has been acquired.
cleanup_stale_sensitive_files

case "$command" in
  reconcile) reconcile ;;
  status) status_command ;;
  prepare-maintenance) prepare_maintenance ;;
  finish-maintenance) finish_maintenance ;;
esac
