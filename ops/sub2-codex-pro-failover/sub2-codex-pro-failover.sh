#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly GROUP_NAME="${GROUP_NAME:-codex-pro}"
readonly BRIDGE_ACCOUNT_ID="${BRIDGE_ACCOUNT_ID:-7692}"
readonly HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8090/health}"
readonly SUB2_ADMIN_BASE_URL="${SUB2_ADMIN_BASE_URL:-http://127.0.0.1:18082}"
readonly SUB2_POSTGRES_CONTAINER="${SUB2_POSTGRES_CONTAINER:-sub2api-postgres}"
readonly SUB2_REDIS_CONTAINER="${SUB2_REDIS_CONTAINER:-sub2api-redis}"
readonly DOCKER_BIN="${DOCKER_BIN:-docker}"
readonly CURL_BIN="${CURL_BIN:-curl}"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"
readonly FLOCK_BIN="${FLOCK_BIN:-flock}"
readonly RECOVERY_CONFIRMATIONS="${RECOVERY_CONFIRMATIONS:-3}"
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
HEALTH_GUARDIAN_STATUS="unknown"
STATE_MODE="normal"
STATE_HEALTHY_STREAK=0
STATE_LAST_REASON="startup"
STATE_PROOF_AFTER=""
CURRENT_CONDITION="unknown"
ACTIVE_HEADER_FILE=""
ACTIVE_RESPONSE_FILE=""

declare -a MEMBER_IDS=()
declare -a BACKUP_IDS=()
declare -A MEMBER_NAME_B64=()
declare -A MEMBER_STATUS=()
declare -A MEMBER_SCHEDULABLE=()
declare -A MEMBER_NOT_DELETED=()
declare -A MEMBER_RUNTIME_READY=()

cleanup_current_sensitive_files() {
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
  local details="${4:-{}}"
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
  "RECOVERY_CONFIRMATIONS:$RECOVERY_CONFIRMATIONS" \
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

  [[ -n "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]+x}" ]] || {
    emit_event "critical" "inventory" "primary_not_in_group" '{}'
    return 1
  }
  return 0
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
  "$DOCKER_BIN" exec "$SUB2_REDIS_CONTAINER" env -u REDISCLI_AUTH redis-cli --raw "$@"
}

ready_openai_buckets() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call buckets "$GROUP_ID"
    return
  fi
  local bucket
  while IFS= read -r bucket; do
    [[ "$bucket" == "${GROUP_ID}:openai:"* ]] || continue
    if [[ "$(redis_raw GET "sched:ready:${bucket}")" == "1" ]]; then
      printf '%s\n' "$bucket"
    fi
  done < <(redis_raw SMEMBERS sched:buckets)
}

bucket_snapshot_key() {
  local bucket="$1"
  local version
  version="$(redis_raw GET "sched:active:${bucket}")" || return 1
  [[ "$version" =~ ^[0-9]+$ ]] || return 1
  printf 'sched:%s:v%s\n' "$bucket" "$version"
}

bucket_ready_active() {
  local bucket="$1"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call bucket-ready "$GROUP_ID" "$bucket"
    return
  fi
  [[ "$(redis_raw GET "sched:ready:${bucket}")" == "1" ]] || return 1
  local snapshot_key
  snapshot_key="$(bucket_snapshot_key "$bucket")" || return 1
  [[ "$(redis_raw EXISTS "$snapshot_key")" == "1" ]]
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
  snapshot_key="$(bucket_snapshot_key "$bucket")" || return 1
  [[ -n "$(redis_raw ZSCORE "$snapshot_key" "$account_id")" ]]
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
    bucket_ready_active "$bucket" || return 1
    bucket_contains_account "$bucket" "$account_id" || return 1
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
    bucket_ready_active "$bucket" || return 1
    if bucket_contains_account "$bucket" "$account_id"; then
      return 1
    else
      local rc=$?
      (( rc == 1 )) || return 1
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
    bucket_ready_active "$bucket" || return 1
    found=false
    for id in "${candidates[@]}"; do
      if bucket_contains_account "$bucket" "$id"; then
        found=true
        break
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

api_set_schedulable() {
  local account_id="$1"
  local desired="$2"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call set-schedulable "$account_id" "$desired"
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' --max-time 15 -X POST \
    --header "@$ACTIVE_HEADER_FILE" -H 'Content-Type: application/json' \
    --data "{\"schedulable\":${desired}}" \
    "$SUB2_ADMIN_BASE_URL/api/v1/admin/accounts/$account_id/schedulable")" || {
      cleanup_current_sensitive_files
      return 1
    }
  cleanup_current_sensitive_files
  [[ "$code" == "200" ]]
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

  local current="${MEMBER_SCHEDULABLE[$account_id]}"
  local expected_db="$([[ "$desired" == true ]] && printf t || printf f)"
  if [[ "$current" == "$expected_db" ]]; then
    if wait_for_account_snapshot "$account_id" "$desired"; then
      return 0
    fi
  fi

  api_set_schedulable "$account_id" "$desired" || {
    emit_event "critical" "set_schedulable" "admin_api_failed" \
      "$(printf '{"account_id":%s,"desired":%s}' "$(json_quote "$account_id")" "$desired")"
    return 1
  }
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
  local eligible=0
  for id in "${BACKUP_IDS[@]}"; do
    eligible=$((eligible + 1))
    if [[ "${MEMBER_SCHEDULABLE[$id]}" != "t" ]]; then
      set_schedulable_guarded "$id" true || return 1
    fi
  done
  (( eligible > 0 )) || {
    emit_event "critical" "open_backups" "no_active_backup_accounts" '{}'
    return 1
  }
  wait_for_backups_ready || {
    emit_event "critical" "open_backups" "backup_scheduler_snapshot_not_ready" '{}'
    return 1
  }
  emit_event "ok" "open_backups" "backups_ready" \
    "$(printf '{"eligible_backups":%s}' "$eligible")"
}

close_backups() {
  load_members || return 1
  local id
  for id in "${BACKUP_IDS[@]}"; do
    if [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]]; then
      if ! evaluate_condition; then
        emit_event "degraded" "close_backups" "recovery_condition_changed_backups_held" \
          "$(printf '{"trigger":%s,"next_account_id":%s}' "$(json_quote "$CURRENT_CONDITION")" "$(json_quote "$id")")"
        return 1
      fi
      set_schedulable_guarded "$id" false || return 1
    fi
  done
  if ! evaluate_condition; then
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
print("|".join((
    str(p.get("status") or "unknown"),
    str(int(p.get("available") if isinstance(p.get("available"), (int,float)) else -1)),
    str(int(r.get("schedulable") if isinstance(r.get("schedulable"), (int,float)) else -1)),
    str(g.get("status") or "unknown"),
)))
')" || return 1
  fi
  IFS='|' read -r HEALTH_SERVICE_STATUS HEALTH_AVAILABLE HEALTH_RELAY_SCHEDULABLE HEALTH_GUARDIAN_STATUS <<<"$normalized"
  [[ "$HEALTH_AVAILABLE" =~ ^-?[0-9]+$ && "$HEALTH_RELAY_SCHEDULABLE" =~ ^-?[0-9]+$ ]]
}

read_state() {
  STATE_MODE="normal"
  STATE_HEALTHY_STREAK=0
  STATE_LAST_REASON="startup"
  STATE_PROOF_AFTER=""
  [[ -s "$STATE_FILE" ]] || return 0
  local normalized
  normalized="$("$PYTHON_BIN" - "$STATE_FILE" <<'PY'
import json,sys
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
except Exception:
    raise SystemExit(1)
print('|'.join((
    str(p.get('mode') or 'normal'),
    str(int(p.get('healthy_streak') or 0)),
    str(p.get('last_reason') or 'unknown'),
    str(p.get('proof_after') or ''),
)))
PY
)" || return 1
  IFS='|' read -r STATE_MODE STATE_HEALTHY_STREAK STATE_LAST_REASON STATE_PROOF_AFTER <<<"$normalized"
  [[ "$STATE_HEALTHY_STREAK" =~ ^[0-9]+$ ]]
}

write_state() {
  local mode="$1"
  local healthy_streak="$2"
  local last_reason="$3"
  local proof_after="${4:-}"
  local tmp
  tmp="$(mktemp "$STATE_DIR/state.XXXXXX")"
  "$PYTHON_BIN" - "$tmp" "$STATE_FILE" "$mode" "$healthy_streak" "$last_reason" "$proof_after" <<'PY'
import datetime as dt,json,os,sys
tmp,path,mode,streak,reason,proof_after=sys.argv[1:]
p={
  'schema_version':1,
  'mode':mode,
  'healthy_streak':int(streak),
  'last_reason':reason,
  'proof_after':proof_after or None,
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
  local tmp
  tmp="$(mktemp "$STATE_DIR/maintenance.XXXXXX")"
  "$PYTHON_BIN" - "$tmp" "$MAINTENANCE_FILE" "$reason" "$primary_owned" <<'PY'
import datetime as dt,json,os,sys
tmp,path,reason,owned=sys.argv[1:]
p={
  'schema_version':1,
  'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),
  'reason':reason,
  'primary_disabled_by_maintenance':owned == 'true',
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

maintenance_primary_owned() {
  [[ -s "$MAINTENANCE_FILE" ]] || {
    printf 'false\n'
    return
  }
  "$PYTHON_BIN" - "$MAINTENANCE_FILE" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
print('true' if p.get('primary_disabled_by_maintenance') else 'false')
PY
}

now_rfc3339() {
  date --iso-8601=seconds
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
  if ! fetch_health; then
    CURRENT_CONDITION="service_health_unreachable"
    return 1
  fi
  if [[ "$HEALTH_SERVICE_STATUS" != "ok" || "$HEALTH_AVAILABLE" -le 0 ]]; then
    CURRENT_CONDITION="service_unhealthy"
    return 1
  fi
  if (( HEALTH_RELAY_SCHEDULABLE <= 0 )); then
    CURRENT_CONDITION="relay_zero"
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
    emit_event "critical" "reconcile" "state_invalid" '{}'
    return 2
  }
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    open_backups || return 2
    write_state "maintenance" 0 "maintenance_marker_present" "$STATE_PROOF_AFTER"
    emit_event "ok" "reconcile" "maintenance_backups_held_open" '{}'
    return 0
  fi

  local schedulable_backups
  schedulable_backups="$(active_backup_count)" || return 2
  if (( schedulable_backups > 0 )) && [[ -z "$STATE_PROOF_AFTER" ]]; then
    STATE_PROOF_AFTER="$(now_rfc3339)"
    write_state "recovery_pending" 0 "primary_success_proof_started" "$STATE_PROOF_AFTER"
    emit_event "ok" "reconcile" "primary_success_proof_pending" \
      "$(printf '{"proof_after":%s}' "$(json_quote "$STATE_PROOF_AFTER")")"
    return 0
  fi

  if evaluate_condition; then
    local next=$((STATE_HEALTHY_STREAK + 1))
    if (( next >= RECOVERY_CONFIRMATIONS )); then
      close_backups || return 2
      write_state "normal" "$RECOVERY_CONFIRMATIONS" "healthy" ""
      emit_event "ok" "reconcile" "normal_primary_preferred" \
        "$(printf '{"healthy_streak":%s,"guardian_status":%s}' "$RECOVERY_CONFIRMATIONS" "$(json_quote "$HEALTH_GUARDIAN_STATUS")")"
    else
      write_state "recovery_pending" "$next" "healthy" "$STATE_PROOF_AFTER"
      emit_event "ok" "reconcile" "recovery_confirmation_pending" \
        "$(printf '{"healthy_streak":%s,"required":%s}' "$next" "$RECOVERY_CONFIRMATIONS")"
    fi
    return 0
  fi

  open_backups || return 2
  local proof_after="$STATE_PROOF_AFTER"
  if [[ -z "$proof_after" || ( "$STATE_MODE" != "failover" && "$CURRENT_CONDITION" != "primary_success_unproven" ) ]]; then
    proof_after="$(now_rfc3339)"
  fi
  write_state "failover" 0 "$CURRENT_CONDITION" "$proof_after"
  emit_event "degraded" "reconcile" "standby_takeover_active" \
    "$(printf '{"trigger":%s,"guardian_status":%s}' "$(json_quote "$CURRENT_CONDITION")" "$(json_quote "$HEALTH_GUARDIAN_STATUS")")"
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
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    existing_owned="$(maintenance_primary_owned)" || return 2
  fi
  write_maintenance_marker "planned_codex2api_maintenance" "$existing_owned"
  open_backups || {
    emit_event "critical" "prepare_maintenance" "backup_takeover_not_ready_primary_unchanged" '{}'
    return 2
  }
  load_members || return 2
  if [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}" != "active" || "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    emit_event "critical" "prepare_maintenance" "primary_not_active_primary_unchanged" '{}'
    return 2
  fi

  if [[ "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}" == "t" ]]; then
    write_maintenance_marker "planned_codex2api_maintenance" true
    set_schedulable_guarded "$BRIDGE_ACCOUNT_ID" false || return 2
  fi
  wait_for_primary_drain || {
    emit_event "critical" "prepare_maintenance" "primary_drain_timeout_backups_left_open" '{}'
    return 2
  }
  write_state "maintenance" 0 "maintenance_prepared" "$(now_rfc3339)"
  emit_event "ok" "prepare_maintenance" "maintenance_ready" '{}'
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

  local owned
  owned="$(maintenance_primary_owned)" || return 2
  if [[ "$owned" == true ]]; then
    set_schedulable_guarded "$BRIDGE_ACCOUNT_ID" true || {
      emit_event "critical" "finish_maintenance" "primary_restore_failed_backups_left_open" '{}'
      return 2
    }
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

  if (( HEALTH_RELAY_SCHEDULABLE <= 0 )); then
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
  read_state || return 2
  fetch_health || true
  local active_backups=0 id
  for id in "${BACKUP_IDS[@]}"; do
    [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" ]] && active_backups=$((active_backups + 1))
  done
  emit_event "ok" "status" "status_snapshot" \
    "$(printf '{"mode":%s,"healthy_streak":%s,"maintenance":%s,"primary_status":%s,"primary_schedulable":%s,"eligible_backups":%s,"schedulable_backups":%s,"service_status":%s,"relay_schedulable":%s,"guardian_status":%s}' \
      "$(json_quote "$STATE_MODE")" "$STATE_HEALTHY_STREAK" \
      "$([[ -e "$MAINTENANCE_FILE" ]] && printf true || printf false)" \
      "$(json_quote "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}")" \
      "$([[ "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}" == t ]] && printf true || printf false)" \
      "${#BACKUP_IDS[@]}" "$active_backups" \
      "$(json_quote "$HEALTH_SERVICE_STATUS")" "$HEALTH_RELAY_SCHEDULABLE" \
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
