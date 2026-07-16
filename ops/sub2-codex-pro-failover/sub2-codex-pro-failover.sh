#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly GROUP_NAME="${GROUP_NAME:-codex-pro}"
readonly FAILOVER_CONFIG_FILE="${FAILOVER_CONFIG_FILE:-/etc/default/codex2api-sub2-codex-pro-failover}"
BRIDGE_ACCOUNT_ID="${BRIDGE_ACCOUNT_ID:-}"

configuration_error() {
  printf 'sub2-codex-pro-failover: %s\n' "$1" >&2
  exit 64
}

load_bridge_account_id() {
  [[ -z "$BRIDGE_ACCOUNT_ID" ]] || return 0
  [[ -r "$FAILOVER_CONFIG_FILE" ]] || configuration_error "BRIDGE_ACCOUNT_ID_required_config_unreadable"

  local line value="" matches=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" == BRIDGE_ACCOUNT_ID=* ]]; then
      matches=$((matches + 1))
      value="${line#BRIDGE_ACCOUNT_ID=}"
    fi
  done <"$FAILOVER_CONFIG_FILE"

  (( matches == 1 )) || configuration_error "BRIDGE_ACCOUNT_ID_required_config_invalid"
  BRIDGE_ACCOUNT_ID="$value"
}

load_bridge_account_id
readonly BRIDGE_ACCOUNT_ID
readonly HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8090/health}"
readonly SUB2_ADMIN_BASE_URL="${SUB2_ADMIN_BASE_URL:-http://127.0.0.1:18082}"
readonly SUB2_POSTGRES_CONTAINER="${SUB2_POSTGRES_CONTAINER:-sub2api-postgres}"
readonly SUB2_REDIS_CONTAINER="${SUB2_REDIS_CONTAINER:-sub2api-redis}"
readonly SUB2_API_CONTAINER="${SUB2_API_CONTAINER:-sub2api}"
readonly CODEX_POSTGRES_CONTAINER="${CODEX_POSTGRES_CONTAINER:-codex2api-postgres}"
readonly DOCKER_BIN="${DOCKER_BIN:-docker}"
readonly CURL_BIN="${CURL_BIN:-curl}"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"
readonly FLOCK_BIN="${FLOCK_BIN:-flock}"
readonly TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
readonly BACKUP_OPEN_PARALLELISM="${BACKUP_OPEN_PARALLELISM:-4}"
readonly SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS="${SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS:-5}"
readonly PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS="${PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS:-20}"
readonly BACKUP_OPEN_BATCH_TIMEOUT_SECONDS="${BACKUP_OPEN_BATCH_TIMEOUT_SECONDS:-120}"
readonly MAINTENANCE_RECEIPT_TIMEOUT_SECONDS="${MAINTENANCE_RECEIPT_TIMEOUT_SECONDS:-90}"
readonly MAINTENANCE_DRAIN_SETTLE_SECONDS="${MAINTENANCE_DRAIN_SETTLE_SECONDS:-10}"
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
readonly MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS="${MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS:-90}"
readonly SNAPSHOT_POLL_SECONDS="${SNAPSHOT_POLL_SECONDS:-1}"
readonly DRAIN_TIMEOUT_SECONDS="${DRAIN_TIMEOUT_SECONDS:-600}"
readonly DRAIN_POLL_SECONDS="${DRAIN_POLL_SECONDS:-5}"
readonly LOCK_WAIT_SECONDS="${LOCK_WAIT_SECONDS:-30}"
readonly STATE_DIR="${STATE_DIRECTORY:-${FAILOVER_STATE_DIR:-/var/lib/codex2api-sub2-codex-pro-failover}}"
readonly RUNTIME_DIR="${RUNTIME_DIRECTORY:-${FAILOVER_RUNTIME_DIR:-/run/codex2api-sub2-codex-pro-failover}}"
readonly STATE_FILE="$STATE_DIR/state.json"
readonly MAINTENANCE_FILE="$STATE_DIR/maintenance.json"
readonly MAINTENANCE_AMBIGUITY_FILE="$STATE_DIR/maintenance-ambiguous.json"
readonly LOCK_FILE="$RUNTIME_DIR/controller.lock"
readonly TEST_BACKEND="${FAILOVER_TEST_BACKEND:-}"
readonly TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER="${FAILOVER_TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER:-0}"
readonly TEST_STOP_AFTER_SEAL_RESOLUTION_COMMIT="${FAILOVER_TEST_STOP_AFTER_SEAL_RESOLUTION_COMMIT:-0}"

GROUP_ID=""
GROUP_DISCOVERY_RESULT="unverifiable"
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
SCHEDULABLE_WRITE_HTTP_OK=false
SCHEDULABLE_WRITE_UPDATED_AT=""
MAINTENANCE_MARKER_WRITE_COUNT=0
M_PHASE=""
M_RUN_ID=""
M_PRIMARY_ACCOUNT_ID=""
M_GROUP_ID=""
M_GROUP_MEMBER_IDS=""
M_BACKUP_ACCOUNT_IDS=""
M_IDENTITY_DIGEST=""
M_LOG_WATERMARK=""
M_INCARNATION=""
M_SINK_DROPPED=""
M_SINK_FAILED=""
M_SINK_WRITTEN=""
M_PAUSE_REQUEST_ID=""
M_PAUSE_LOG_ID=""
M_PAUSE_RESPONSE_CHECKPOINT="none"
M_PAUSE_RESPONSE_UPDATED_AT=""
M_SEAL_REQUEST_ID=""
M_SEAL_LOG_ID=""
M_SEAL_RESPONSE_UPDATED_AT=""
M_RESTORE_REQUEST_ID=""
M_RESTORE_LOG_ID=""
M_RESTORE_RESPONSE_CHECKPOINT="none"
M_RESTORE_RESPONSE_UPDATED_AT=""
M_OWNED_UPDATED_AT=""
M_OWNED_XMIN=""
M_SIDECAR_ONLY=false
M_AMBIGUITY_RUN_ID=""
M_AMBIGUITY_PRIMARY_ACCOUNT_ID=""
M_AMBIGUITY_GROUP_ID=""
M_AMBIGUITY_GROUP_MEMBER_IDS=""
M_AMBIGUITY_BACKUP_ACCOUNT_IDS=""
M_AMBIGUITY_IDENTITY_DIGEST=""
M_AMBIGUITY_PHASE=""
M_AMBIGUITY_REASON=""
M_AMBIGUITY_CREATED_AT=""
MAINTENANCE_IDENTITY_ERROR=""
MAINTENANCE_FOREIGN_FENCE_RESULT="unverifiable"
MAINTENANCE_RECEIPT_RESULT="unverifiable"
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
declare -A MEMBER_ACTIVE_GROUP_COUNT=()

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

validate_account_id() {
  local name="$1"
  local value="$2"
  validate_positive_integer "$name" "$value"
  local maximum=9223372036854775807
  if (( ${#value} > ${#maximum} )) ||
     (( ${#value} == ${#maximum} )) && [[ "$value" > "$maximum" ]]; then
    die "${name}_out_of_bigint_range"
  fi
}

[[ "$BRIDGE_ACCOUNT_ID" =~ ^[1-9][0-9]*$ ]] || configuration_error "BRIDGE_ACCOUNT_ID_must_be_positive_integer"
bridge_account_id_maximum=9223372036854775807
if (( ${#BRIDGE_ACCOUNT_ID} > ${#bridge_account_id_maximum} )); then
  configuration_error "BRIDGE_ACCOUNT_ID_out_of_bigint_range"
fi
if (( ${#BRIDGE_ACCOUNT_ID} == ${#bridge_account_id_maximum} )) &&
   [[ "$BRIDGE_ACCOUNT_ID" > "$bridge_account_id_maximum" ]]; then
  configuration_error "BRIDGE_ACCOUNT_ID_out_of_bigint_range"
fi
readonly bridge_account_id_maximum
for pair in \
  "BACKUP_OPEN_PARALLELISM:$BACKUP_OPEN_PARALLELISM" \
  "SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS:$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS" \
  "PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS:$PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS" \
  "BACKUP_OPEN_BATCH_TIMEOUT_SECONDS:$BACKUP_OPEN_BATCH_TIMEOUT_SECONDS" \
  "MAINTENANCE_RECEIPT_TIMEOUT_SECONDS:$MAINTENANCE_RECEIPT_TIMEOUT_SECONDS" \
  "MAINTENANCE_DRAIN_SETTLE_SECONDS:$MAINTENANCE_DRAIN_SETTLE_SECONDS" \
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
  "MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS:$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" \
  "SNAPSHOT_POLL_SECONDS:$SNAPSHOT_POLL_SECONDS" \
  "DRAIN_TIMEOUT_SECONDS:$DRAIN_TIMEOUT_SECONDS" \
  "DRAIN_POLL_SECONDS:$DRAIN_POLL_SECONDS" \
  "LOCK_WAIT_SECONDS:$LOCK_WAIT_SECONDS"; do
  validate_positive_integer "${pair%%:*}" "${pair#*:}"
done
if [[ -n "$TEST_BACKEND" && ! "$TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER" =~ ^[0-9]+$ ]]; then
  die "FAILOVER_TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER_must_be_non_negative_integer"
fi
if [[ -n "$TEST_BACKEND" && ! "$TEST_STOP_AFTER_SEAL_RESOLUTION_COMMIT" =~ ^[01]$ ]]; then
  die "FAILOVER_TEST_STOP_AFTER_SEAL_RESOLUTION_COMMIT_must_be_boolean_integer"
fi

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
  GROUP_DISCOVERY_RESULT="unverifiable"
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
    GROUP_DISCOVERY_RESULT="mismatch"
    emit_event "critical" "discover_group" "active_group_not_unique" \
      "$(printf '{"matching_groups":%s,"group_name":%s}' "$count" "$(json_quote "$GROUP_NAME")")"
    return 1
  fi
  GROUP_DISCOVERY_RESULT="match"
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
  ),
  (
    SELECT COUNT(*)
    FROM account_groups ag2
    JOIN groups g2 ON g2.id = ag2.group_id
    WHERE ag2.account_id = a.id
      AND g2.deleted_at IS NULL
      AND g2.status = 'active'
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
  MEMBER_ACTIVE_GROUP_COUNT=()

  local rows
  rows="$(query_members)" || return 1
  local id name_b64 status schedulable not_deleted runtime_ready active_group_count
  while IFS='|' read -r id name_b64 status schedulable not_deleted runtime_ready active_group_count; do
    [[ "$id" =~ ^[1-9][0-9]*$ ]] || continue
    MEMBER_IDS+=("$id")
    MEMBER_NAME_B64["$id"]="$name_b64"
    MEMBER_STATUS["$id"]="$status"
    MEMBER_SCHEDULABLE["$id"]="$schedulable"
    MEMBER_NOT_DELETED["$id"]="$not_deleted"
    MEMBER_RUNTIME_READY["$id"]="$runtime_ready"
    MEMBER_ACTIVE_GROUP_COUNT["$id"]="$active_group_count"
    if [[ "$id" != "$BRIDGE_ACCOUNT_ID" && "$status" == "active" && "$not_deleted" == "t" &&
          "$active_group_count" == "1" ]]; then
      BACKUP_IDS+=("$id")
    fi
  done <<<"$rows"

  return 0
}

# Produce a stable, content-only snapshot of every current member that can
# affect maintenance ownership.  Names and runtime-ready timestamps are
# deliberately excluded; membership, status, schedulability, deletion state,
# and active-group count are the control-plane fields that must stay stable
# while an explicit ambiguity resolution is being proved.
maintenance_group_membership_snapshot() {
  load_members || return 1
  (( ${#MEMBER_IDS[@]} > 0 )) || return 1
  local id
  for id in "${MEMBER_IDS[@]}"; do
    printf '%s|%s|%s|%s|%s\n' "$id" \
      "${MEMBER_STATUS[$id]}" "${MEMBER_SCHEDULABLE[$id]}" \
      "${MEMBER_NOT_DELETED[$id]}" "${MEMBER_ACTIVE_GROUP_COUNT[$id]}"
  done | LC_ALL=C sort -t '|' -k1,1n
}

# Canonical, immutable identity of the full live membership at maintenance
# marker creation time.  Keep every account_groups row (including inactive or
# deleted accounts); only the numeric IDs are sealed because a later account
# DELETE may cascade the live membership row before its access log is fenced.
loaded_group_member_ids() {
  (( ${#MEMBER_IDS[@]} > 0 )) || return 1
  local id
  local -a ids=()
  for id in "${MEMBER_IDS[@]}"; do
    [[ "$id" =~ ^[1-9][0-9]{0,18}$ ]] || return 1
    if (( ${#id} == 19 )) && [[ "$id" > "9223372036854775807" ]]; then
      return 1
    fi
    ids+=("$id")
  done
  local canonical count
  canonical="$(printf '%s\n' "${ids[@]}" | LC_ALL=C sort -n -u | paste -sd, -)" || return 1
  count="$(tr ',' '\n' <<<"$canonical" | wc -l)" || return 1
  (( count == ${#ids[@]} )) || return 1
  [[ "$canonical" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
  printf '%s\n' "$canonical"
}

loaded_backup_account_ids() {
  (( ${#BACKUP_IDS[@]} > 0 )) || return 1
  local id
  local -a ids=()
  for id in "${BACKUP_IDS[@]}"; do
    [[ "$id" =~ ^[1-9][0-9]{0,18}$ ]] || return 1
    if (( ${#id} == 19 )) && [[ "$id" > "9223372036854775807" ]]; then
      return 1
    fi
    [[ "$id" != "$BRIDGE_ACCOUNT_ID" ]] || return 1
    ids+=("$id")
  done
  local canonical count
  canonical="$(printf '%s\n' "${ids[@]}" | LC_ALL=C sort -n -u | paste -sd, -)" || return 1
  count="$(tr ',' '\n' <<<"$canonical" | wc -l)" || return 1
  (( count == ${#ids[@]} )) || return 1
  [[ "$canonical" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
  printf '%s\n' "$canonical"
}

# Once a maintenance artifact exists, its backup collection is an authorization
# boundary, not merely an audit field. A member that becomes eligible later was
# never sealed by this run and must cause a zero-write abort. Sealed members
# that later become ineligible are simply omitted; callers may only consider the
# sealed/live-eligible intersection.
scope_backup_ids_to_maintenance_identity() {
  local action="${1:-maintenance_backup_scope}"
  [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]] || return 0
  [[ -n "$M_BACKUP_ACCOUNT_IDS" ]] || return 0
  [[ "$M_BACKUP_ACCOUNT_IDS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
  local sealed=",${M_BACKUP_ACCOUNT_IDS},"
  local id
  local -a scoped=()
  for id in "${BACKUP_IDS[@]}"; do
    if [[ "$sealed" != *",${id},"* ]]; then
      emit_event "critical" "$action" "unsealed_backup_became_eligible" \
        "$(printf '{"account_id":%s,"account_writes":0,"operator_action_required":true}' \
          "$(json_quote "$id")")"
      return 2
    fi
    scoped+=("$id")
  done
  BACKUP_IDS=("${scoped[@]}")
}

verify_sidecar_backup_identity() {
  [[ "$M_SIDECAR_ONLY" == true ]] || return 0
  local current_backup_ids
  current_backup_ids="$(loaded_backup_account_ids)" || return 1
  [[ "$current_backup_ids" == "$M_BACKUP_ACCOUNT_IDS" ]]
}

primary_is_group_member() {
  [[ -n "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]+x}" ]]
}

primary_is_exclusive_group_member() {
  primary_is_group_member &&
    [[ "${MEMBER_ACTIVE_GROUP_COUNT[$BRIDGE_ACCOUNT_ID]:-0}" == 1 &&
       "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]:-}" == active &&
       "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]:-}" == t ]]
}

verify_maintenance_group_identity() {
  local expected_group_id="$1"
  local previous_group_id="$GROUP_ID"
  if ! discover_group; then
    local discovery_result="$GROUP_DISCOVERY_RESULT"
    GROUP_ID="$previous_group_id"
    [[ "$discovery_result" == mismatch ]] && return 2
    return 1
  fi
  if [[ "$GROUP_ID" != "$expected_group_id" ]]; then
    emit_event "critical" "maintenance_group_fence" "active_group_identity_changed" \
      '{"operator_action_required":true}'
    GROUP_ID="$previous_group_id"
    return 2
  fi
  load_members || return 1
  if ! primary_is_exclusive_group_member; then
    emit_event "critical" "maintenance_group_fence" "configured_primary_group_membership_not_exclusive" \
      '{"operator_action_required":true}'
    return 2
  fi
  if [[ -n "$M_GROUP_MEMBER_IDS" ]]; then
    local current_member_ids
    current_member_ids="$(loaded_group_member_ids)" || return 1
    if [[ "$current_member_ids" != "$M_GROUP_MEMBER_IDS" ]]; then
      emit_event "critical" "maintenance_group_fence" \
        "maintenance_group_membership_changed" \
        '{"operator_action_required":true}'
      return 2
    fi
  fi
  local backup_scope_rc=0
  scope_backup_ids_to_maintenance_identity "maintenance_group_fence" || backup_scope_rc=$?
  if (( backup_scope_rc != 0 )); then
    if (( backup_scope_rc != 2 )); then
      emit_event "critical" "maintenance_group_fence" \
        "maintenance_backup_identity_unverifiable" '{"account_writes":0}'
    fi
    (( backup_scope_rc == 2 )) && return 2 || return 1
  fi
  if ! verify_sidecar_backup_identity; then
    emit_event "critical" "maintenance_group_fence" "sidecar_backup_identity_changed" \
      '{"operator_action_required":true,"account_writes":0}'
    return 2
  fi
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
import datetime as dt, json, re, sys
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
def parse_rfc3339(value):
    match=re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?"
        r"(Z|[+-]\d{2}:\d{2})",str(value))
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or "")+"000000")[:6]
    zone="+00:00" if zone == "Z" else zone
    stamp=dt.datetime.fromisoformat(f"{base}.{fraction}{zone}")
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
def future(value):
    if not value:
        return False
    return parse_rfc3339(value) > now
try:
    blocked=(future(a.get("RateLimitResetAt")) or
             future(a.get("OverloadUntil")) or
             future(a.get("TempUnschedulableUntil")))
    expired=(a.get("AutoPauseOnExpired") and a.get("ExpiresAt") and
             not future(a.get("ExpiresAt")))
except Exception:
    raise SystemExit(1)
if blocked or expired:
    raise SystemExit(1)
' "$expected"
}

# The full scheduler account cache intentionally contains credentials. Never
# return it. Project only the three control fields needed to bind a successful
# maintenance write to scheduler convergence.
full_account_control_projection() {
  local account_id="$1"
  local backend_command="${2:-full-account}"
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call "$backend_command" "$account_id"
    return
  fi
  local lua
  read -r -d '' lua <<'LUA' || true
local raw = redis.call('GET', KEYS[1])
if not raw then return '' end
local ok, a = pcall(cjson.decode, raw)
if not ok then return '' end
return cjson.encode({Status=a.Status,Schedulable=a.Schedulable,UpdatedAt=a.UpdatedAt})
LUA
  redis_raw EVAL "$lua" 1 "sched:acc:${account_id}"
}

full_account_control_matches() {
  local account_id="$1"
  local expected="$2"
  local expected_updated_at="$3"
  local projection
  projection="$(full_account_control_projection "$account_id")" || return 1
  [[ -n "$projection" ]] || return 1
  printf '%s' "$projection" | "$PYTHON_BIN" -c '
import datetime as dt,json,re,sys
expected=sys.argv[1] == "true"
expected_updated_at=sys.argv[2]
def parse_rfc3339(value):
    match=re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?"
        r"(Z|[+-]\d{2}:\d{2})",str(value))
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or "")+"000000")[:6]
    zone="+00:00" if zone == "Z" else zone
    stamp=dt.datetime.fromisoformat(f"{base}.{fraction}{zone}")
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
try:
    account=json.load(sys.stdin)
    if account.get("Status") != "active" or bool(account.get("Schedulable")) is not expected:
        raise ValueError
    stamp=parse_rfc3339(account.get("UpdatedAt") or "")
    actual=stamp.isoformat(timespec="microseconds").replace("+00:00","Z")
    if actual != expected_updated_at:
        raise ValueError
except Exception:
    raise SystemExit(1)
' "$expected" "$expected_updated_at"
}

# State-only scheduler fences intentionally do not bind an UpdatedAt generation.
# Maintenance ownership calls full_account_control_matches directly with the
# exact synchronous response timestamp; keeping the two reads distinct lets the
# ownership state machine detect a later foreign generation instead of adopting
# it as a new baseline.
full_account_state_matches() {
  local account_id="$1"
  local expected="$2"
  local projection
  if [[ -n "$TEST_BACKEND" ]]; then
    projection="$(backend_call full-account-state "$account_id")" || return 1
  else
    projection="$(full_account_control_projection "$account_id")" || return 1
  fi
  [[ -n "$projection" ]] || return 1
  printf '%s' "$projection" | "$PYTHON_BIN" -c '
import datetime as dt,json,re,sys
expected=sys.argv[1] == "true"
def parse_rfc3339(value):
    match=re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?"
        r"(Z|[+-]\d{2}:\d{2})",str(value))
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or "")+"000000")[:6]
    zone="+00:00" if zone == "Z" else zone
    stamp=dt.datetime.fromisoformat(f"{base}.{fraction}{zone}")
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
try:
    account=json.load(sys.stdin)
    if account.get("Status") != "active" or bool(account.get("Schedulable")) is not expected:
        raise ValueError
    parse_rfc3339(account.get("UpdatedAt") or "")
except Exception:
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
  scope_backup_ids_to_maintenance_identity "backup_readiness" || return $?
  local -a candidates=()
  local id
  for id in "${BACKUP_IDS[@]}"; do
    if [[ "${MEMBER_SCHEDULABLE[$id]}" == "t" && "${MEMBER_RUNTIME_READY[$id]}" == "t" ]] &&
       meta_matches "$id" true && full_account_state_matches "$id" true; then
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
  local snapshot_timeout="${1:-$SNAPSHOT_TIMEOUT_SECONDS}"
  local deadline=$((SECONDS + snapshot_timeout))
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

account_snapshot_matches() {
  local account_id="$1"
  local expected="$2"
  local expected_updated_at="${3:-}"
  local db_ok=false meta_ok=false full_ok=false bucket_ok=true
  if load_members && [[ "${MEMBER_SCHEDULABLE[$account_id]:-}" == "$([[ "$expected" == true ]] && printf t || printf f)" ]]; then
    db_ok=true
  fi
  if meta_matches "$account_id" "$expected"; then
    meta_ok=true
  fi
  if [[ -n "$expected_updated_at" ]]; then
    full_account_control_matches "$account_id" "$expected" "$expected_updated_at" && full_ok=true
  elif full_account_state_matches "$account_id" "$expected"; then
    full_ok=true
  fi
  if [[ "$expected" == true ]]; then
    bucket_ok=false
    all_buckets_contain_account "$account_id" && bucket_ok=true
  fi
  # Closing is a scheduler-state fence, not a topology-cleanup fence. sub2
  # rechecks sched:meta for bucket candidates, sched:acc for sticky/account-id
  # paths, and the database on fallback/acquire paths. Once all three current
  # states are false, a stale ZSET member or a processed-but-not-deleted outbox row
  # cannot admit a new request and must not cause the controller to reopen the
  # standby. Opening remains stricter because the account must also be
  # discoverable from every current ready bucket before it can protect traffic.
  [[ "$db_ok" == true && "$meta_ok" == true && "$full_ok" == true && "$bucket_ok" == true ]]
}

account_snapshot_diagnostics_json() {
  local account_id="$1"
  local expected="$2"
  local expected_updated_at="${3:-}"
  local db_ok=false meta_ok=false full_ok=false bucket_ok=false
  local outbox_rows=null
  if load_members && [[ "${MEMBER_SCHEDULABLE[$account_id]:-}" == "$([[ "$expected" == true ]] && printf t || printf f)" ]]; then
    db_ok=true
  fi
  meta_matches "$account_id" "$expected" && meta_ok=true
  if [[ -n "$expected_updated_at" ]]; then
    full_account_control_matches "$account_id" "$expected" "$expected_updated_at" && full_ok=true
  else
    full_account_state_matches "$account_id" "$expected" && full_ok=true
  fi
  if [[ "$expected" == true ]]; then
    all_buckets_contain_account "$account_id" && bucket_ok=true
  else
    all_buckets_exclude_account "$account_id" && bucket_ok=true
  fi
  local raw_outbox
  raw_outbox="$(query_outbox_count "$account_id" 2>/dev/null || true)"
  [[ "$raw_outbox" =~ ^[0-9]+$ ]] && outbox_rows="$raw_outbox"
  printf '{"db_ok":%s,"meta_ok":%s,"full_ok":%s,"bucket_cleanup_complete":%s,"outbox_rows":%s}' \
    "$db_ok" "$meta_ok" "$full_ok" "$bucket_ok" "$outbox_rows"
}

wait_for_account_snapshot() {
  local account_id="$1"
  local expected="$2"
  local snapshot_timeout="${3:-$SNAPSHOT_TIMEOUT_SECONDS}"
  local expected_updated_at="${4:-}"
  local deadline=$((SECONDS + snapshot_timeout))
  local confirmations=0
  while (( SECONDS < deadline )); do
    if account_snapshot_matches "$account_id" "$expected" "$expected_updated_at"; then
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
  local request_id="${5:-}"
  if [[ -n "$request_id" ]]; then
    [[ "$desired" == true && "$account_id" != "$BRIDGE_ACCOUNT_ID" &&
       "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ &&
       "$request_id" == "c2m-${M_RUN_ID}-b-${account_id}" && ${#request_id} -le 64 ]] || return 1
  fi
  if [[ -n "$TEST_BACKEND" ]]; then
    local test_command=set-schedulable
    [[ -n "$request_id" ]] && test_command=set-schedulable-requested
    "$TIMEOUT_BIN" --signal=TERM --kill-after=1s "${request_timeout}s" \
      "$TEST_BACKEND" "$test_command" "$account_id" "$desired" "$request_id"
    return
  fi
  [[ -r "$header_file" ]] || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local -a request_id_header=()
  [[ -n "$request_id" ]] && request_id_header=(-H "X-Request-ID: $request_id")
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
    --connect-timeout 2 --max-time "$request_timeout" -X POST \
    --header "@$header_file" -H 'Content-Type: application/json' \
    "${request_id_header[@]}" \
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
    api_set_schedulable_with_header "$account_id" "$desired" "" \
      "$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS"
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

# Send one maintenance-owned primary mutation with a caller-generated request
# id. Return 0 only when the synchronous HTTP 200 body is structurally valid;
# callers must still verify the durable http.access receipt before advancing.
# Return 2 for a malformed 200 body and 1 for transport/non-200 outcomes.
api_set_primary_schedulable() {
  local account_id="$1"
  local desired="$2"
  local request_id="$3"
  [[ "$account_id" == "$BRIDGE_ACCOUNT_ID" ]] || return 2
  [[ "$desired" == true || "$desired" == false ]] || return 2
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore)$ ]] || return 2
  SCHEDULABLE_WRITE_HTTP_OK=false
  SCHEDULABLE_WRITE_UPDATED_AT=""
  cleanup_current_sensitive_files
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code="" transport_rc=0
  if [[ -n "$TEST_BACKEND" ]]; then
    if "$TIMEOUT_BIN" --signal=TERM --kill-after=1s "${PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS}s" \
      "$TEST_BACKEND" set-schedulable-receipted "$account_id" "$desired" "$request_id" \
      >"$ACTIVE_RESPONSE_FILE"; then
      code=200
    else
      transport_rc=$?
    fi
  else
    make_admin_header_file || {
      cleanup_current_sensitive_files
      return 1
    }
    code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
      --connect-timeout 2 --max-time "$PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS" -X POST \
      --header "@$ACTIVE_HEADER_FILE" -H 'Content-Type: application/json' \
      -H "X-Request-ID: $request_id" \
      --data "{\"schedulable\":${desired}}" \
      "$SUB2_ADMIN_BASE_URL/api/v1/admin/accounts/$account_id/schedulable")" || transport_rc=$?
  fi
  if (( transport_rc != 0 )) || [[ "$code" != "200" ]]; then
    cleanup_current_sensitive_files
    return 1
  fi
  local response_updated_at
  if ! response_updated_at="$("$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" "$account_id" "$desired" <<'PY'
import datetime as dt,json,re,sys
path,expected_id,desired=sys.argv[1:]
def parse_rfc3339(value):
    match=re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?'
        r'(Z|[+-]\d{2}:\d{2})',str(value))
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or '')+'000000')[:6]
    zone='+00:00' if zone == 'Z' else zone
    stamp=dt.datetime.fromisoformat(f'{base}.{fraction}{zone}')
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
try:
    payload=json.load(open(path,encoding='utf-8'))
    account=payload.get('data',payload)
    if isinstance(account,dict) and isinstance(account.get('account'),dict):
        account=account['account']
    if not isinstance(account,dict) or str(account.get('id')) != expected_id:
        raise ValueError('account id mismatch')
    schedulable=account.get('schedulable')
    if type(schedulable) is not bool or schedulable is not (desired == 'true'):
        raise ValueError('schedulable mismatch')
    if account.get('status') != 'active':
        raise ValueError('account not active')
    raw=account.get('updated_at') or account.get('updatedAt') or account.get('UpdatedAt') or ''
    stamp=parse_rfc3339(raw)
    print(stamp.isoformat(timespec='microseconds').replace('+00:00','Z'))
except Exception:
    raise SystemExit(1)
PY
)"; then
    cleanup_current_sensitive_files
    return 2
  fi
  cleanup_current_sensitive_files
  SCHEDULABLE_WRITE_HTTP_OK=true
  SCHEDULABLE_WRITE_UPDATED_AT="$response_updated_at"
  return 0
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
  normalized="$("$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" "$account_id" <<'PY'
import json,sys
path,expected_id=sys.argv[1:]
p=json.load(open(path,encoding='utf-8'))
if not isinstance(p,dict):
    raise ValueError('response is not an object')
a=p.get('data',p)
if isinstance(a,dict) and isinstance(a.get('account'),dict):
    a=a['account']
if not isinstance(a,dict) or str(a.get('id')) != expected_id:
    raise ValueError('account id mismatch')
status=a.get('status')
schedulable=a.get('schedulable')
concurrency=a.get('current_concurrency')
if not isinstance(status,str) or not status or '|' in status:
    raise ValueError('invalid status')
if type(schedulable) is not bool:
    raise ValueError('invalid schedulable')
if type(concurrency) is not int or concurrency < 0:
    raise ValueError('invalid current_concurrency')
print('|'.join((
    status,
    'true' if schedulable else 'false',
    str(concurrency),
)))
PY
)" || {
    cleanup_current_sensitive_files
    return 1
  }
  cleanup_current_sensitive_files
  printf '%s\n' "$normalized"
}

classify_primary_api_state() {
  local expected_schedulable="$1"
  local row status sched concurrency
  row="$(api_get_account "$BRIDGE_ACCOUNT_ID")" || return 1
  IFS='|' read -r status sched concurrency <<<"$row"
  [[ "$status" =~ ^[a-z_]+$ && "$sched" =~ ^(true|false)$ &&
     "$concurrency" =~ ^[0-9]+$ ]] || return 1
  if [[ "$status" != active || "$sched" != "$expected_schedulable" ]]; then
    return 2
  fi
}

classify_primary_api_state_drained() {
  local expected_schedulable="$1"
  local row status sched concurrency
  row="$(api_get_account "$BRIDGE_ACCOUNT_ID")" || return 1
  IFS='|' read -r status sched concurrency <<<"$row"
  [[ "$status" =~ ^[a-z_]+$ && "$sched" =~ ^(true|false)$ &&
     "$concurrency" =~ ^[0-9]+$ ]] || return 1
  if [[ "$status" != active || "$sched" != "$expected_schedulable" ||
        "$concurrency" != 0 ]]; then
    return 2
  fi
}

set_schedulable_guarded() {
  local account_id="$1"
  local desired="$2"
  local expected_primary_row_version="${3:-}"
  local snapshot_timeout="${4:-$SNAPSHOT_TIMEOUT_SECONDS}"
  SCHEDULABLE_WRITE_PERFORMED=false
  [[ "$snapshot_timeout" =~ ^[1-9][0-9]*$ ]] || return 1
  load_members || return 1
  scope_backup_ids_to_maintenance_identity "set_schedulable" || return 1
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
    [[ "$account_id" == "$BRIDGE_ACCOUNT_ID" && "$desired" == true ]] || return 1
    verify_primary_disabled_version "$expected_primary_row_version" || {
      emit_event "critical" "set_schedulable" "primary_row_version_changed_before_restore_write" \
        "$(printf '{\"expected_xmin\":%s}' "$(json_quote "$expected_primary_row_version")")"
      return 1
    }
  fi

  local current="${MEMBER_SCHEDULABLE[$account_id]}"
  local expected_db="$([[ "$desired" == true ]] && printf t || printf f)"
  if [[ "$current" == "$expected_db" ]]; then
    wait_for_account_snapshot "$account_id" "$desired" "$snapshot_timeout"
    return
  fi

  api_set_schedulable "$account_id" "$desired" || {
    emit_event "critical" "set_schedulable" "admin_api_failed" \
      "$(printf '{\"account_id\":%s,\"desired\":%s}' "$(json_quote "$account_id")" "$desired")"
    return 1
  }
  SCHEDULABLE_WRITE_PERFORMED=true
  wait_for_account_snapshot "$account_id" "$desired" "$snapshot_timeout" || {
    local snapshot_diagnostics
    snapshot_diagnostics="$(account_snapshot_diagnostics_json "$account_id" "$desired")"
    emit_event "critical" "set_schedulable" "scheduler_snapshot_not_confirmed" \
      "$(printf '{"account_id":%s,"desired":%s,"snapshot":%s}' \
        "$(json_quote "$account_id")" "$desired" "$snapshot_diagnostics")"
    return 1
  }
  load_members || true
	emit_event "ok" "set_schedulable" "account_schedulable_updated" \
	  "$(printf '{"account_id":%s,"account_name":%s,"desired":%s}' \
		  "$(json_quote "$account_id")" "$(json_quote "$(account_name "$account_id")")" "$desired")"
}

backup_open_target_live_eligible() {
  local account_id="$1"

  # Re-read the authoritative inventory in the child that will issue the POST.
  # Maintenance also re-proves the sealed full-group identity at this boundary.
  if [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]]; then
    [[ "$M_GROUP_ID" =~ ^[1-9][0-9]*$ && -n "$M_BACKUP_ACCOUNT_IDS" ]] || return 1
    verify_maintenance_group_identity "$M_GROUP_ID" || return 1
  else
    load_members || return 1
  fi
  scope_backup_ids_to_maintenance_identity "backup_open_submit_fence" || return 1

  [[ "$account_id" != "$BRIDGE_ACCOUNT_ID" &&
     "${MEMBER_STATUS[$account_id]:-}" == active &&
     "${MEMBER_NOT_DELETED[$account_id]:-}" == t &&
     "${MEMBER_ACTIVE_GROUP_COUNT[$account_id]:-0}" == 1 ]] || return 1
  if [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]]; then
    [[ ",${M_BACKUP_ACCOUNT_IDS}," == *",${account_id},"* ]] || return 1
  fi

  local id
  for id in "${BACKUP_IDS[@]}"; do
    [[ "$id" == "$account_id" ]] && return 0
  done
  return 1
}

open_backups() {
	local snapshot_timeout="${1:-$SNAPSHOT_TIMEOUT_SECONDS}"
	load_members || return 1
	scope_backup_ids_to_maintenance_identity "open_backups" || return 1
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
		if [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]]; then
			if ! verify_maintenance_group_identity "$M_GROUP_ID"; then
				inventory_skipped=$((total - next))
				failed=$((failed + inventory_skipped))
				emit_event "critical" "open_backups" "maintenance_group_changed_before_backup_batch" \
				  "$(printf '{\"unattempted_backups\":%s}' "$inventory_skipped")"
				cleanup_current_sensitive_files
				return 1
			fi
		elif ! load_members; then
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
			      "${MEMBER_NOT_DELETED[$id]:-}" != "t" ||
			      "${MEMBER_ACTIVE_GROUP_COUNT[$id]:-0}" != "1" ]]; then
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
				local backup_request_id=""
				if [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]]; then
					backup_request_id="c2m-${M_RUN_ID}-b-${id}"
				fi
				if [[ -n "$TEST_BACKEND" ]]; then
					backend_call before-backup-open-submit "$id" || exit 1
				fi
				if ! backup_open_target_live_eligible "$id"; then
					emit_event "degraded" "open_backups" \
					  "backup_live_revalidation_failed_at_submit" \
					  "$(printf '{"account_id":%s,"account_writes":0}' "$(json_quote "$id")")"
					exit 1
				fi
				# Another actor may already have opened the still-eligible account.
				# In that case the safe result is no controller POST.
				[[ "${MEMBER_SCHEDULABLE[$id]:-}" != t ]] || exit 0
				api_set_schedulable_with_header "$id" true "$shared_header" \
				  "$request_timeout" "$backup_request_id"
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
	wait_for_backups_ready "$snapshot_timeout" || {
		emit_event "critical" "open_backups" "no_backup_reached_scheduler_snapshot" \
		  "$(printf '{"eligible_backups":%s,"attempted_backups":%s,"failed_updates":%s,"deadline_skipped":%s,"inventory_skipped":%s,"ineligible_skipped":%s}' \
			  "$eligible" "$attempted" "$failed" "$deadline_exhausted" "$inventory_skipped" "$ineligible_skipped")"
		return 1
	}
	emit_event "ok" "open_backups" "backups_ready" \
	  "$(printf '{"eligible_backups":%s,"attempted_backups":%s,"failed_updates":%s,"deadline_skipped":%s,"inventory_skipped":%s,"ineligible_skipped":%s}' \
		  "$eligible" "$attempted" "$failed" "$deadline_exhausted" "$inventory_skipped" "$ineligible_skipped")"
}

ensure_maintenance_backups_ready() {
  local timeout_seconds="${1:-$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS}"
  backups_ready_in_all_buckets && return 0
  emit_event "degraded" "maintenance_backup_fence" \
    "standby_readiness_lost_reopening_before_abort" '{}'
  open_backups "$timeout_seconds" || true
  return 1
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
  scope_backup_ids_to_maintenance_identity "close_backups" || return 1
  # schedulable is global to an account, not scoped to one group.  If a
  # standby opened by an earlier run is later attached to another active
  # group, closing it could break that group, while ignoring it and declaring
  # normal would lose controller ownership.  Stop before the first write and
  # require an operator to reconcile the membership.
  guard_no_shared_schedulable_backups close_backups || return 1
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
import datetime as dt,re,sys
latest_at,latest_id,watermark_at,watermark_id=sys.argv[1:]
try:
    latest_id=int(latest_id)
    watermark_id=int(watermark_id)
except ValueError:
    raise SystemExit(2)
if latest_id <= 0:
    raise SystemExit(1)
def parse(value):
    match=re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?'
        r'(Z|[+-]\d{2}:\d{2})',value)
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or '')+'000000')[:6]
    zone='+00:00' if zone == 'Z' else zone
    parsed=dt.datetime.fromisoformat(f'{base}.{fraction}{zone}')
    if parsed.tzinfo is None:
        raise ValueError
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
import datetime as dt,json,re,sys
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
def canonical_rfc3339(value):
    match=re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?'
        r'(Z|[+-]\d{2}:\d{2})',str(value))
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or '')+'000000')[:6]
    zone='+00:00' if zone == 'Z' else zone
    parsed=dt.datetime.fromisoformat(f'{base}.{fraction}{zone}')
    if parsed.tzinfo is None:
        raise ValueError
    return parsed.astimezone(dt.timezone.utc).isoformat(
        timespec='microseconds').replace('+00:00','Z')
for key in ('proof_after','takeover_started_at','last_trigger_at','healthy_since','last_unavailable_at','last_availability_at'):
    value=p.get(key)
    if not value:
        continue
    try:
        p[key]=canonical_rfc3339(value)
    except Exception:
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
  [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] && mode="maintenance"
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

new_maintenance_run_id() {
  "$PYTHON_BIN" -c 'import uuid; print(uuid.uuid4())'
}

new_maintenance_request_id() {
  local kind="$1"
  [[ "$kind" == pause || "$kind" == seal || "$kind" == restore || "$kind" == fence ]] || return 1
  printf 'codex2api-maint-%s-%s\n' "$(new_maintenance_run_id)" "$kind"
}

sub2_runtime_incarnation() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call incarnation
    return
  fi
  "$DOCKER_BIN" inspect --format '{{.Id}}@{{.State.StartedAt}}' "$SUB2_API_CONTAINER"
}

read_log_sink_health() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call log-sink-health
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
    --connect-timeout 2 --max-time 5 --header "@$ACTIVE_HEADER_FILE" \
    "$SUB2_ADMIN_BASE_URL/api/v1/admin/ops/system-logs/health")" || {
      cleanup_current_sensitive_files
      return 1
    }
  [[ "$code" == 200 ]] || {
    cleanup_current_sensitive_files
    return 1
  }
  local normalized
  normalized="$("$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" <<'PY'
import json,sys
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
    h=p.get('data',p)
    values=[int(h[k]) for k in ('queue_depth','dropped_count','write_failed_count','written_count')]
    if any(v < 0 for v in values):
        raise ValueError
    print('|'.join(str(v) for v in values))
except Exception:
    raise SystemExit(1)
PY
)" || {
    cleanup_current_sensitive_files
    return 1
  }
  cleanup_current_sensitive_files
  printf '%s\n' "$normalized"
}

read_runtime_logging_control() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call runtime-logging
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
    --connect-timeout 2 --max-time 5 --header "@$ACTIVE_HEADER_FILE" \
    "$SUB2_ADMIN_BASE_URL/api/v1/admin/ops/runtime/logging")" || {
      cleanup_current_sensitive_files
      return 1
    }
  [[ "$code" == 200 ]] || {
    cleanup_current_sensitive_files
    return 1
  }
  local normalized
  normalized="$("$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" <<'PY'
import json,sys
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
    cfg=p.get('data',p)
    level=str(cfg['level']).strip().lower()
    sampling=cfg['enable_sampling']
    if level not in {'debug','info','warn','error'} or type(sampling) is not bool:
        raise ValueError
    print(level+'|'+('true' if sampling else 'false'))
except Exception:
    raise SystemExit(1)
PY
)" || {
    cleanup_current_sensitive_files
    return 1
  }
  cleanup_current_sensitive_files
  printf '%s\n' "$normalized"
}

verify_runtime_logging_evidence() {
  RUNTIME_LOGGING_RESULT="unverifiable"
  local control level sampling
  control="$(read_runtime_logging_control)" || return 1
  IFS='|' read -r level sampling <<<"$control"
  [[ "$level" =~ ^(debug|info|warn|error)$ && "$sampling" =~ ^(true|false)$ ]] || return 1
  if [[ "$sampling" != false || ( "$level" != debug && "$level" != info ) ]]; then
    RUNTIME_LOGGING_RESULT="conflict"
    return 2
  fi
  RUNTIME_LOGGING_RESULT="valid"
}

capture_log_watermark() {
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call log-watermark
    return
  fi
  db_query "SELECT COALESCE(MAX(id),0) FROM ops_system_logs;"
}

maintenance_request_id_occurrences() {
  local request_id="$1"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore|fence)$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call request-id-count "$request_id"
    return
  fi
  db_query "SELECT COUNT(*) FROM ops_system_logs WHERE request_id='${request_id}';"
}

submit_maintenance_sentinel() {
  local request_id="$1"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-fence$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call sentinel "$request_id"
    return
  fi
  cleanup_current_sensitive_files
  make_admin_header_file || return 1
  ACTIVE_RESPONSE_FILE="$(mktemp "$RUNTIME_DIR/response.XXXXXX")"
  local code
  code="$("$CURL_BIN" -sS -o "$ACTIVE_RESPONSE_FILE" -w '%{http_code}' \
    --connect-timeout 2 --max-time "$SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS" \
    --header "@$ACTIVE_HEADER_FILE" -H "X-Request-ID: $request_id" \
    "$SUB2_ADMIN_BASE_URL/api/v1/admin/ops/system-logs/health")" || {
      cleanup_current_sensitive_files
      return 1
    }
  [[ "$code" == 200 ]] || {
    cleanup_current_sensitive_files
    return 1
  }
  "$PYTHON_BIN" - "$ACTIVE_RESPONSE_FILE" <<'PY' || {
import json,sys
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
    h=p.get('data',p)
    values=[int(h[k]) for k in ('queue_depth','dropped_count','write_failed_count','written_count')]
    if any(v < 0 for v in values):
        raise ValueError
except Exception:
    raise SystemExit(1)
PY
    cleanup_current_sensitive_files
    return 1
  }
  cleanup_current_sensitive_files
}

maintenance_sentinel_receipt_record() {
  local request_id="$1"
  local watermark="$2"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-fence$ ]] || return 1
  [[ "$watermark" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call sentinel-receipt-record "$request_id" "$watermark"
    return
  fi
  db_query "
SELECT COUNT(*), COALESCE(MIN(id),0), COALESCE(MIN(extra->>'status_code'),'')
FROM ops_system_logs
WHERE id > ${watermark}
  AND request_id='${request_id}'
  AND component='http.access'
  AND message='http request completed'
  AND extra->>'method'='GET'
  AND extra->>'path'='/api/v1/admin/ops/system-logs/health';"
}

maintenance_receipt_record() {
  local request_id="$1"
  local watermark="$2"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore)$ ]] || return 1
  [[ "$watermark" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call receipt-record "$request_id" "$watermark" "$BRIDGE_ACCOUNT_ID"
    return
  fi
  db_query "
SELECT COUNT(*), COALESCE(MIN(id),0), COALESCE(MIN(extra->>'status_code'),'')
FROM ops_system_logs
WHERE id > ${watermark}
  AND request_id='${request_id}'
  AND component='http.access'
  AND message='http request completed'
  AND extra->>'method'='POST'
  AND extra->>'path'='/api/v1/admin/accounts/${BRIDGE_ACCOUNT_ID}/schedulable';"
}

maintenance_schedulable_audit_record() {
  local request_id="$1"
  local desired="$2"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore)$ ]] || return 1
  [[ "$desired" == true || "$desired" == false ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call audit-receipt-record "$request_id" "$BRIDGE_ACCOUNT_ID" "$desired"
    return
  fi
  db_query "
SELECT
  COUNT(*),
  COUNT(*) FILTER (
    WHERE action='admin.accounts.schedulable.create'
      AND method='POST'
      AND path='/api/v1/admin/accounts/:id/schedulable'
      AND status_code=200
      AND request_body::jsonb=jsonb_build_object('schedulable', ${desired})
      AND extra->'params'->>'id'='${BRIDGE_ACCOUNT_ID}'
  ),
  COALESCE(MIN(id) FILTER (
    WHERE action='admin.accounts.schedulable.create'
      AND method='POST'
      AND path='/api/v1/admin/accounts/:id/schedulable'
      AND status_code=200
      AND request_body::jsonb=jsonb_build_object('schedulable', ${desired})
      AND extra->'params'->>'id'='${BRIDGE_ACCOUNT_ID}'
  ),0),
  COALESCE(TO_CHAR(
    (MIN(created_at) FILTER (
      WHERE action='admin.accounts.schedulable.create'
        AND method='POST'
        AND path='/api/v1/admin/accounts/:id/schedulable'
        AND status_code=200
        AND request_body::jsonb=jsonb_build_object('schedulable', ${desired})
        AND extra->'params'->>'id'='${BRIDGE_ACCOUNT_ID}'
    )) AT TIME ZONE 'UTC',
    'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'
  ),''),
  COALESCE(MIN(latency_ms) FILTER (
    WHERE action='admin.accounts.schedulable.create'
      AND method='POST'
      AND path='/api/v1/admin/accounts/:id/schedulable'
      AND status_code=200
      AND request_body::jsonb=jsonb_build_object('schedulable', ${desired})
      AND extra->'params'->>'id'='${BRIDGE_ACCOUNT_ID}'
  ),-1)
FROM audit_logs
WHERE request_id='${request_id}';"
}

maintenance_receipt_evidence_record() {
  local request_id="$1"
  local watermark="$2"
  [[ "$request_id" =~ ^codex2api-maint-[a-f0-9-]{36}-seal$ ]] || return 1
  [[ "$watermark" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call receipt-evidence-record "$request_id" "$watermark" "$BRIDGE_ACCOUNT_ID"
    return
  fi
  db_query "
SELECT COUNT(*), COALESCE(MIN(id),0),
       COALESCE(MIN(extra->>'status_code'),''),
       COALESCE(TO_CHAR(
         MIN((extra->>'completed_at')::timestamptz) AT TIME ZONE 'UTC',
         'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'
       ),'')
FROM ops_system_logs
WHERE id > ${watermark}
  AND request_id='${request_id}'
  AND component='http.access'
  AND message='http request completed'
  AND extra->>'method'='POST'
  AND extra->>'path'='/api/v1/admin/accounts/${BRIDGE_ACCOUNT_ID}/schedulable';"
}

unique_successful_seal_receipt() {
  local request_id="$1"
  local watermark="$2"
  local record count log_id status access_at
  record="$(maintenance_receipt_evidence_record "$request_id" "$watermark")" || return 1
  IFS='|' read -r count log_id status access_at <<<"$record"
  [[ "$count" == 1 && "$log_id" =~ ^[1-9][0-9]*$ && "$status" == 200 &&
     "$access_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || return 2
  printf '%s|%s\n' "$log_id" "$access_at"
}

unique_schedulable_audit_record() {
  local request_id="$1"
  local desired="$2"
  local record total exact audit_id audit_at latency_ms
  record="$(maintenance_schedulable_audit_record "$request_id" "$desired")" || return 1
  IFS='|' read -r total exact audit_id audit_at latency_ms <<<"$record"
  [[ "$total" == 1 && "$exact" == 1 && "$audit_id" =~ ^[1-9][0-9]*$ &&
     "$audit_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$ &&
     "$latency_ms" =~ ^[0-9]+$ ]] || return 2
  printf '%s|%s|%s\n' "$audit_id" "$audit_at" "$latency_ms"
}

seal_evidence_chronology_valid() {
  local pause_at="$1"
  local updated_at="$2"
  local audit_at="$3"
  local audit_latency_ms="$4"
  local access_at="$5"
  "$PYTHON_BIN" - "$pause_at" "$updated_at" "$audit_at" \
    "$audit_latency_ms" "$access_at" \
    "$((PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS * 1000 + 1000))" <<'PY'
import datetime as dt,re,sys
def parse(value):
    match=re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?'
        r'(Z|[+-]\d{2}:\d{2})',value)
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or '')+'000000')[:6]
    zone='+00:00' if zone == 'Z' else zone
    stamp=dt.datetime.fromisoformat(f'{base}.{fraction}{zone}')
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
try:
    pause,updated,audit=parse(sys.argv[1]),parse(sys.argv[2]),parse(sys.argv[3])
    latency_ms=int(sys.argv[4])
    access=parse(sys.argv[5])
    if latency_ms < 0 or latency_ms > int(sys.argv[6]):
        raise ValueError
    if not (pause < updated <= audit <= access):
        raise ValueError
    if (audit-updated).total_seconds()*1000 > latency_ms + 1000:
        raise ValueError
except Exception:
    raise SystemExit(1)
PY
}

foreign_account_mutation_count() {
  local watermark="$1"
  local upper_log_id="$2"
  local provisional_restore_log_id="${3:-}"
  local provisional_seal_log_id="${4:-}"
  (( $# <= 4 )) || return 1
  [[ "$watermark" =~ ^[0-9]+$ && "$upper_log_id" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]] || return 1

  local seal_log_id="$M_SEAL_LOG_ID"
  if [[ -n "$provisional_seal_log_id" ]]; then
    [[ "$M_PHASE" == PAUSE_AMBIGUOUS &&
       "$M_AMBIGUITY_PHASE" == SEAL_INTENT &&
       "$M_AMBIGUITY_REASON" == ownership_seal_response_not_durable_backups_left_open &&
       "$M_SEAL_REQUEST_ID" =~ ^codex2api-maint-[a-f0-9-]{36}-seal$ &&
       -z "$seal_log_id" && -z "$M_SEAL_RESPONSE_UPDATED_AT" &&
       "$provisional_seal_log_id" =~ ^[1-9][0-9]*$ ]] || return 1
    seal_log_id="$provisional_seal_log_id"
  fi

  local restore_log_id="$M_RESTORE_LOG_ID"
  local restore_allow_2xx=false
  if [[ -n "$provisional_restore_log_id" ]]; then
    [[ "$M_PHASE" =~ ^(RESTORE_ACKED|RESTORE_AMBIGUOUS)$ &&
       "$provisional_restore_log_id" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -z "$restore_log_id" || "$restore_log_id" == "$provisional_restore_log_id" ]] || return 1
    restore_log_id="$provisional_restore_log_id"
    restore_allow_2xx=true
  elif [[ "$M_RESTORE_RESPONSE_CHECKPOINT" == explicitly_resolved ]]; then
    restore_allow_2xx=true
  fi

  local primary_write_exemption=""
  if [[ -n "$M_PAUSE_REQUEST_ID" || -n "$M_PAUSE_LOG_ID" ]]; then
    [[ "$M_PAUSE_REQUEST_ID" =~ ^codex2api-maint-[a-f0-9-]{36}-pause$ &&
       "$M_PAUSE_LOG_ID" =~ ^[1-9][0-9]*$ ]] || return 1
    primary_write_exemption+=" OR (
      id=${M_PAUSE_LOG_ID}
      AND request_id='${M_PAUSE_REQUEST_ID}'
      AND extra->>'method'='POST'
      AND extra->>'path'='/api/v1/admin/accounts/${BRIDGE_ACCOUNT_ID}/schedulable'
      AND extra->>'status_code'='200'
    )"
  fi
  if [[ -n "$M_SEAL_REQUEST_ID" || -n "$seal_log_id" ]]; then
    [[ "$M_SEAL_REQUEST_ID" =~ ^codex2api-maint-[a-f0-9-]{36}-seal$ &&
       "$seal_log_id" =~ ^[1-9][0-9]*$ ]] || return 1
    primary_write_exemption+=" OR (
      id=${seal_log_id}
      AND request_id='${M_SEAL_REQUEST_ID}'
      AND extra->>'method'='POST'
      AND extra->>'path'='/api/v1/admin/accounts/${BRIDGE_ACCOUNT_ID}/schedulable'
      AND extra->>'status_code'='200'
    )"
  fi
  if [[ -n "$M_RESTORE_REQUEST_ID" || -n "$restore_log_id" ]]; then
    [[ "$M_RESTORE_REQUEST_ID" =~ ^codex2api-maint-[a-f0-9-]{36}-restore$ &&
       "$restore_log_id" =~ ^[1-9][0-9]*$ ]] || return 1
    local restore_status_sql="extra->>'status_code'='200'"
    if [[ "$restore_allow_2xx" == true ]]; then
      restore_status_sql="COALESCE(extra->>'status_code','') ~ '^2[0-9][0-9]$'"
    fi
    primary_write_exemption+=" OR (
      id=${restore_log_id}
      AND request_id='${M_RESTORE_REQUEST_ID}'
      AND extra->>'method'='POST'
      AND extra->>'path'='/api/v1/admin/accounts/${BRIDGE_ACCOUNT_ID}/schedulable'
      AND ${restore_status_sql}
    )"
  fi

  if [[ -n "$TEST_BACKEND" ]]; then
    backend_call foreign-mutation-count "$watermark" "$upper_log_id" "$BRIDGE_ACCOUNT_ID" \
      "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" "$M_SEAL_REQUEST_ID" "$seal_log_id" \
      "$M_RESTORE_REQUEST_ID" "$restore_log_id" "$restore_allow_2xx"
    return
  fi
  [[ "$M_RUN_ID" =~ ^[a-f0-9-]{36}$ ]] || return 1
  [[ "$M_GROUP_ID" =~ ^[1-9][0-9]{0,18}$ ]] || return 1
  if (( ${#M_GROUP_ID} == 19 )) && [[ "$M_GROUP_ID" > "9223372036854775807" ]]; then
    return 1
  fi
  [[ "$M_GROUP_MEMBER_IDS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
  [[ "$M_BACKUP_ACCOUNT_IDS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
  db_query "
SELECT COUNT(*)
FROM ops_system_logs
WHERE id > ${watermark}
  AND id <= ${upper_log_id}
  AND component='http.access'
  AND message='http request completed'
  AND extra->>'method' IN ('POST','PUT','PATCH','DELETE')
  AND extra->>'path' LIKE '/api/v1/admin/%'
  AND NOT CASE
    WHEN COALESCE(extra->>'status_code','') ~ '^[0-9]{3}$'
    THEN (extra->>'status_code')::INTEGER BETWEEN 400 AND 499
    ELSE FALSE
  END
  AND NOT (
    (
      extra->>'method'='POST'
      AND extra->>'path'='/api/v1/admin/accounts/today-stats/batch'
    )
    OR (
      extra->>'method'='POST'
      AND extra->>'path' ~ '^/api/v1/admin/accounts/[1-9][0-9]{0,18}/schedulable$'
      AND (SUBSTRING(extra->>'path' FROM '^/api/v1/admin/accounts/([1-9][0-9]{0,18})/schedulable$'))::NUMERIC
          <= 9223372036854775807
      AND (
        FALSE
        ${primary_write_exemption}
      )
    )
  );"
}

verify_runtime_evidence() {
  RUNTIME_EVIDENCE_RESULT="unverifiable"
  local expected_incarnation="$1"
  local expected_dropped="$2"
  local expected_failed="$3"
  local minimum_written="$4"
  local current
  current="$(sub2_runtime_incarnation)" || return 1
  if [[ "$current" != "$expected_incarnation" ]]; then
    RUNTIME_EVIDENCE_RESULT="conflict"
    return 2
  fi
  local health queue dropped failed written
  health="$(read_log_sink_health)" || return 1
  IFS='|' read -r queue dropped failed written <<<"$health"
  [[ "$queue" =~ ^[0-9]+$ && "$dropped" =~ ^[0-9]+$ && "$failed" =~ ^[0-9]+$ && "$written" =~ ^[0-9]+$ ]] || return 1
  if [[ "$dropped" != "$expected_dropped" || "$failed" != "$expected_failed" ]] ||
     (( written < minimum_written )); then
    RUNTIME_EVIDENCE_RESULT="conflict"
    return 2
  fi
  RUNTIME_EVIDENCE_RESULT="valid"
  printf '%s|%s\n' "$queue" "$written"
}

wait_for_maintenance_receipt() {
  local request_id="$1"
  local watermark="$2"
  local expected_incarnation="$3"
  local expected_dropped="$4"
  local expected_failed="$5"
  local minimum_written="$6"
  local deadline=$((SECONDS + MAINTENANCE_RECEIPT_TIMEOUT_SECONDS))
  local record count log_id status
  while (( SECONDS < deadline )); do
    # Return codes deliberately distinguish a bounded absence from a read-side
    # outage and from a receipt that positively contradicts this request.  The
    # caller may retry an unchanged INTENT after code 3; only codes 1/2 make the
    # already-issued write outcome unsafe to adopt.
    local runtime_rc=0
    verify_runtime_evidence "$expected_incarnation" "$expected_dropped" \
      "$expected_failed" "$minimum_written" >/dev/null || runtime_rc=$?
    (( runtime_rc == 0 )) || { (( runtime_rc == 2 )) && return 2 || return 3; }
    record="$(maintenance_receipt_record "$request_id" "$watermark")" || return 3
    IFS='|' read -r count log_id status <<<"$record"
    [[ "$count" =~ ^[0-9]+$ && "$log_id" =~ ^[0-9]+$ && "$status" =~ ^[0-9]*$ ]] || return 3
    if (( count > 1 )); then
      return 2
    fi
    if (( count == 1 )); then
      [[ "$status" == 200 ]] || return 2
      runtime_rc=0
      verify_runtime_evidence "$expected_incarnation" "$expected_dropped" \
        "$expected_failed" "$minimum_written" >/dev/null || runtime_rc=$?
      (( runtime_rc == 0 )) || { (( runtime_rc == 2 )) && return 2 || return 3; }
      record="$(maintenance_receipt_record "$request_id" "$watermark")" || return 3
      IFS='|' read -r count log_id status <<<"$record"
      [[ "$count" =~ ^[0-9]+$ && "$log_id" =~ ^[0-9]+$ && "$status" =~ ^[0-9]*$ ]] || return 3
      [[ "$count" == 1 && "$log_id" =~ ^[1-9][0-9]*$ && "$status" == 200 ]] || return 2
      printf '%s\n' "$log_id"
      return 0
    fi
    sleep "$SNAPSHOT_POLL_SECONDS"
  done
  return 1
}

wait_for_maintenance_sentinel() {
  local request_id="$1"
  local watermark="$2"
  local expected_incarnation="$3"
  local expected_dropped="$4"
  local expected_failed="$5"
  local minimum_written="$6"
  local deadline=$((SECONDS + MAINTENANCE_RECEIPT_TIMEOUT_SECONDS))
  local record count log_id status runtime_rc
  while (( SECONDS < deadline )); do
    runtime_rc=0
    verify_runtime_evidence "$expected_incarnation" "$expected_dropped" \
      "$expected_failed" "$minimum_written" >/dev/null || runtime_rc=$?
    (( runtime_rc == 0 )) || { (( runtime_rc == 2 )) && return 2 || return 3; }
    record="$(maintenance_sentinel_receipt_record "$request_id" "$watermark")" || return 3
    IFS='|' read -r count log_id status <<<"$record"
    [[ "$count" =~ ^[0-9]+$ && "$log_id" =~ ^[0-9]+$ && "$status" =~ ^[0-9]*$ ]] || return 3
    (( count <= 1 )) || return 2
    if (( count == 1 )); then
      [[ "$log_id" =~ ^[1-9][0-9]*$ && "$status" == 200 ]] || return 2
      runtime_rc=0
      verify_runtime_evidence "$expected_incarnation" "$expected_dropped" \
        "$expected_failed" "$minimum_written" >/dev/null || runtime_rc=$?
      (( runtime_rc == 0 )) || { (( runtime_rc == 2 )) && return 2 || return 3; }
      record="$(maintenance_sentinel_receipt_record "$request_id" "$watermark")" || return 3
      IFS='|' read -r count log_id status <<<"$record"
      [[ "$count" =~ ^[0-9]+$ && "$log_id" =~ ^[0-9]+$ && "$status" =~ ^[0-9]*$ ]] || return 3
      [[ "$count" == 1 && "$log_id" =~ ^[1-9][0-9]*$ && "$status" == 200 ]] || return 2
      printf '%s\n' "$log_id"
      return 0
    fi
    sleep "$SNAPSHOT_POLL_SECONDS"
  done
  return 1
}

verify_maintenance_receipt() {
  MAINTENANCE_RECEIPT_RESULT="unverifiable"
  local request_id="$1"
  local expected_log_id="$2"
  local watermark="$3"
  local record count log_id status
  record="$(maintenance_receipt_record "$request_id" "$watermark")" || return 1
  IFS='|' read -r count log_id status <<<"$record"
  [[ "$count" =~ ^[0-9]+$ && "$log_id" =~ ^[0-9]+$ && "$status" =~ ^[0-9]*$ ]] || return 1
  if [[ "$count" == 1 && "$log_id" == "$expected_log_id" && "$status" == 200 ]]; then
    MAINTENANCE_RECEIPT_RESULT="valid"
    return 0
  fi
  MAINTENANCE_RECEIPT_RESULT="conflict"
  return 2
}

# Explicit ambiguity resolution may adopt only one durably logged successful
# restore.  It intentionally accepts the complete 2xx class because the live
# account and scheduler proof below remains authoritative; ordinary automatic
# maintenance continues to require its existing structurally valid HTTP 200
# response and exact 200 receipt.
unique_successful_restore_receipt() {
  local request_id="$1"
  local watermark="$2"
  local record count log_id status
  record="$(maintenance_receipt_record "$request_id" "$watermark")" || return 1
  IFS='|' read -r count log_id status <<<"$record"
  [[ "$count" == 1 && "$log_id" =~ ^[1-9][0-9]*$ && "$status" =~ ^2[0-9][0-9]$ ]] || return 2
  printf '%s\n' "$log_id"
}

verify_successful_restore_receipt() {
  local request_id="$1"
  local expected_log_id="$2"
  local watermark="$3"
  local log_id rc=0
  [[ "$expected_log_id" =~ ^[1-9][0-9]*$ ]] || return 2
  log_id="$(unique_successful_restore_receipt "$request_id" "$watermark")" || rc=$?
  (( rc == 0 )) || return "$rc"
  [[ "$log_id" == "$expected_log_id" ]] || return 2
}

verify_no_foreign_mutations() {
  local provisional_restore_log_id="${1:-}"
  local provisional_seal_log_id="${2:-}"
  (( $# <= 2 )) || return 1
  MAINTENANCE_FOREIGN_FENCE_RESULT="unverifiable"
  local logging_rc=0 runtime_rc=0 sentinel_rc=0 group_rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
  if (( group_rc != 0 )); then
    [[ "$group_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="group_evidence_conflict"
    (( group_rc == 2 )) && return 2 || return 1
  fi
  verify_runtime_logging_evidence || logging_rc=$?
  if (( logging_rc != 0 )); then
    [[ "$logging_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="logging_evidence_conflict"
    (( logging_rc == 2 )) && return 2 || return 1
  fi
  verify_runtime_evidence "$M_INCARNATION" "$M_SINK_DROPPED" \
    "$M_SINK_FAILED" "$M_SINK_WRITTEN" >/dev/null || runtime_rc=$?
  if (( runtime_rc != 0 )); then
    [[ "$runtime_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="runtime_evidence_conflict"
    (( runtime_rc == 2 )) && return 2 || return 1
  fi
  local fence_request_id fence_log_id count
  fence_request_id="$(new_maintenance_request_id fence)" || return 1
  preflight_maintenance_request_id "$fence_request_id" || return 1
  submit_maintenance_sentinel "$fence_request_id" || return 1
  fence_log_id="$(wait_for_maintenance_sentinel "$fence_request_id" "$M_LOG_WATERMARK" \
    "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN")" || sentinel_rc=$?
  if (( sentinel_rc != 0 )); then
    [[ "$sentinel_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="sentinel_receipt_conflict"
    (( sentinel_rc == 2 )) && return 2 || return 1
  fi
  count="$(foreign_account_mutation_count "$M_LOG_WATERMARK" "$fence_log_id" \
    "$provisional_restore_log_id" "$provisional_seal_log_id")" || return 1
  [[ "$count" =~ ^[0-9]+$ ]] || return 1
  if (( count > 0 )); then
    MAINTENANCE_FOREIGN_FENCE_RESULT="foreign_mutation_confirmed"
    return 2
  fi
  group_rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
  if (( group_rc != 0 )); then
    [[ "$group_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="group_evidence_conflict"
    (( group_rc == 2 )) && return 2 || return 1
  fi
  runtime_rc=0
  verify_runtime_evidence "$M_INCARNATION" "$M_SINK_DROPPED" \
    "$M_SINK_FAILED" "$M_SINK_WRITTEN" >/dev/null || runtime_rc=$?
  if (( runtime_rc != 0 )); then
    [[ "$runtime_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="runtime_evidence_conflict"
    (( runtime_rc == 2 )) && return 2 || return 1
  fi
  logging_rc=0
  verify_runtime_logging_evidence || logging_rc=$?
  if (( logging_rc != 0 )); then
    [[ "$logging_rc" == 2 ]] && MAINTENANCE_FOREIGN_FENCE_RESULT="logging_evidence_conflict"
    (( logging_rc == 2 )) && return 2 || return 1
  fi
  MAINTENANCE_FOREIGN_FENCE_RESULT="clean"
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
  TO_CHAR(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
  xmin::text
FROM accounts
WHERE id = ${BRIDGE_ACCOUNT_ID};"
}

capture_primary_disabled_tuple() {
  local row status schedulable not_deleted runtime_ready updated_at row_version
  row="$(primary_maintenance_snapshot)" || return 1
  IFS='|' read -r status schedulable not_deleted runtime_ready updated_at row_version <<<"$row"
  [[ "$status" == active && "$schedulable" == f && "$not_deleted" == t &&
     "$runtime_ready" == t && "$updated_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$ &&
     "$row_version" =~ ^[0-9]+$ ]] || return 1
  printf '%s|%s\n' "$updated_at" "$row_version"
}

verify_primary_disabled_tuple() {
  PRIMARY_DISABLED_TUPLE_RESULT="unverifiable"
  local expected_updated_at="$1"
  local expected_xmin="$2"
  local row status schedulable not_deleted runtime_ready updated_at row_version
  row="$(primary_maintenance_snapshot)" || return 1
  IFS='|' read -r status schedulable not_deleted runtime_ready updated_at row_version <<<"$row"
  [[ "$status" =~ ^[a-z_]+$ && "$schedulable" =~ ^[tf]$ &&
     "$not_deleted" =~ ^[tf]$ && "$runtime_ready" =~ ^[tf]$ &&
     "$updated_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$ &&
     "$row_version" =~ ^[0-9]+$ ]] || return 1
  if [[ "$status" != active || "$schedulable" != f || "$not_deleted" != t ||
        "$runtime_ready" != t || "$updated_at" != "$expected_updated_at" ||
        "$row_version" != "$expected_xmin" ]]; then
    PRIMARY_DISABLED_TUPLE_RESULT="conflict"
    return 2
  fi
  PRIMARY_DISABLED_TUPLE_RESULT="valid"
  return 0
}

verify_primary_disabled_version() {
  local expected_xmin="$1"
  local current
  current="$(capture_primary_disabled_tuple)" || return 1
  [[ "${current##*|}" == "$expected_xmin" ]]
}

compute_maintenance_identity_digest() {
  "$PYTHON_BIN" - "$M_RUN_ID" "$M_PRIMARY_ACCOUNT_ID" "$M_GROUP_ID" \
    "$M_GROUP_MEMBER_IDS" "$M_BACKUP_ACCOUNT_IDS" "$M_LOG_WATERMARK" \
    "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN" <<'PY'
import hashlib,json,sys
(run_id,primary,group_id,members,backups,watermark,incarnation,
 dropped,failed,written)=sys.argv[1:]
payload={
  'schema_version':7,
  'run_id':run_id,
  'primary_account_id':int(primary),
  'group_id':int(group_id),
  'group_member_ids':[int(v) for v in members.split(',')],
  'backup_account_ids':[int(v) for v in backups.split(',')],
  'log_watermark':int(watermark),
  'sub2_incarnation':incarnation,
  'sink_dropped_base':int(dropped),
  'sink_failed_base':int(failed),
  'sink_written_base':int(written),
}
canonical=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
print(hashlib.sha256(canonical).hexdigest())
PY
}

maintenance_state_line() {
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$M_PHASE" "$M_RUN_ID" "$M_PRIMARY_ACCOUNT_ID" "$M_GROUP_ID" \
    "$M_GROUP_MEMBER_IDS" "$M_BACKUP_ACCOUNT_IDS" "$M_IDENTITY_DIGEST" \
    "$M_LOG_WATERMARK" "$M_INCARNATION" \
    "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN" \
    "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" "$M_PAUSE_RESPONSE_CHECKPOINT" \
    "$M_PAUSE_RESPONSE_UPDATED_AT" "$M_SEAL_REQUEST_ID" \
    "$M_SEAL_LOG_ID" "$M_SEAL_RESPONSE_UPDATED_AT" "$M_RESTORE_REQUEST_ID" \
    "$M_RESTORE_LOG_ID" "$M_RESTORE_RESPONSE_CHECKPOINT" \
    "$M_RESTORE_RESPONSE_UPDATED_AT" "$M_OWNED_UPDATED_AT" "$M_OWNED_XMIN"
}

write_maintenance_marker() {
  local next_phase="$1"
  local reason="${2:-planned_codex2api_maintenance}"
  MAINTENANCE_MARKER_WRITE_COUNT=$((MAINTENANCE_MARKER_WRITE_COUNT + 1))
  if [[ -n "$TEST_BACKEND" && "$TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER" != 0 &&
        "$MAINTENANCE_MARKER_WRITE_COUNT" == "$TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER" ]]; then
    return 1
  fi
  local tmp
  tmp="$(mktemp "$STATE_DIR/maintenance.XXXXXX")"
  if ! "$PYTHON_BIN" - "$tmp" "$MAINTENANCE_FILE" "$next_phase" "$M_RUN_ID" \
    "$M_PRIMARY_ACCOUNT_ID" "$M_GROUP_ID" "$M_GROUP_MEMBER_IDS" \
    "$M_BACKUP_ACCOUNT_IDS" "$M_IDENTITY_DIGEST" "$M_LOG_WATERMARK" \
    "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" \
    "$M_SINK_WRITTEN" "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" \
    "$M_PAUSE_RESPONSE_CHECKPOINT" "$M_PAUSE_RESPONSE_UPDATED_AT" \
    "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" "$M_SEAL_RESPONSE_UPDATED_AT" \
    "$M_RESTORE_REQUEST_ID" "$M_RESTORE_LOG_ID" \
    "$M_RESTORE_RESPONSE_CHECKPOINT" "$M_RESTORE_RESPONSE_UPDATED_AT" \
    "$M_OWNED_UPDATED_AT" "$M_OWNED_XMIN" "$reason" <<'PY'
import datetime as dt,hashlib,json,os,re,sys,uuid
(tmp,path,phase,run_id,primary_account_id,group_id,member_ids_csv,backup_ids_csv,
 identity_digest,watermark,incarnation,dropped,failed,written,pause_req,pause_log,
 pause_checkpoint,pause_response_at,seal_req,seal_log,seal_response_at,
 restore_req,restore_log,restore_checkpoint,restore_response_at,
 owned_at,owned_xmin,reason)=sys.argv[1:]
allowed={
  'PREPARING','EXTERNAL_PAUSED','PAUSE_INTENT','PAUSE_ACKED','SEAL_INTENT',
  'SEAL_ACKED','PAUSE_AMBIGUOUS',
  'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED',
}
if phase not in allowed or str(uuid.UUID(run_id)) != run_id:
    raise SystemExit(1)
maximum=9223372036854775807
if (not primary_account_id.isdigit() or int(primary_account_id) <= 0 or
    int(primary_account_id) > maximum or not group_id.isdigit() or
    int(group_id) <= 0 or int(group_id) > maximum):
    raise SystemExit(1)
member_tokens=member_ids_csv.split(',')
if (not member_tokens or any(not value.isdigit() or int(value)<=0 or int(value)>maximum
                             for value in member_tokens)):
    raise SystemExit(1)
member_ids=[int(value) for value in member_tokens]
if member_ids != sorted(set(member_ids)) or int(primary_account_id) not in member_ids:
    raise SystemExit(1)
if member_ids_csv != ','.join(str(value) for value in member_ids):
    raise SystemExit(1)
backup_tokens=backup_ids_csv.split(',')
if (not backup_tokens or any(not value.isdigit() or int(value)<=0 or int(value)>maximum
                             for value in backup_tokens)):
    raise SystemExit(1)
backup_ids=[int(value) for value in backup_tokens]
if (backup_ids != sorted(set(backup_ids)) or int(primary_account_id) in backup_ids or
    any(value not in member_ids for value in backup_ids)):
    raise SystemExit(1)
if backup_ids_csv != ','.join(str(value) for value in backup_ids):
    raise SystemExit(1)
if not re.fullmatch(r'[a-f0-9]{64}',identity_digest):
    raise SystemExit(1)
if not all(value.isdigit() for value in (watermark,dropped,failed,written)):
    raise SystemExit(1)
if not incarnation or len(incarnation)>200 or '|' in incarnation or not incarnation.isascii():
    raise SystemExit(1)
identity_payload={
  'schema_version':7,
  'run_id':run_id,
  'primary_account_id':int(primary_account_id),
  'group_id':int(group_id),
  'group_member_ids':member_ids,
  'backup_account_ids':backup_ids,
  'log_watermark':int(watermark),
  'sub2_incarnation':incarnation,
  'sink_dropped_base':int(dropped),
  'sink_failed_base':int(failed),
  'sink_written_base':int(written),
}
canonical=json.dumps(identity_payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
if hashlib.sha256(canonical).hexdigest() != identity_digest:
    raise SystemExit(1)

req_re=re.compile(r'^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore)$')
for value in (pause_req,seal_req,restore_req):
    if value and (len(value)>64 or not value.isascii() or not req_re.fullmatch(value)):
        raise SystemExit(1)
for value in (pause_log,seal_log,restore_log,owned_xmin):
    if value and (not value.isdigit() or int(value)<=0):
        raise SystemExit(1)
def valid_stamp(value):
    if not value:
        return True
    raw=value[:-1]+'+00:00' if value.endswith('Z') else value
    stamp=dt.datetime.fromisoformat(raw)
    if stamp.tzinfo is None:
        raise ValueError('timestamp must carry timezone')
    canonical_stamp=stamp.astimezone(dt.timezone.utc).isoformat(
        timespec='microseconds').replace('+00:00','Z')
    return canonical_stamp == value
for value in (pause_response_at,seal_response_at,restore_response_at,owned_at):
    if not valid_stamp(value):
        raise SystemExit(1)
pause_states={'none','pending','validated','transport_or_non200','invalid'}
restore_states=pause_states|{'explicitly_resolved'}
if pause_checkpoint not in pause_states or restore_checkpoint not in restore_states:
    raise SystemExit(1)
if (pause_checkpoint == 'validated') != bool(pause_response_at):
    raise SystemExit(1)
if (restore_checkpoint == 'validated') != bool(restore_response_at):
    raise SystemExit(1)

if phase in {'PREPARING','EXTERNAL_PAUSED'}:
    if (pause_checkpoint != 'none' or restore_checkpoint != 'none' or
        any((pause_req,pause_log,pause_response_at,seal_req,seal_log,seal_response_at,
             restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
elif phase == 'PAUSE_INTENT':
    if (not pause_req or pause_log or pause_checkpoint == 'none' or
        restore_checkpoint != 'none' or
        any((seal_req,seal_log,seal_response_at,restore_req,restore_log,
             restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
elif phase == 'PAUSE_ACKED':
    if (not pause_req or not pause_log or pause_checkpoint != 'validated' or
        restore_checkpoint != 'none' or
        any((seal_req,seal_log,seal_response_at,restore_req,restore_log,
             restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
elif phase == 'SEAL_INTENT':
    if (not pause_req or not pause_log or pause_checkpoint != 'validated' or
        not seal_req or seal_log or restore_checkpoint != 'none' or
        any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
elif phase == 'SEAL_ACKED':
    if (not all((pause_req,pause_log,pause_response_at,seal_req,seal_log,
                 seal_response_at)) or pause_checkpoint != 'validated' or
        restore_checkpoint != 'none' or
        any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
elif phase == 'PAUSE_AMBIGUOUS':
    if (not pause_req or pause_checkpoint == 'none' or restore_checkpoint != 'none' or
        any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
        raise SystemExit(1)
    if pause_log and pause_checkpoint != 'validated':
        raise SystemExit(1)
    if seal_log and (not seal_req or not seal_response_at):
        raise SystemExit(1)
    if seal_response_at and not seal_req:
        raise SystemExit(1)
elif phase in {'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED'}:
    if (not all((pause_req,pause_log,pause_response_at,seal_req,seal_log,
                 seal_response_at,owned_at,owned_xmin)) or
        pause_checkpoint != 'validated'):
        raise SystemExit(1)
    if phase == 'OWNED':
        if restore_checkpoint != 'none' or any((restore_req,restore_log,restore_response_at)):
            raise SystemExit(1)
    elif phase == 'RESTORE_INTENT':
        if not restore_req or restore_log or restore_checkpoint == 'none':
            raise SystemExit(1)
    elif phase in {'RESTORE_ACKED','RESTORED'}:
        if (not restore_req or not restore_log or
            restore_checkpoint not in {'validated','explicitly_resolved'}):
            raise SystemExit(1)
    elif phase == 'RESTORE_AMBIGUOUS':
        if not restore_req or restore_checkpoint == 'none':
            raise SystemExit(1)
        if restore_log and restore_checkpoint not in {'validated','explicitly_resolved'}:
            raise SystemExit(1)

started_at=None
try:
    old=json.load(open(path,encoding='utf-8'))
    if old.get('schema_version') != 7 or old.get('run_id') != run_id:
        raise ValueError('maintenance marker identity changed')
    old_members=old.get('group_member_ids')
    old_backups=old.get('backup_account_ids')
    immutable=(
      str(old.get('primary_account_id')),str(old.get('group_id')),
      ','.join(str(value) for value in old_members) if isinstance(old_members,list) else '',
      ','.join(str(value) for value in old_backups) if isinstance(old_backups,list) else '',
      str(old.get('identity_digest') or ''),str(old.get('log_watermark')),
      str(old.get('sub2_incarnation')),str(old.get('sink_dropped_base')),
      str(old.get('sink_failed_base')),str(old.get('sink_written_base')),
    )
    expected=(primary_account_id,group_id,member_ids_csv,backup_ids_csv,identity_digest,
              watermark,incarnation,dropped,failed,written)
    if immutable != expected:
        raise ValueError('immutable maintenance evidence changed')
    started_at=old.get('started_at')
except FileNotFoundError:
    pass
except Exception:
    raise SystemExit(1)
now=dt.datetime.now(dt.timezone.utc).isoformat()
owned=phase in {'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS'}
payload={
  'schema_version':7,
  'run_id':run_id,
  'primary_account_id':int(primary_account_id),
  'group_id':int(group_id),
  'group_member_ids':member_ids,
  'backup_account_ids':backup_ids,
  'identity_digest':identity_digest,
  'phase':phase,
  'started_at':started_at or now,
  'updated_at':now,
  'reason':reason,
  'log_watermark':int(watermark),
  'sub2_incarnation':incarnation,
  'sink_dropped_base':int(dropped),
  'sink_failed_base':int(failed),
  'sink_written_base':int(written),
  'pause_request_id':pause_req or None,
  'pause_log_id':int(pause_log) if pause_log else None,
  'pause_response_checkpoint':pause_checkpoint,
  'pause_response_updated_at':pause_response_at or None,
  'seal_request_id':seal_req or None,
  'seal_log_id':int(seal_log) if seal_log else None,
  'seal_response_updated_at':seal_response_at or None,
  'restore_request_id':restore_req or None,
  'restore_log_id':int(restore_log) if restore_log else None,
  'restore_response_checkpoint':restore_checkpoint,
  'restore_response_updated_at':restore_response_at or None,
  'owned_updated_at':owned_at or None,
  'owned_xmin':owned_xmin or None,
  'primary_disabled_by_maintenance':owned,
  'primary_row_version':owned_xmin or None,
  'pending_primary_row_version':None,
}
with open(tmp,'w',encoding='utf-8') as f:
    json.dump(payload,f,ensure_ascii=False,sort_keys=True)
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
  then
    rm -f -- "$tmp"
    return 1
  fi
  local persisted
  persisted="$(read_maintenance_state)" || return 1
  local previous_phase="$M_PHASE"
  M_PHASE="$next_phase"
  local expected
  expected="$(maintenance_state_line)"
  M_PHASE="$previous_phase"
  [[ "$persisted" == "$expected" ]] || return 1
  M_PHASE="$next_phase"
}

remove_maintenance_marker() {
  "$PYTHON_BIN" - "$MAINTENANCE_FILE" "$MAINTENANCE_AMBIGUITY_FILE" <<'PY'
import os,sys
for path in sys.argv[1:]:
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

remove_maintenance_ambiguity() {
  "$PYTHON_BIN" - "$MAINTENANCE_AMBIGUITY_FILE" <<'PY'
import os,sys
path=sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    raise SystemExit(1)
fd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

persist_maintenance_ambiguity() {
  local reason="$1"
  "$PYTHON_BIN" - "$MAINTENANCE_AMBIGUITY_FILE" "$M_RUN_ID" "$M_PHASE" "$reason" \
    "$M_PRIMARY_ACCOUNT_ID" "$M_GROUP_ID" "$M_GROUP_MEMBER_IDS" \
    "$M_BACKUP_ACCOUNT_IDS" "$M_IDENTITY_DIGEST" <<'PY'
import datetime as dt,json,os,re,sys,tempfile,uuid
(path,run_id,phase,reason,primary_account_id,group_id,member_ids_csv,
 backup_ids_csv,identity_digest)=sys.argv[1:]
if str(uuid.UUID(run_id)) != run_id:
    raise SystemExit(1)
allowed={'PAUSE_INTENT','PAUSE_ACKED','SEAL_INTENT','SEAL_ACKED','PAUSE_AMBIGUOUS',
         'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED'}
if phase not in allowed:
    raise SystemExit(1)
if not reason or len(reason)>300 or not reason.isascii() or not re.fullmatch(r'[a-z0-9_]+',reason):
    raise SystemExit(1)
maximum=9223372036854775807
if (not primary_account_id.isdigit() or int(primary_account_id)<=0 or
    int(primary_account_id)>maximum or not group_id.isdigit() or
    int(group_id)<=0 or int(group_id)>maximum):
    raise SystemExit(1)
def parse_ids(value):
    tokens=value.split(',')
    if (not tokens or any(not token.isdigit() or int(token)<=0 or int(token)>maximum
                          for token in tokens)):
        raise ValueError
    result=[int(token) for token in tokens]
    if result != sorted(set(result)) or value != ','.join(str(item) for item in result):
        raise ValueError
    return result
try:
    member_ids=parse_ids(member_ids_csv)
    backup_ids=parse_ids(backup_ids_csv)
except ValueError:
    raise SystemExit(1)
if (int(primary_account_id) not in member_ids or int(primary_account_id) in backup_ids or
    any(value not in member_ids for value in backup_ids) or
    not re.fullmatch(r'[a-f0-9]{64}',identity_digest)):
    raise SystemExit(1)
payload={
  'schema_version':3,
  'run_id':run_id,
  'primary_account_id':int(primary_account_id),
  'group_id':int(group_id),
  'group_member_ids':member_ids,
  'backup_account_ids':backup_ids,
  'identity_digest':identity_digest,
  'phase':phase,
  'reason':reason,
  'created_at':dt.datetime.now(dt.timezone.utc).isoformat(
      timespec='microseconds').replace('+00:00','Z'),
}
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='maintenance-ambiguous.')
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump(payload,f,ensure_ascii=False,sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp,0o600)
    os.replace(tmp,path)
    dfd=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
finally:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY
}

load_maintenance_ambiguity_identity() {
  [[ -s "$MAINTENANCE_AMBIGUITY_FILE" ]] || return 1
  local identity
  identity="$("$PYTHON_BIN" - "$MAINTENANCE_AMBIGUITY_FILE" <<'PY'
import datetime as dt,json,re,sys,uuid
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
    if p.get('schema_version') != 3:
        raise ValueError
    run_id=str(uuid.UUID(str(p.get('run_id') or '')))
    primary=str(p.get('primary_account_id') or '')
    group_id=str(p.get('group_id') or '')
    phase=str(p.get('phase') or '')
    reason=str(p.get('reason') or '')
    created_at=str(p.get('created_at') or '')
    identity_digest=str(p.get('identity_digest') or '')
    maximum=9223372036854775807
    if (not primary.isdigit() or int(primary)<=0 or int(primary)>maximum or
        not group_id.isdigit() or int(group_id)<=0 or int(group_id)>maximum):
        raise ValueError
    def parse_ids(name):
        values=p.get(name)
        if (not isinstance(values,list) or not values or
            any(type(value) is not int or value<=0 or value>maximum for value in values) or
            values != sorted(set(values))):
            raise ValueError
        return values
    member_ids=parse_ids('group_member_ids')
    backup_ids=parse_ids('backup_account_ids')
    if (int(primary) not in member_ids or int(primary) in backup_ids or
        any(value not in member_ids for value in backup_ids) or
        not re.fullmatch(r'[a-f0-9]{64}',identity_digest)):
        raise ValueError
    allowed={'PAUSE_INTENT','PAUSE_ACKED','SEAL_INTENT','SEAL_ACKED','PAUSE_AMBIGUOUS',
             'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED'}
    if (phase not in allowed or not reason or len(reason)>300 or not reason.isascii() or
        not re.fullmatch(r'[a-z0-9_]+',reason)):
        raise ValueError
    raw=created_at[:-1]+'+00:00' if created_at.endswith('Z') else created_at
    stamp=dt.datetime.fromisoformat(raw)
    if stamp.tzinfo is None:
        raise ValueError
    canonical=stamp.astimezone(dt.timezone.utc).isoformat(
        timespec='microseconds').replace('+00:00','Z')
    if canonical != created_at:
        raise ValueError
    print('|'.join((
      run_id,primary,group_id,','.join(str(value) for value in member_ids),
      ','.join(str(value) for value in backup_ids),identity_digest,
      phase,reason,created_at,
    )))
except Exception:
    raise SystemExit(1)
PY
)" || return 1
  IFS='|' read -r M_AMBIGUITY_RUN_ID M_AMBIGUITY_PRIMARY_ACCOUNT_ID \
    M_AMBIGUITY_GROUP_ID M_AMBIGUITY_GROUP_MEMBER_IDS \
    M_AMBIGUITY_BACKUP_ACCOUNT_IDS M_AMBIGUITY_IDENTITY_DIGEST \
    M_AMBIGUITY_PHASE M_AMBIGUITY_REASON M_AMBIGUITY_CREATED_AT <<<"$identity"
  [[ "$M_AMBIGUITY_RUN_ID|$M_AMBIGUITY_PRIMARY_ACCOUNT_ID|$M_AMBIGUITY_GROUP_ID|$M_AMBIGUITY_GROUP_MEMBER_IDS|$M_AMBIGUITY_BACKUP_ACCOUNT_IDS|$M_AMBIGUITY_IDENTITY_DIGEST|$M_AMBIGUITY_PHASE|$M_AMBIGUITY_REASON|$M_AMBIGUITY_CREATED_AT" == "$identity" ]]
}
read_maintenance_state() {
  [[ -s "$MAINTENANCE_FILE" ]] || return 1
  "$PYTHON_BIN" - "$MAINTENANCE_FILE" <<'PY'
import datetime as dt,hashlib,json,re,sys,uuid
try:
    p=json.load(open(sys.argv[1],encoding='utf-8'))
    if p.get('schema_version') != 7:
        raise ValueError
    phase=str(p.get('phase') or '')
    allowed={
      'PREPARING','EXTERNAL_PAUSED','PAUSE_INTENT','PAUSE_ACKED','SEAL_INTENT',
      'SEAL_ACKED','PAUSE_AMBIGUOUS',
      'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED',
    }
    if phase not in allowed:
        raise ValueError
    run_id=str(uuid.UUID(str(p.get('run_id') or '')))
    primary_account_id=str(p.get('primary_account_id') or '')
    group_id=str(p.get('group_id') or '')
    maximum=9223372036854775807
    if (not primary_account_id.isdigit() or int(primary_account_id)<=0 or
        int(primary_account_id)>maximum or not group_id.isdigit() or
        int(group_id)<=0 or int(group_id)>maximum):
        raise ValueError
    def parse_ids(name):
        values=p.get(name)
        if (not isinstance(values,list) or not values or
            any(type(value) is not int or value<=0 or value>maximum for value in values) or
            values != sorted(set(values))):
            raise ValueError
        return values
    member_ids=parse_ids('group_member_ids')
    backup_ids=parse_ids('backup_account_ids')
    if (int(primary_account_id) not in member_ids or
        int(primary_account_id) in backup_ids or
        any(value not in member_ids for value in backup_ids)):
        raise ValueError
    member_ids_csv=','.join(str(value) for value in member_ids)
    backup_ids_csv=','.join(str(value) for value in backup_ids)
    numeric=('log_watermark','sink_dropped_base','sink_failed_base','sink_written_base')
    if any(type(p.get(name)) is not int or p.get(name)<0 for name in numeric):
        raise ValueError
    nums=[str(p.get(name)) for name in numeric]
    incarnation=str(p.get('sub2_incarnation') or '')
    if not incarnation or len(incarnation)>200 or '|' in incarnation or not incarnation.isascii():
        raise ValueError
    identity_digest=str(p.get('identity_digest') or '')
    if not re.fullmatch(r'[a-f0-9]{64}',identity_digest):
        raise ValueError
    identity_payload={
      'schema_version':7,
      'run_id':run_id,
      'primary_account_id':int(primary_account_id),
      'group_id':int(group_id),
      'group_member_ids':member_ids,
      'backup_account_ids':backup_ids,
      'log_watermark':int(nums[0]),
      'sub2_incarnation':incarnation,
      'sink_dropped_base':int(nums[1]),
      'sink_failed_base':int(nums[2]),
      'sink_written_base':int(nums[3]),
    }
    canonical=json.dumps(identity_payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    if hashlib.sha256(canonical).hexdigest() != identity_digest:
        raise ValueError

    pause_req=str(p.get('pause_request_id') or '')
    pause_log=str(p.get('pause_log_id') or '')
    pause_checkpoint=str(p.get('pause_response_checkpoint') or '')
    pause_response_at=str(p.get('pause_response_updated_at') or '')
    seal_req=str(p.get('seal_request_id') or '')
    seal_log=str(p.get('seal_log_id') or '')
    seal_response_at=str(p.get('seal_response_updated_at') or '')
    restore_req=str(p.get('restore_request_id') or '')
    restore_log=str(p.get('restore_log_id') or '')
    restore_checkpoint=str(p.get('restore_response_checkpoint') or '')
    restore_response_at=str(p.get('restore_response_updated_at') or '')
    owned_at=str(p.get('owned_updated_at') or '')
    owned_xmin=str(p.get('owned_xmin') or '')
    req_re=re.compile(r'^codex2api-maint-[a-f0-9-]{36}-(pause|seal|restore)$')
    for value in (pause_req,seal_req,restore_req):
        if value and (len(value)>64 or not value.isascii() or not req_re.fullmatch(value)):
            raise ValueError
    for value in (pause_log,seal_log,restore_log,owned_xmin):
        if value and (not value.isdigit() or int(value)<=0):
            raise ValueError
    def valid_stamp(value):
        if not value:
            return True
        raw=value[:-1]+'+00:00' if value.endswith('Z') else value
        stamp=dt.datetime.fromisoformat(raw)
        if stamp.tzinfo is None:
            raise ValueError
        canonical_stamp=stamp.astimezone(dt.timezone.utc).isoformat(
            timespec='microseconds').replace('+00:00','Z')
        return canonical_stamp == value
    for value in (pause_response_at,seal_response_at,restore_response_at,owned_at):
        if not valid_stamp(value):
            raise ValueError
    pause_states={'none','pending','validated','transport_or_non200','invalid'}
    restore_states=pause_states|{'explicitly_resolved'}
    if pause_checkpoint not in pause_states or restore_checkpoint not in restore_states:
        raise ValueError
    if (pause_checkpoint == 'validated') != bool(pause_response_at):
        raise ValueError
    if (restore_checkpoint == 'validated') != bool(restore_response_at):
        raise ValueError

    if phase in {'PREPARING','EXTERNAL_PAUSED'}:
        if (pause_checkpoint != 'none' or restore_checkpoint != 'none' or
            any((pause_req,pause_log,pause_response_at,seal_req,seal_log,seal_response_at,
                 restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
            raise ValueError
    elif phase == 'PAUSE_INTENT':
        if (not pause_req or pause_log or pause_checkpoint == 'none' or
            restore_checkpoint != 'none' or
            any((seal_req,seal_log,seal_response_at,restore_req,restore_log,
                 restore_response_at,owned_at,owned_xmin))):
            raise ValueError
    elif phase == 'PAUSE_ACKED':
        if (not pause_req or not pause_log or pause_checkpoint != 'validated' or
            restore_checkpoint != 'none' or
            any((seal_req,seal_log,seal_response_at,restore_req,restore_log,
                 restore_response_at,owned_at,owned_xmin))):
            raise ValueError
    elif phase == 'SEAL_INTENT':
        if (not pause_req or not pause_log or pause_checkpoint != 'validated' or
            not seal_req or seal_log or restore_checkpoint != 'none' or
            any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
            raise ValueError
    elif phase == 'SEAL_ACKED':
        if (not all((pause_req,pause_log,pause_response_at,seal_req,seal_log,
                     seal_response_at)) or pause_checkpoint != 'validated' or
            restore_checkpoint != 'none' or
            any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
            raise ValueError
    elif phase == 'PAUSE_AMBIGUOUS':
        if (not pause_req or pause_checkpoint == 'none' or restore_checkpoint != 'none' or
            any((restore_req,restore_log,restore_response_at,owned_at,owned_xmin))):
            raise ValueError
        if pause_log and pause_checkpoint != 'validated':
            raise ValueError
        if seal_log and (not seal_req or not seal_response_at):
            raise ValueError
        if seal_response_at and not seal_req:
            raise ValueError
    elif phase in {'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS','RESTORED'}:
        if (not all((pause_req,pause_log,pause_response_at,seal_req,seal_log,
                     seal_response_at,owned_at,owned_xmin)) or
            pause_checkpoint != 'validated'):
            raise ValueError
        if phase == 'OWNED':
            if restore_checkpoint != 'none' or any((restore_req,restore_log,restore_response_at)):
                raise ValueError
        elif phase == 'RESTORE_INTENT':
            if not restore_req or restore_log or restore_checkpoint == 'none':
                raise ValueError
        elif phase in {'RESTORE_ACKED','RESTORED'}:
            if (not restore_req or not restore_log or
                restore_checkpoint not in {'validated','explicitly_resolved'}):
                raise ValueError
        elif phase == 'RESTORE_AMBIGUOUS':
            if not restore_req or restore_checkpoint == 'none':
                raise ValueError
            if restore_log and restore_checkpoint not in {'validated','explicitly_resolved'}:
                raise ValueError

    owned=phase in {'OWNED','RESTORE_INTENT','RESTORE_ACKED','RESTORE_AMBIGUOUS'}
    if p.get('primary_disabled_by_maintenance') is not owned:
        raise ValueError
    if str(p.get('primary_row_version') or '') != owned_xmin:
        raise ValueError
    if p.get('pending_primary_row_version') is not None:
        raise ValueError
    fields=(
      pause_req,pause_log,pause_checkpoint,pause_response_at,
      seal_req,seal_log,seal_response_at,
      restore_req,restore_log,restore_checkpoint,restore_response_at,
      owned_at,owned_xmin,
    )
    print('|'.join((
      phase,run_id,primary_account_id,group_id,member_ids_csv,backup_ids_csv,
      identity_digest,nums[0],incarnation,nums[1],nums[2],nums[3],*fields,
    )))
except Exception:
    raise SystemExit(1)
PY
}
load_maintenance_state() {
  local state
  state="$(read_maintenance_state)" || return 1
  IFS='|' read -r M_PHASE M_RUN_ID M_PRIMARY_ACCOUNT_ID M_GROUP_ID \
    M_GROUP_MEMBER_IDS M_BACKUP_ACCOUNT_IDS M_IDENTITY_DIGEST \
    M_LOG_WATERMARK M_INCARNATION \
    M_SINK_DROPPED M_SINK_FAILED M_SINK_WRITTEN M_PAUSE_REQUEST_ID \
    M_PAUSE_LOG_ID M_PAUSE_RESPONSE_CHECKPOINT M_PAUSE_RESPONSE_UPDATED_AT \
    M_SEAL_REQUEST_ID M_SEAL_LOG_ID M_SEAL_RESPONSE_UPDATED_AT \
    M_RESTORE_REQUEST_ID M_RESTORE_LOG_ID M_RESTORE_RESPONSE_CHECKPOINT \
    M_RESTORE_RESPONSE_UPDATED_AT M_OWNED_UPDATED_AT M_OWNED_XMIN <<<"$state"
  [[ "$(maintenance_state_line)" == "$state" ]]
}

maintenance_identity_matches_current() {
  [[ "$M_PRIMARY_ACCOUNT_ID" == "$BRIDGE_ACCOUNT_ID" && "$M_GROUP_ID" == "$GROUP_ID" ]]
}

validate_maintenance_artifact_identity() {
  MAINTENANCE_IDENTITY_ERROR=""
  M_SIDECAR_ONLY=false
  M_AMBIGUITY_RUN_ID=""
  M_AMBIGUITY_PRIMARY_ACCOUNT_ID=""
  M_AMBIGUITY_GROUP_ID=""
  M_AMBIGUITY_GROUP_MEMBER_IDS=""
  M_AMBIGUITY_BACKUP_ACCOUNT_IDS=""
  M_AMBIGUITY_IDENTITY_DIGEST=""
  local marker_run="" marker_primary="" marker_group="" marker_members=""
  local marker_backups="" marker_digest="" marker_phase=""
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    if ! load_maintenance_state; then
      MAINTENANCE_IDENTITY_ERROR="maintenance_marker_identity_missing_or_invalid"
      return 1
    fi
    marker_run="$M_RUN_ID"
    marker_primary="$M_PRIMARY_ACCOUNT_ID"
    marker_group="$M_GROUP_ID"
    marker_members="$M_GROUP_MEMBER_IDS"
    marker_backups="$M_BACKUP_ACCOUNT_IDS"
    marker_digest="$M_IDENTITY_DIGEST"
    marker_phase="$M_PHASE"
  fi
  if [[ -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    if ! load_maintenance_ambiguity_identity; then
      MAINTENANCE_IDENTITY_ERROR="maintenance_ambiguity_identity_missing_or_invalid"
      return 1
    fi
    if [[ -n "$marker_primary" ]] &&
       [[ "$M_AMBIGUITY_RUN_ID" != "$marker_run" ||
          "$M_AMBIGUITY_PRIMARY_ACCOUNT_ID" != "$marker_primary" ||
          "$M_AMBIGUITY_GROUP_ID" != "$marker_group" ||
          "$M_AMBIGUITY_GROUP_MEMBER_IDS" != "$marker_members" ||
          "$M_AMBIGUITY_BACKUP_ACCOUNT_IDS" != "$marker_backups" ||
          "$M_AMBIGUITY_IDENTITY_DIGEST" != "$marker_digest" ]]; then
      MAINTENANCE_IDENTITY_ERROR="maintenance_artifact_identity_conflict"
      return 1
    fi
    if [[ -n "$marker_phase" ]]; then
      case "$marker_phase" in
        PAUSE_AMBIGUOUS)
          [[ "$M_AMBIGUITY_PHASE" =~ ^(PAUSE_INTENT|PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED|PAUSE_AMBIGUOUS)$ ]] || {
            MAINTENANCE_IDENTITY_ERROR="maintenance_artifact_phase_conflict"
            return 1
          }
          ;;
        SEAL_ACKED)
          if [[ "$M_AMBIGUITY_PHASE" == SEAL_INTENT &&
                "$M_AMBIGUITY_REASON" == ownership_seal_response_not_durable_backups_left_open ]]; then
            :
          else
            [[ "$M_AMBIGUITY_PHASE" == SEAL_ACKED ]] || {
              MAINTENANCE_IDENTITY_ERROR="maintenance_artifact_phase_conflict"
              return 1
            }
          fi
          ;;
        RESTORE_AMBIGUOUS|RESTORE_ACKED)
          [[ "$M_AMBIGUITY_PHASE" =~ ^(RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)$ ]] || {
            MAINTENANCE_IDENTITY_ERROR="maintenance_artifact_phase_conflict"
            return 1
          }
          ;;
        *)
          [[ "$M_AMBIGUITY_PHASE" == "$marker_phase" ]] || {
            MAINTENANCE_IDENTITY_ERROR="maintenance_artifact_phase_conflict"
            return 1
          }
          ;;
      esac
    else
      M_RUN_ID="$M_AMBIGUITY_RUN_ID"
      M_PRIMARY_ACCOUNT_ID="$M_AMBIGUITY_PRIMARY_ACCOUNT_ID"
      M_GROUP_ID="$M_AMBIGUITY_GROUP_ID"
      M_GROUP_MEMBER_IDS="$M_AMBIGUITY_GROUP_MEMBER_IDS"
      M_BACKUP_ACCOUNT_IDS="$M_AMBIGUITY_BACKUP_ACCOUNT_IDS"
      M_IDENTITY_DIGEST="$M_AMBIGUITY_IDENTITY_DIGEST"
      M_PHASE="$M_AMBIGUITY_PHASE"
      M_SIDECAR_ONLY=true
    fi
  fi
  if ! maintenance_identity_matches_current; then
    MAINTENANCE_IDENTITY_ERROR="maintenance_identity_differs_from_current_configuration"
    return 1
  fi
}

reject_maintenance_identity_mismatch() {
  local action="$1"
  emit_event "critical" "$action" "${MAINTENANCE_IDENTITY_ERROR:-maintenance_identity_invalid}" \
    '{"operator_action_required":true,"account_writes":0}'
  return 2
}

transition_maintenance_marker() {
  local expected_phase="$1"
  local next_phase="$2"
  local expected_state="${3:-$(maintenance_state_line)}"
  [[ "$M_PHASE" == "$expected_phase" ]] || return 1
  local persisted
  persisted="$(read_maintenance_state)" || return 1
  [[ "$persisted" == "$expected_state" ]] || return 1
  write_maintenance_marker "$next_phase"
}
PRIMARY_RESPONSE_CHECKPOINT_OUTCOME=""

maintenance_test_barrier_after_primary_response() {
  local action="$1"
  local prefix="${MAINTENANCE_TEST_RESPONSE_BARRIER_PREFIX:-}"
  [[ -n "$TEST_BACKEND" && -n "$prefix" ]] || return 0
  [[ "$action" == pause || "$action" == restore ]] || return 1
  : >"${prefix}.${action}.reached" || return 1
  while [[ ! -e "${prefix}.${action}.release" ]]; do
    sleep 0.05
  done
}

persist_primary_response_checkpoint() {
  local action="$1"
  local api_rc="$2"
  local phase before checkpoint response_updated_at=""
  case "$api_rc" in
    0)
      if [[ "$SCHEDULABLE_WRITE_HTTP_OK" == true && -n "$SCHEDULABLE_WRITE_UPDATED_AT" ]]; then
        checkpoint="validated"
        response_updated_at="$SCHEDULABLE_WRITE_UPDATED_AT"
      else
        checkpoint="invalid"
      fi
      ;;
    1) checkpoint="transport_or_non200" ;;
    2) checkpoint="invalid" ;;
    *) checkpoint="invalid" ;;
  esac
  PRIMARY_RESPONSE_CHECKPOINT_OUTCOME="$checkpoint"
  case "$action" in
    pause)
      phase=PAUSE_INTENT
      [[ "$M_PHASE" == "$phase" ]] || return 1
      before="$(maintenance_state_line)"
      M_PAUSE_RESPONSE_CHECKPOINT="$checkpoint"
      M_PAUSE_RESPONSE_UPDATED_AT="$response_updated_at"
      ;;
    restore)
      phase=RESTORE_INTENT
      [[ "$M_PHASE" == "$phase" ]] || return 1
      before="$(maintenance_state_line)"
      M_RESTORE_RESPONSE_CHECKPOINT="$checkpoint"
      M_RESTORE_RESPONSE_UPDATED_AT="$response_updated_at"
      ;;
    *) return 1 ;;
  esac
  transition_maintenance_marker "$phase" "$phase" "$before"
}

wait_for_restored_primary_snapshot() {
  case "$M_RESTORE_RESPONSE_CHECKPOINT" in
    validated)
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true \
        "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" "$M_RESTORE_RESPONSE_UPDATED_AT"
      ;;
    explicitly_resolved)
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true \
        "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS"
      ;;
    *) return 1 ;;
  esac
}

restored_primary_snapshot_matches() {
  case "$M_RESTORE_RESPONSE_CHECKPOINT" in
    validated)
      account_snapshot_matches "$BRIDGE_ACCOUNT_ID" true "$M_RESTORE_RESPONSE_UPDATED_AT"
      ;;
    explicitly_resolved)
      account_snapshot_matches "$BRIDGE_ACCOUNT_ID" true
      ;;
    *) return 1 ;;
  esac
}


now_rfc3339() {
  date --iso-8601=seconds
}

timestamp_age_at_least() {
  local value="$1"
  local seconds="$2"
  [[ -n "$value" ]] || return 1
  "$PYTHON_BIN" - "$value" "$seconds" <<'PY'
import datetime as dt,re,sys
def parse_rfc3339(value):
    match=re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?'
        r'(Z|[+-]\d{2}:\d{2})',value)
    if not match:
        raise ValueError
    base,fraction,zone=match.groups()
    fraction=((fraction or '')+'000000')[:6]
    zone='+00:00' if zone == 'Z' else zone
    stamp=dt.datetime.fromisoformat(f'{base}.{fraction}{zone}')
    if stamp.tzinfo is None:
        raise ValueError
    return stamp.astimezone(dt.timezone.utc)
try:
    value=parse_rfc3339(sys.argv[1])
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

shared_schedulable_backup_count() {
  local count=0 id
  for id in "${MEMBER_IDS[@]}"; do
    if [[ "$id" != "$BRIDGE_ACCOUNT_ID" &&
          "${MEMBER_STATUS[$id]:-}" == active &&
          "${MEMBER_NOT_DELETED[$id]:-}" == t &&
          "${MEMBER_SCHEDULABLE[$id]:-}" == t &&
          "${MEMBER_ACTIVE_GROUP_COUNT[$id]:-0}" != 1 ]]; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

guard_no_shared_schedulable_backups() {
  local action="${1:-close_backups}"
  local reason="${2:-shared_schedulable_backup_requires_manual_reconciliation}"
  local count
  count="$(shared_schedulable_backup_count)" || return 1
  if (( count > 0 )); then
    emit_event "critical" "$action" "$reason" \
      "$(printf '{\"shared_schedulable_backups\":%s,\"account_writes\":0}' "$count")"
    return 1
  fi
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
  if ! primary_is_exclusive_group_member; then
    CURRENT_CONDITION="primary_shared_across_active_groups"
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
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] &&
     ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "reconcile"
    return 2
  fi
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] &&
     ! guard_maintenance_group_identity "reconcile" false; then
    return 2
  fi
  read_state || {
    rebuild_state_fail_open "state_invalid_or_incompatible" || return 2
    return 0
  }
  if [[ "$STATE_REQUIRES_REBUILD" == true ]]; then
    rebuild_state_fail_open "state_missing" || return 2
    return 0
  fi
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    open_backups || return 2
    write_state "maintenance" 0 "maintenance_marker_present" "$STATE_PROOF_AFTER"
    if [[ -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
      emit_event "critical" "reconcile" \
        "maintenance_ambiguity_sidecar_backups_held_open_operator_action_required" '{}'
    else
      emit_event "ok" "reconcile" "maintenance_backups_held_open" '{}'
    fi
    return 0
  fi

  local schedulable_backups
  schedulable_backups="$(active_backup_count)" || return 2
  local shared_schedulable_backups
  shared_schedulable_backups="$(shared_schedulable_backup_count)" || return 2
  if (( shared_schedulable_backups > 0 )); then
    [[ -n "$STATE_TAKEOVER_STARTED_AT" ]] || STATE_TAKEOVER_STARTED_AT="$(now_rfc3339)"
    STATE_HEALTHY_STREAK=0
    STATE_HEALTHY_SINCE=""
    write_state "recovery_pending" 0 \
      "shared_schedulable_backup_requires_manual_reconciliation" "$STATE_PROOF_AFTER"
    emit_event "critical" "reconcile" \
      "shared_schedulable_backup_requires_manual_reconciliation" \
      "$(printf '{\"shared_schedulable_backups\":%s,\"account_writes\":0}' "$shared_schedulable_backups")"
    return 2
  fi
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
    local group_rc=0
    verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
    if (( group_rc == 2 )); then
      return 4
    elif (( group_rc != 0 )); then
      zero_samples=0
      sleep "$DRAIN_POLL_SECONDS"
      continue
    fi
    if ! ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS"; then
      zero_samples=0
      sleep "$DRAIN_POLL_SECONDS"
      continue
    fi
    local row status sched concurrency
    if ! row="$(api_get_account "$BRIDGE_ACCOUNT_ID")"; then
      zero_samples=0
      sleep "$DRAIN_POLL_SECONDS"
      continue
    fi
    IFS='|' read -r status sched concurrency <<<"$row"
    if [[ ! "$status" =~ ^[a-z_]+$ || ! "$sched" =~ ^(true|false)$ ||
          ! "$concurrency" =~ ^[0-9]+$ ]]; then
      zero_samples=0
      sleep "$DRAIN_POLL_SECONDS"
      continue
    fi
    if [[ "$status" != "active" || "$sched" != "false" ]]; then
      return 5
    fi
    if [[ -n "$M_PAUSE_REQUEST_ID" ]]; then
      local foreign_rc=0
      verify_no_foreign_mutations || foreign_rc=$?
      if (( foreign_rc == 2 )); then
        return 5
      elif (( foreign_rc != 0 )); then
        zero_samples=0
        sleep "$DRAIN_POLL_SECONDS"
        continue
      fi
    fi
    if [[ "$sched" == "false" && "$concurrency" == "0" ]]; then
      zero_samples=$((zero_samples + 1))
      (( zero_samples >= 2 )) && return 0
    else
      zero_samples=0
    fi
    sleep "$DRAIN_POLL_SECONDS"
  done
  return 3
}

mark_pause_ambiguous() {
  local reason="$1"
  local previous="$M_PHASE"
  persist_maintenance_ambiguity "$reason" || {
    emit_event "critical" "prepare_maintenance" \
      "ambiguity_evidence_persist_failed_backups_left_open" \
      "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
    return 1
  }
  if [[ "$previous" != PAUSE_AMBIGUOUS ]]; then
    transition_maintenance_marker "$previous" PAUSE_AMBIGUOUS || {
      emit_event "critical" "prepare_maintenance" \
        "ambiguity_sidecar_persisted_marker_transition_failed" \
        "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
      return 1
    }
  fi
  emit_event "critical" "prepare_maintenance" "$reason" \
    "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
}

mark_restore_ambiguous() {
  local reason="$1"
  local previous="$M_PHASE"
  persist_maintenance_ambiguity "$reason" || {
    emit_event "critical" "finish_maintenance" \
      "ambiguity_evidence_persist_failed_backups_left_open" \
      "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
    return 1
  }
  if [[ "$previous" != RESTORE_AMBIGUOUS ]]; then
    transition_maintenance_marker "$previous" RESTORE_AMBIGUOUS || {
      emit_event "critical" "finish_maintenance" \
        "ambiguity_sidecar_persisted_marker_transition_failed" \
        "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
      return 1
    }
  fi
  emit_event "critical" "finish_maintenance" "$reason" \
    "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
}

retryable_maintenance_evidence_failure() {
  local action="$1"
  local reason="$2"
  emit_event "critical" "$action" "$reason" \
    '{"retryable":true,"artifact_unchanged":true}'
  return 1
}

guard_prepare_recorded_receipt() {
  local request_id="$1"
  local log_id="$2"
  local rc=0
  verify_maintenance_receipt "$request_id" "$log_id" "$M_LOG_WATERMARK" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "prepare_maintenance" \
         "recorded_receipt_temporarily_unverifiable" ;;
    2) mark_pause_ambiguous "recorded_receipt_definitive_conflict" || true ;;
  esac
  return 1
}

guard_prepare_foreign_fence() {
  local rc=0
  verify_no_foreign_mutations || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "prepare_maintenance" \
         "foreign_mutation_fence_temporarily_unverifiable" ;;
    2)
      if [[ "$MAINTENANCE_FOREIGN_FENCE_RESULT" == foreign_mutation_confirmed ]]; then
        mark_pause_ambiguous "foreign_admin_mutation_confirmed" || true
      else
        mark_pause_ambiguous "foreign_fence_definitive_evidence_conflict" || true
      fi
      ;;
  esac
  return 1
}

guard_finish_recorded_receipt() {
  local request_id="$1"
  local log_id="$2"
  local rc=0
  verify_maintenance_receipt "$request_id" "$log_id" "$M_LOG_WATERMARK" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "finish_maintenance" \
         "recorded_receipt_temporarily_unverifiable" ;;
    2) mark_restore_ambiguous "recorded_restore_receipt_definitive_conflict" || true ;;
  esac
  return 1
}

guard_finish_restore_receipt() {
  local request_id="$1"
  local log_id="$2"
  local rc=0
  verify_successful_restore_receipt "$request_id" "$log_id" \
    "$M_LOG_WATERMARK" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "finish_maintenance" \
         "recorded_restore_receipt_temporarily_unverifiable" ;;
    2) mark_restore_ambiguous "recorded_restore_receipt_definitive_conflict" || true ;;
  esac
  return 1
}

guard_owned_recorded_receipt() {
  local request_id="$1"
  local log_id="$2"
  local action="${3:-finish_maintenance}"
  local rc=0
  verify_maintenance_receipt "$request_id" "$log_id" "$M_LOG_WATERMARK" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "$action" \
         "owned_receipt_temporarily_unverifiable" ;;
    2)
      persist_maintenance_ambiguity "owned_receipt_definitive_conflict" || true
      emit_event "critical" "$action" "owned_receipt_definitive_conflict" '{}'
      ;;
  esac
  return 1
}

guard_owned_primary_tuple() {
  local action="${1:-finish_maintenance}"
  local rc=0
  verify_primary_disabled_tuple "$M_OWNED_UPDATED_AT" "$M_OWNED_XMIN" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "$action" \
         "owned_primary_tuple_temporarily_unverifiable" ;;
    2)
      persist_maintenance_ambiguity "owned_primary_tuple_definitive_conflict" || true
      emit_event "critical" "$action" "owned_primary_tuple_definitive_conflict" \
        '{"operator_action_required":true}'
      ;;
  esac
  return 1
}

guard_owned_primary_api_state() {
  local action="${1:-finish_maintenance}"
  local rc=0
  classify_primary_api_state false || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "$action" \
         "owned_primary_api_state_temporarily_unverifiable" ;;
    2)
      persist_maintenance_ambiguity "owned_primary_api_state_definitive_conflict" || true
      emit_event "critical" "$action" "owned_primary_api_state_definitive_conflict" \
        '{"operator_action_required":true}'
      ;;
  esac
  return 1
}

guard_maintenance_runtime_evidence() {
  local action="$1"
  local logging_rc=0 rc=0
  verify_runtime_logging_evidence || logging_rc=$?
  if (( logging_rc != 0 )); then
    if (( logging_rc == 1 )); then
      retryable_maintenance_evidence_failure "$action" \
        "maintenance_runtime_logging_temporarily_unverifiable" || true
    else
      case "$M_PHASE" in
        PREPARING|EXTERNAL_PAUSED)
          emit_event "critical" "$action" "maintenance_runtime_logging_changed_before_ownership" \
            '{"artifact_unchanged":true}'
          ;;
        PAUSE_INTENT|PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED|PAUSE_AMBIGUOUS)
          mark_pause_ambiguous "maintenance_runtime_logging_definitive_conflict" || true
          ;;
        OWNED)
          persist_maintenance_ambiguity "maintenance_runtime_logging_definitive_conflict" || true
          emit_event "critical" "$action" "maintenance_runtime_logging_definitive_conflict" \
            '{"operator_action_required":true}'
          ;;
        RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)
          mark_restore_ambiguous "maintenance_runtime_logging_definitive_conflict" || true
          ;;
      esac
    fi
    return 1
  fi
  verify_runtime_evidence "$M_INCARNATION" "$M_SINK_DROPPED" \
    "$M_SINK_FAILED" "$M_SINK_WRITTEN" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "$action" \
         "maintenance_runtime_evidence_temporarily_unverifiable" ;;
    2)
      case "$M_PHASE" in
        PREPARING|EXTERNAL_PAUSED)
          emit_event "critical" "$action" "maintenance_runtime_evidence_changed_before_ownership" \
            '{"artifact_unchanged":true}'
          ;;
        PAUSE_INTENT|PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED|PAUSE_AMBIGUOUS)
          mark_pause_ambiguous "maintenance_runtime_evidence_definitive_conflict" || true
          ;;
        OWNED)
          persist_maintenance_ambiguity "maintenance_runtime_evidence_definitive_conflict" || true
          emit_event "critical" "$action" "maintenance_runtime_evidence_definitive_conflict" \
            '{"operator_action_required":true}'
          ;;
        RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)
          mark_restore_ambiguous "maintenance_runtime_evidence_definitive_conflict" || true
          ;;
      esac
      ;;
  esac
  return 1
}

guard_finish_foreign_fence() {
  local action="${1:-finish_maintenance}"
  local rc=0
  verify_no_foreign_mutations || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) retryable_maintenance_evidence_failure "$action" \
         "foreign_mutation_fence_temporarily_unverifiable" ;;
    2)
      local conflict_reason="foreign_fence_definitive_evidence_conflict"
      [[ "$MAINTENANCE_FOREIGN_FENCE_RESULT" == foreign_mutation_confirmed ]] &&
        conflict_reason="foreign_admin_mutation_confirmed"
      case "$M_PHASE" in
        OWNED)
          persist_maintenance_ambiguity "${conflict_reason}_after_ownership" || true
          emit_event "critical" "$action" \
            "${conflict_reason}_after_ownership" '{}'
          ;;
        *) mark_restore_ambiguous "${conflict_reason}_during_restore" || true ;;
      esac
      ;;
  esac
  return 1
}

handle_maintenance_group_fence_failure() {
  local action="$1"
  case "$M_PHASE" in
    PAUSE_INTENT|PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED)
      mark_pause_ambiguous "group_identity_changed_after_primary_pause" || true
      ;;
    OWNED)
      persist_maintenance_ambiguity "group_identity_changed_after_ownership" || true
      emit_event "critical" "$action" "group_identity_changed_after_ownership" \
        '{"operator_action_required":true}'
      ;;
    RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)
      mark_restore_ambiguous "group_identity_changed_during_primary_restore" || true
      ;;
    *)
      emit_event "critical" "$action" "maintenance_group_identity_changed" \
        '{"operator_action_required":true}'
      ;;
  esac
  return 1
}

handle_seal_convergence_failure() {
  local expected_tuple="$1"
  local retry_reason="$2"
  local db_retry_reason="$3"
  local conflict_reason="$4"
  local tuple_rc=0
  verify_primary_disabled_tuple "${expected_tuple%%|*}" "${expected_tuple##*|}" || tuple_rc=$?
  case "$tuple_rc" in
    0)
      # The authoritative database tuple is unchanged. A scheduler snapshot or
      # sched:acc generation mismatch is propagation uncertainty only.
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "$retry_reason" || true
      ;;
    1)
      # A failed/malformed DB read cannot prove a competing writer.
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "$db_retry_reason" || true
      ;;
    2)
      # Re-read after the convergence failure proves the seal tuple changed.
      mark_pause_ambiguous "$conflict_reason" || true
      ;;
  esac
  return 1
}

guard_maintenance_group_identity() {
  local action="$1"
  local allow_sticky="$2"
  local rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1)
      emit_event "critical" "$action" "maintenance_group_identity_unverifiable" \
        '{"operator_action_required":true,"artifact_unchanged":true}'
      ;;
    2)
      if [[ "$allow_sticky" == true ]]; then
        handle_maintenance_group_fence_failure "$action" || true
      else
        emit_event "critical" "$action" "maintenance_group_identity_mismatch_read_only_abort" \
          '{"operator_action_required":true,"artifact_unchanged":true}'
      fi
      ;;
    *)
      emit_event "critical" "$action" "maintenance_group_fence_internal_error" \
        '{"operator_action_required":true,"artifact_unchanged":true}'
      ;;
  esac
  return 1
}

preflight_maintenance_request_id() {
  local request_id="$1"
  local count
  count="$(maintenance_request_id_occurrences "$request_id")" || return 1
  [[ "$count" == 0 ]]
}

adopt_seal_intent_receipt() {
  [[ "$M_PHASE" == SEAL_INTENT ]] || return 0

  # A receipt proves only the asynchronous access-log completion. The validated
  # synchronous response generation must already be durable before this INTENT
  # can be adopted; never substitute the current database generation.
  if [[ -z "$M_SEAL_RESPONSE_UPDATED_AT" ]]; then
    mark_pause_ambiguous "ownership_seal_response_generation_not_persisted" || true
    return 2
  fi

  local receipt_rc=0 log_id before
  log_id="$(wait_for_maintenance_receipt "$M_SEAL_REQUEST_ID" "$M_LOG_WATERMARK" \
    "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN")" || receipt_rc=$?
  if (( receipt_rc != 0 )); then
    case "$receipt_rc" in
      1) mark_pause_ambiguous "ownership_seal_receipt_timeout_backups_left_open" || true ;;
      2) mark_pause_ambiguous "ownership_seal_receipt_definitive_conflict" || true ;;
      3) retryable_maintenance_evidence_failure "prepare_maintenance" \
           "ownership_seal_receipt_temporarily_unverifiable" || true ;;
      *) mark_pause_ambiguous "ownership_seal_receipt_internal_error" || true ;;
    esac
    return 2
  fi

  before="$(maintenance_state_line)"
  M_SEAL_LOG_ID="$log_id"
  transition_maintenance_marker SEAL_INTENT SEAL_ACKED "$before" || return 2
}

prepare_maintenance() {
  discover_group || return 2
  local initial_group_id="$GROUP_ID"
  local health queue dropped failed written bootstrap_watermark bootstrap_fence_id bootstrap_fence_log_id
  local initial_member_ids="" current_member_ids=""
  local initial_backup_ids="" current_backup_ids=""
  load_members || return 2
  if primary_is_group_member && ! primary_is_exclusive_group_member; then
    emit_event "critical" "prepare_maintenance" \
      "configured_primary_shared_across_active_groups_primary_unchanged" \
      '{"operator_action_required":true,"account_writes":0}'
    return 2
  fi
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] &&
     ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "prepare_maintenance"
    return 2
  fi
  if [[ -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    emit_event "critical" "prepare_maintenance" \
      "maintenance_ambiguity_sidecar_present_backups_left_open" '{}'
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    open_backups "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || true
    return 2
  fi
  if [[ -e "$MAINTENANCE_FILE" ]]; then
    : # Identity validation above also loaded and structurally validated it.
  else
    initial_member_ids="$(loaded_group_member_ids)" || {
      emit_event "critical" "prepare_maintenance" \
        "initial_group_membership_seal_unverifiable_primary_unchanged" \
        '{"account_writes":0}'
      return 2
    }
    initial_backup_ids="$(loaded_backup_account_ids)" || {
      emit_event "critical" "prepare_maintenance" \
        "initial_backup_identity_seal_unverifiable_primary_unchanged" \
        '{"account_writes":0}'
      return 2
    }
    open_backups "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      emit_event "critical" "prepare_maintenance" \
        "backup_takeover_not_ready_primary_unchanged" '{}'
      return 2
    }
    verify_maintenance_group_identity "$initial_group_id" || {
      emit_event "critical" "prepare_maintenance" \
        "group_changed_after_backup_open_primary_unchanged" '{}'
      return 2
    }
    current_member_ids="$(loaded_group_member_ids)" || return 2
    current_backup_ids="$(loaded_backup_account_ids)" || return 2
    if [[ "$current_member_ids" != "$initial_member_ids" ||
          "$current_backup_ids" != "$initial_backup_ids" ]]; then
      emit_event "critical" "prepare_maintenance" \
        "sealed_maintenance_identity_changed_after_backup_open_primary_unchanged" \
        '{"account_writes":0}'
      return 2
    fi
    verify_runtime_logging_evidence || {
      emit_event "critical" "prepare_maintenance" \
        "runtime_logging_cannot_prove_info_unsampled_primary_unchanged" '{}'
      return 2
    }
    M_RUN_ID="$(new_maintenance_run_id)" || return 2
    M_INCARNATION="$(sub2_runtime_incarnation)" || return 2
    health="$(read_log_sink_health)" || return 2
    IFS='|' read -r queue dropped failed written <<<"$health"
    [[ "$queue" =~ ^[0-9]+$ && "$dropped" =~ ^[0-9]+$ && "$failed" =~ ^[0-9]+$ && "$written" =~ ^[0-9]+$ ]] || return 2
    M_SINK_DROPPED="$dropped"
    M_SINK_FAILED="$failed"
    M_SINK_WRITTEN="$written"
    verify_runtime_evidence "$M_INCARNATION" "$M_SINK_DROPPED" \
      "$M_SINK_FAILED" "$M_SINK_WRITTEN" >/dev/null || return 2
    bootstrap_watermark="$(capture_log_watermark)" || return 2
    [[ "$bootstrap_watermark" =~ ^[0-9]+$ ]] || return 2
    bootstrap_fence_id="$(new_maintenance_request_id fence)" || return 2
    preflight_maintenance_request_id "$bootstrap_fence_id" || return 2
    submit_maintenance_sentinel "$bootstrap_fence_id" || return 2
    bootstrap_fence_log_id="$(wait_for_maintenance_sentinel "$bootstrap_fence_id" \
      "$bootstrap_watermark" "$M_INCARNATION" "$M_SINK_DROPPED" \
      "$M_SINK_FAILED" "$M_SINK_WRITTEN")" || return 2
    verify_maintenance_group_identity "$initial_group_id" || {
      emit_event "critical" "prepare_maintenance" \
        "group_changed_before_maintenance_marker_primary_unchanged" '{}'
      return 2
    }
    current_member_ids="$(loaded_group_member_ids)" || return 2
    current_backup_ids="$(loaded_backup_account_ids)" || return 2
    if [[ "$current_member_ids" != "$initial_member_ids" ||
          "$current_backup_ids" != "$initial_backup_ids" ]]; then
      emit_event "critical" "prepare_maintenance" \
        "sealed_maintenance_identity_changed_before_maintenance_marker_primary_unchanged" \
        '{"account_writes":0}'
      return 2
    fi
    M_LOG_WATERMARK="$bootstrap_fence_log_id"
    M_PHASE=PREPARING
    M_PRIMARY_ACCOUNT_ID="$BRIDGE_ACCOUNT_ID"
    M_GROUP_ID="$initial_group_id"
    M_GROUP_MEMBER_IDS="$initial_member_ids"
    M_BACKUP_ACCOUNT_IDS="$initial_backup_ids"
    M_PAUSE_REQUEST_ID=""
    M_PAUSE_LOG_ID=""
    M_PAUSE_RESPONSE_CHECKPOINT="none"
    M_PAUSE_RESPONSE_UPDATED_AT=""
    M_SEAL_REQUEST_ID=""
    M_SEAL_LOG_ID=""
    M_SEAL_RESPONSE_UPDATED_AT=""
    M_RESTORE_REQUEST_ID=""
    M_RESTORE_LOG_ID=""
    M_RESTORE_RESPONSE_CHECKPOINT="none"
    M_RESTORE_RESPONSE_UPDATED_AT=""
    M_OWNED_UPDATED_AT=""
    M_OWNED_XMIN=""
    M_IDENTITY_DIGEST="$(compute_maintenance_identity_digest)" || return 2
    write_maintenance_marker PREPARING || return 2
  fi
  guard_maintenance_group_identity "prepare_maintenance" true || return 2
  wait_for_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
    emit_event "critical" "prepare_maintenance" \
      "backup_takeover_changed_after_evidence_baseline_primary_unchanged" '{}'
    return 2
  }
  load_members || return 2
  if ! primary_is_group_member; then
    emit_event "critical" "prepare_maintenance" "primary_not_in_group_backups_left_open" '{}'
    return 2
  fi
  if ! primary_is_exclusive_group_member; then
    emit_event "critical" "prepare_maintenance" "primary_shared_across_active_groups" '{}'
    return 2
  fi
  if [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]}" != "active" || "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]}" != "t" ]]; then
    emit_event "critical" "prepare_maintenance" "primary_not_active_primary_unchanged" '{}'
    return 2
  fi

  if [[ "$M_PHASE" != EXTERNAL_PAUSED ]]; then
    guard_maintenance_runtime_evidence prepare_maintenance || return 2
  fi

  local primary_schedulable="${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]}"
  local before request_id api_rc receipt_rc log_id tuple first_tuple second_tuple foreign_rc
  case "$M_PHASE" in
    PREPARING)
      if [[ "$primary_schedulable" == "f" ]]; then
        wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
          emit_event "critical" "prepare_maintenance" "external_pause_snapshot_unconfirmed" '{}'
          return 2
        }
        transition_maintenance_marker PREPARING EXTERNAL_PAUSED || return 2
      elif [[ "$primary_schedulable" == "t" ]]; then
        [[ "${MEMBER_RUNTIME_READY[$BRIDGE_ACCOUNT_ID]}" == "t" ]] || {
          emit_event "critical" "prepare_maintenance" "primary_not_runtime_ready_before_pause" '{}'
          return 2
        }
        wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
          emit_event "critical" "prepare_maintenance" "primary_pre_pause_snapshot_unconfirmed" '{}'
          return 2
        }
        verify_runtime_logging_evidence || {
          emit_event "critical" "prepare_maintenance" \
            "runtime_logging_changed_before_primary_pause" '{}'
          return 2
        }
        ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
          emit_event "critical" "prepare_maintenance" \
            "standby_readiness_changed_before_primary_pause_primary_unchanged" '{}'
          return 2
        }
        foreign_rc=0
        verify_no_foreign_mutations || foreign_rc=$?
        if (( foreign_rc != 0 )); then
          if (( foreign_rc == 1 )); then
            emit_event "critical" "prepare_maintenance" \
              "foreign_mutation_fence_temporarily_unverifiable_before_primary_pause" \
              '{"retryable":true,"artifact_unchanged":true,"primary_writes":0,"phase":"PREPARING"}'
          elif [[ "$MAINTENANCE_FOREIGN_FENCE_RESULT" == foreign_mutation_confirmed ]]; then
            emit_event "critical" "prepare_maintenance" \
              "foreign_admin_mutation_before_primary_pause_primary_unchanged" \
              '{"operator_action_required":true,"manual_marker_rebase_required":true,"primary_writes":0,"phase":"PREPARING","backups_left_open":true}'
          else
            emit_event "critical" "prepare_maintenance" \
              "foreign_fence_definitive_evidence_conflict_before_primary_pause" \
              '{"operator_action_required":true,"manual_marker_rebase_required":true,"primary_writes":0,"phase":"PREPARING","backups_left_open":true}'
          fi
          return 2
        fi
        guard_maintenance_group_identity "prepare_maintenance" true || return 2
        request_id="$(new_maintenance_request_id pause)" || return 2
        preflight_maintenance_request_id "$request_id" || {
          emit_event "critical" "prepare_maintenance" "pause_request_id_preflight_failed" '{}'
          return 2
        }
        before="$(maintenance_state_line)"
        M_PAUSE_REQUEST_ID="$request_id"
        M_PAUSE_RESPONSE_CHECKPOINT="pending"
        M_PAUSE_RESPONSE_UPDATED_AT=""
        transition_maintenance_marker PREPARING PAUSE_INTENT "$before" || return 2
        api_rc=0
        api_set_primary_schedulable "$BRIDGE_ACCOUNT_ID" false "$M_PAUSE_REQUEST_ID" || api_rc=$?
        maintenance_test_barrier_after_primary_response pause || {
          mark_pause_ambiguous "primary_pause_response_barrier_failed_backups_left_open" || true
          return 2
        }
        persist_primary_response_checkpoint pause "$api_rc" || {
          mark_pause_ambiguous "primary_pause_response_checkpoint_persist_failed" || true
          return 2
        }
        if [[ "$PRIMARY_RESPONSE_CHECKPOINT_OUTCOME" != validated ]]; then
          if [[ "$PRIMARY_RESPONSE_CHECKPOINT_OUTCOME" == transport_or_non200 ]]; then
            mark_pause_ambiguous "primary_pause_transport_or_non200_backups_left_open" || true
          else
            mark_pause_ambiguous "primary_pause_response_invalid_backups_left_open" || true
          fi
          return 2
        fi
      else
        emit_event "critical" "prepare_maintenance" "primary_schedulable_state_invalid" '{}'
        return 2
      fi
      ;;
    PAUSE_AMBIGUOUS|RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)
      emit_event "critical" "prepare_maintenance" "maintenance_phase_not_preparable" \
        "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
      return 2
      ;;
    PAUSE_INTENT|PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED) ;;
    OWNED)
      guard_maintenance_group_identity "prepare_maintenance" true || return 2
      guard_owned_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" prepare_maintenance || return 2
      guard_owned_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" prepare_maintenance || return 2
      guard_finish_foreign_fence prepare_maintenance || return 2
      guard_owned_primary_api_state prepare_maintenance || return 2
      guard_owned_primary_tuple prepare_maintenance || return 2
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" &&
      full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_RESPONSE_UPDATED_AT" || {
        retryable_maintenance_evidence_failure "prepare_maintenance" \
          "owned_evidence_temporarily_unverifiable" || true
        return 2
      }
      guard_maintenance_group_identity "prepare_maintenance" true || return 2
      write_state "maintenance" 0 "maintenance_prepared" "$(now_rfc3339)"
      emit_event "ok" "prepare_maintenance" "maintenance_ready" '{"primary_owned":true,"phase":"OWNED"}'
      return 0
      ;;
    EXTERNAL_PAUSED)
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
        emit_event "critical" "prepare_maintenance" "external_pause_changed_backups_left_open" '{}'
        return 2
      }
      ;;
    *) return 2 ;;
  esac

  if [[ "$M_PHASE" == PAUSE_INTENT ]]; then
    if [[ "$M_PAUSE_RESPONSE_CHECKPOINT" != validated ]]; then
      case "$M_PAUSE_RESPONSE_CHECKPOINT" in
        pending) mark_pause_ambiguous "primary_pause_response_pending_requires_resolution" || true ;;
        transport_or_non200) mark_pause_ambiguous "primary_pause_transport_or_non200_requires_resolution" || true ;;
        invalid) mark_pause_ambiguous "primary_pause_invalid_response_requires_resolution" || true ;;
        *) mark_pause_ambiguous "primary_pause_response_checkpoint_invalid" || true ;;
      esac
      return 2
    fi
    receipt_rc=0
    log_id="$(wait_for_maintenance_receipt "$M_PAUSE_REQUEST_ID" "$M_LOG_WATERMARK" \
      "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN")" || receipt_rc=$?
    if (( receipt_rc != 0 )); then
      case "$receipt_rc" in
        1) mark_pause_ambiguous "primary_pause_receipt_timeout_backups_left_open" || true ;;
        2) mark_pause_ambiguous "primary_pause_receipt_definitive_conflict" || true ;;
        3) retryable_maintenance_evidence_failure "prepare_maintenance" \
             "primary_pause_receipt_temporarily_unverifiable" || true ;;
        *) mark_pause_ambiguous "primary_pause_receipt_internal_error" || true ;;
      esac
      return 2
    fi
    before="$(maintenance_state_line)"
    M_PAUSE_LOG_ID="$log_id"
    transition_maintenance_marker PAUSE_INTENT PAUSE_ACKED "$before" || return 2
  fi

  # A resumed seal INTENT has no recorded log id yet, so it must adopt its
  # unique durable receipt before any foreign-write fence or drain proof. The
  # adoption never resubmits the seal and creates the exact log-id tuple used by
  # every later exemption.
  if [[ "$M_PHASE" == SEAL_INTENT ]]; then
    adopt_seal_intent_receipt || return 2
  fi

  if [[ "$M_PHASE" == PAUSE_ACKED ]]; then
    guard_prepare_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
    guard_prepare_foreign_fence || return 2
    local primary_state_rc=0
    classify_primary_api_state false || primary_state_rc=$?
    if (( primary_state_rc == 2 )); then
      mark_pause_ambiguous "primary_pause_state_definitive_conflict" || true
      return 2
    elif (( primary_state_rc != 0 )); then
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "primary_pause_state_temporarily_unverifiable" || true
      return 2
    fi
    wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false \
      "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" "$M_PAUSE_RESPONSE_UPDATED_AT" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "primary_pause_snapshot_temporarily_unverifiable" || true
      return 2
    }
  fi

  local drain_rc=0
  wait_for_primary_drain || drain_rc=$?
  if (( drain_rc != 0 )); then
    case "$drain_rc" in
      3) emit_event "critical" "prepare_maintenance" "primary_drain_not_proven_before_deadline" \
           '{"artifact_unchanged":true}' ;;
      4) handle_maintenance_group_fence_failure "prepare_maintenance" || true ;;
      5) mark_pause_ambiguous "primary_drain_definitive_conflict_backups_left_open" || true ;;
      *) retryable_maintenance_evidence_failure "prepare_maintenance" \
           "primary_drain_internal_result_unverifiable" || true ;;
    esac
    return 2
  fi
  sleep "$MAINTENANCE_DRAIN_SETTLE_SECONDS"
  drain_rc=0
  wait_for_primary_drain || drain_rc=$?
  if (( drain_rc != 0 )); then
    case "$drain_rc" in
      3) emit_event "critical" "prepare_maintenance" "primary_settle_drain_not_proven_before_deadline" \
           '{"artifact_unchanged":true}' ;;
      4) handle_maintenance_group_fence_failure "prepare_maintenance" || true ;;
      5) mark_pause_ambiguous "primary_settle_drain_definitive_conflict_backups_left_open" || true ;;
      *) retryable_maintenance_evidence_failure "prepare_maintenance" \
           "primary_settle_drain_internal_result_unverifiable" || true ;;
    esac
    return 2
  fi

  if [[ "$M_PHASE" == PAUSE_ACKED ]]; then
    guard_prepare_foreign_fence || return 2
    primary_state_rc=0
    classify_primary_api_state false || primary_state_rc=$?
    if (( primary_state_rc == 2 )); then
      mark_pause_ambiguous "primary_pause_changed_before_ownership_seal" || true
      return 2
    elif (( primary_state_rc != 0 )); then
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "primary_state_unverifiable_before_ownership_seal" || true
      return 2
    fi
    account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "primary_snapshot_unverifiable_before_ownership_seal" || true
      return 2
    }
    guard_maintenance_runtime_evidence prepare_maintenance || return 2
    ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "standby_readiness_unverifiable_before_ownership_seal" || true
      return 2
    }
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    request_id="$(new_maintenance_request_id seal)" || return 2
    preflight_maintenance_request_id "$request_id" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "seal_request_id_preflight_failed_before_write" || true
      return 2
    }
    before="$(maintenance_state_line)"
    M_SEAL_REQUEST_ID="$request_id"
    transition_maintenance_marker PAUSE_ACKED SEAL_INTENT "$before" || return 2
    api_rc=0
    api_set_primary_schedulable "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_REQUEST_ID" || api_rc=$?
    if (( api_rc != 0 )); then
      mark_pause_ambiguous "ownership_seal_response_not_durable_backups_left_open"
      return 2
    fi
    # Persist the validated synchronous response before waiting on the async
    # access-log receipt.  A read-side outage can then resume this exact INTENT
    # without reissuing the seal or losing its database-generation fence.
    before="$(maintenance_state_line)"
    M_SEAL_RESPONSE_UPDATED_AT="$SCHEDULABLE_WRITE_UPDATED_AT"
    transition_maintenance_marker SEAL_INTENT SEAL_INTENT "$before" || {
      mark_pause_ambiguous "ownership_seal_response_evidence_persist_failed" || true
      return 2
    }
  fi

  if [[ "$M_PHASE" == SEAL_INTENT ]]; then
    adopt_seal_intent_receipt || return 2
  fi

  if [[ "$M_PHASE" == SEAL_ACKED ]]; then
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    guard_prepare_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
    guard_prepare_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" || return 2
    guard_prepare_foreign_fence || return 2
    primary_state_rc=0
    classify_primary_api_state false || primary_state_rc=$?
    if (( primary_state_rc == 2 )); then
      mark_pause_ambiguous "ownership_seal_primary_state_definitive_conflict" || true
      return 2
    elif (( primary_state_rc != 0 )); then
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "ownership_seal_primary_state_temporarily_unverifiable" || true
      return 2
    fi
    ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "ownership_seal_standby_readiness_temporarily_unverifiable" || true
      return 2
    }
    first_tuple="$(capture_primary_disabled_tuple)" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "ownership_seal_database_tuple_temporarily_unverifiable" || true
      return 2
    }
    [[ "${first_tuple%%|*}" == "$M_SEAL_RESPONSE_UPDATED_AT" ]] || {
      mark_pause_ambiguous "ownership_seal_response_database_mismatch"
      return 2
    }
    wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" &&
    full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_RESPONSE_UPDATED_AT" || {
      handle_seal_convergence_failure "$first_tuple" \
        "ownership_seal_scheduler_convergence_temporarily_unverifiable" \
        "ownership_seal_post_convergence_database_tuple_temporarily_unverifiable" \
        "ownership_seal_database_tuple_changed_during_scheduler_confirmation" || true
      return 2
    }
    sleep "$SNAPSHOT_POLL_SECONDS"
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    guard_prepare_foreign_fence || return 2
    ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "ownership_seal_second_standby_readiness_temporarily_unverifiable" || true
      return 2
    }
    second_tuple="$(capture_primary_disabled_tuple)" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "ownership_seal_second_database_tuple_temporarily_unverifiable" || true
      return 2
    }
    [[ "$second_tuple" == "$first_tuple" ]] || {
      mark_pause_ambiguous "ownership_seal_database_tuple_changed"
      return 2
    }
    account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false &&
    full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_RESPONSE_UPDATED_AT" || {
      handle_seal_convergence_failure "$second_tuple" \
        "ownership_seal_second_confirmation_temporarily_unverifiable" \
        "ownership_seal_second_post_convergence_database_tuple_temporarily_unverifiable" \
        "ownership_seal_database_tuple_changed_during_second_scheduler_confirmation" || true
      return 2
    }
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "standby_readiness_unverifiable_before_owned_persist" || true
      return 2
    }
    before="$(maintenance_state_line)"
    M_OWNED_UPDATED_AT="${first_tuple%%|*}"
    M_OWNED_XMIN="${first_tuple##*|}"
    transition_maintenance_marker SEAL_ACKED OWNED "$before" || return 2
    guard_maintenance_group_identity "prepare_maintenance" true || return 2
    ensure_maintenance_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "owned_post_persist_standby_temporarily_unverifiable" || true
      return 2
    }
    guard_finish_foreign_fence prepare_maintenance || return 2
    guard_owned_primary_api_state prepare_maintenance || return 2
    guard_owned_primary_tuple prepare_maintenance || return 2
    full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_RESPONSE_UPDATED_AT" || {
      retryable_maintenance_evidence_failure "prepare_maintenance" \
        "owned_post_persist_scheduler_temporarily_unverifiable" || true
      return 2
    }
  elif [[ "$M_PHASE" == EXTERNAL_PAUSED ]]; then
    account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false || {
      emit_event "critical" "prepare_maintenance" "external_pause_changed_during_drain" '{}'
      return 2
    }
  fi

  write_state "maintenance" 0 "maintenance_prepared" "$(now_rfc3339)"
  emit_event "ok" "prepare_maintenance" "maintenance_ready" \
    "$(printf '{\"primary_owned\":%s,\"phase\":%s}' \
      "$([[ "$M_PHASE" == "OWNED" ]] && printf true || printf false)" "$(json_quote "$M_PHASE")")"
}

finish_maintenance() {
  discover_group || return 2
  [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] || {
    emit_event "critical" "finish_maintenance" "maintenance_marker_missing" '{}'
    return 2
  }
  if ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "finish_maintenance"
    return 2
  fi
  guard_maintenance_group_identity "finish_maintenance" true || return 2
  if [[ -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    emit_event "critical" "finish_maintenance" \
      "maintenance_ambiguity_sidecar_present_backups_left_open" '{}'
    open_backups "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || true
    return 2
  fi
  : # Identity validation above also loaded and structurally validated the marker.
  local backups_ready=false
  if open_backups "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS"; then
    backups_ready=true
  else
    emit_event "degraded" "finish_maintenance" \
      "backup_takeover_not_ready_evaluating_owned_primary_restore" \
      "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
    case "$M_PHASE" in
      OWNED|RESTORE_INTENT|RESTORE_ACKED|RESTORED) ;;
      EXTERNAL_PAUSED)
        load_members &&
        [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]:-}" == active &&
           "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]:-}" == t &&
           "${MEMBER_RUNTIME_READY[$BRIDGE_ACCOUNT_ID]:-}" == t &&
           "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]:-}" == t ]] || return 2
        ;;
      *) return 2 ;;
    esac
  fi
  guard_maintenance_group_identity "finish_maintenance" true || return 2
  if ! fetch_health || [[ "$HEALTH_SERVICE_STATUS" != "ok" || "$HEALTH_AVAILABLE" -le 0 ]]; then
    if [[ "$backups_ready" == true ]]; then
      emit_event "critical" "finish_maintenance" \
        "service_not_healthy_backups_confirmed_open" '{}'
    else
      emit_event "critical" "finish_maintenance" \
        "service_not_healthy_no_ready_backup_primary_unchanged" '{}'
    fi
    return 2
  fi
  if [[ "$M_PHASE" != EXTERNAL_PAUSED ]]; then
    guard_maintenance_runtime_evidence finish_maintenance || return 2
  fi

  local restored_primary=false
  local before request_id api_rc receipt_rc log_id
  case "$M_PHASE" in
    OWNED)
      guard_owned_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
      guard_owned_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" || return 2
      guard_finish_foreign_fence || return 2
      guard_owned_primary_api_state || return 2
      guard_owned_primary_tuple || return 2
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" &&
      full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "$M_SEAL_RESPONSE_UPDATED_AT" || {
        retryable_maintenance_evidence_failure "finish_maintenance" \
          "primary_ownership_fence_temporarily_unverifiable" || true
        return 2
      }
      sleep "$SNAPSHOT_POLL_SECONDS"
      guard_finish_foreign_fence || return 2
      guard_owned_primary_api_state || return 2
      guard_owned_primary_tuple || return 2
      guard_maintenance_runtime_evidence finish_maintenance || return 2
      guard_maintenance_group_identity "finish_maintenance" true || return 2
      request_id="$(new_maintenance_request_id restore)" || return 2
      preflight_maintenance_request_id "$request_id" || {
        retryable_maintenance_evidence_failure "finish_maintenance" \
          "restore_request_id_preflight_failed_before_write" || true
        return 2
      }
      before="$(maintenance_state_line)"
      M_RESTORE_REQUEST_ID="$request_id"
      M_RESTORE_RESPONSE_CHECKPOINT="pending"
      M_RESTORE_RESPONSE_UPDATED_AT=""
      transition_maintenance_marker OWNED RESTORE_INTENT "$before" || return 2
      api_rc=0
      api_set_primary_schedulable "$BRIDGE_ACCOUNT_ID" true "$M_RESTORE_REQUEST_ID" || api_rc=$?
      maintenance_test_barrier_after_primary_response restore || {
        mark_restore_ambiguous "primary_restore_response_barrier_failed_backups_left_open" || true
        return 2
      }
      persist_primary_response_checkpoint restore "$api_rc" || {
        mark_restore_ambiguous "primary_restore_response_checkpoint_persist_failed" || true
        return 2
      }
      if [[ "$PRIMARY_RESPONSE_CHECKPOINT_OUTCOME" != validated ]]; then
        if [[ "$PRIMARY_RESPONSE_CHECKPOINT_OUTCOME" == transport_or_non200 ]]; then
          mark_restore_ambiguous "primary_restore_transport_or_non200_backups_left_open" || true
        else
          mark_restore_ambiguous "primary_restore_response_invalid_backups_left_open" || true
        fi
        return 2
      fi
      ;;
    RESTORE_INTENT|RESTORE_ACKED) ;;
    PAUSE_ACKED|SEAL_INTENT|SEAL_ACKED)
      emit_event "critical" "finish_maintenance" "maintenance_not_owned_run_prepare_again" \
        "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
      return 2
      ;;
    PREPARING|PAUSE_INTENT|PAUSE_AMBIGUOUS|RESTORE_AMBIGUOUS)
      emit_event "critical" "finish_maintenance" "maintenance_phase_not_finishable" \
        "$(printf '{\"phase\":%s}' "$(json_quote "$M_PHASE")")"
      return 2
      ;;
    EXTERNAL_PAUSED)
      load_members || return 2
      if [[ "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]:-}" != t ]]; then
        account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false || {
          emit_event "critical" "finish_maintenance" \
            "external_primary_pause_snapshot_invalid_backups_held" '{}'
          return 2
        }
        write_state "maintenance" 0 "external_primary_pause_preserved" "$(now_rfc3339)"
        emit_event "degraded" "finish_maintenance" \
          "external_primary_pause_preserved_backups_held_operator_action_required" \
          '{"primary_owned":false,"marker_retained":true}'
        return 2
      fi
      [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]:-}" == active &&
         "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]:-}" == t &&
         "${MEMBER_RUNTIME_READY[$BRIDGE_ACCOUNT_ID]:-}" == t ]] &&
      wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
        emit_event "critical" "finish_maintenance" \
          "external_primary_restore_not_converged_backups_held" '{}'
        return 2
      }
      guard_maintenance_group_identity "finish_maintenance" true || return 2
      load_members || return 2
      if ! guard_no_shared_schedulable_backups finish_maintenance \
        "shared_schedulable_backup_blocks_maintenance_clear"; then
        write_state "maintenance" 0 \
          "shared_schedulable_backup_requires_manual_reconciliation" "$STATE_PROOF_AFTER"
        return 2
      fi
      remove_maintenance_marker
      if (( HEALTH_RELAY_NORMAL_SCHEDULABLE <= 0 )); then
        write_state "failover" 0 "external_primary_restored_relay_zero" "$(now_rfc3339)"
        emit_event "degraded" "finish_maintenance" \
          "external_primary_restored_outside_controller_relay_zero_backups_held" '{}'
      else
        write_state "recovery_pending" 0 "external_primary_restored_outside_controller" "$(now_rfc3339)"
        emit_event "ok" "finish_maintenance" \
          "external_primary_restored_outside_controller_recovery_confirmation_started" \
          "$(printf '{\"required_confirmations\":%s}' "$RECOVERY_CONFIRMATIONS")"
      fi
      return 0
      ;;
    RESTORED) restored_primary=true ;;
    *) return 2 ;;
  esac

  if [[ "$M_PHASE" == RESTORE_INTENT ]]; then
    if [[ "$M_RESTORE_RESPONSE_CHECKPOINT" != validated ]]; then
      case "$M_RESTORE_RESPONSE_CHECKPOINT" in
        pending) mark_restore_ambiguous "primary_restore_response_pending_requires_resolution" || true ;;
        transport_or_non200) mark_restore_ambiguous "primary_restore_transport_or_non200_requires_resolution" || true ;;
        invalid) mark_restore_ambiguous "primary_restore_invalid_response_requires_resolution" || true ;;
        *) mark_restore_ambiguous "primary_restore_response_checkpoint_invalid" || true ;;
      esac
      return 2
    fi
    guard_maintenance_group_identity "finish_maintenance" true || return 2
    receipt_rc=0
    log_id="$(wait_for_maintenance_receipt "$M_RESTORE_REQUEST_ID" "$M_LOG_WATERMARK" \
      "$M_INCARNATION" "$M_SINK_DROPPED" "$M_SINK_FAILED" "$M_SINK_WRITTEN")" || receipt_rc=$?
    if (( receipt_rc != 0 )); then
      case "$receipt_rc" in
        1) mark_restore_ambiguous "primary_restore_receipt_timeout_backups_left_open" || true ;;
        2) mark_restore_ambiguous "primary_restore_receipt_definitive_conflict" || true ;;
        3) retryable_maintenance_evidence_failure "finish_maintenance" \
             "primary_restore_receipt_temporarily_unverifiable" || true ;;
        *) mark_restore_ambiguous "primary_restore_receipt_internal_error" || true ;;
      esac
      return 2
    fi
    guard_maintenance_group_identity "finish_maintenance" true || return 2
    before="$(maintenance_state_line)"
    M_RESTORE_LOG_ID="$log_id"
    transition_maintenance_marker RESTORE_INTENT RESTORE_ACKED "$before" || return 2
  fi

  if [[ "$M_PHASE" == RESTORE_ACKED ]]; then
    guard_maintenance_group_identity "finish_maintenance" true || return 2
    guard_finish_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
    guard_finish_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" || return 2
    guard_finish_restore_receipt "$M_RESTORE_REQUEST_ID" "$M_RESTORE_LOG_ID" || return 2
    guard_finish_foreign_fence || return 2
    local restored_state_rc=0
    classify_primary_api_state true || restored_state_rc=$?
    if (( restored_state_rc == 2 )); then
      mark_restore_ambiguous "primary_restore_state_definitive_conflict" || true
      return 2
    elif (( restored_state_rc != 0 )); then
      retryable_maintenance_evidence_failure "finish_maintenance" \
        "primary_restore_state_temporarily_unverifiable" || true
      return 2
    fi
    wait_for_restored_primary_snapshot &&
    load_members &&
    [[ "${MEMBER_STATUS[$BRIDGE_ACCOUNT_ID]:-}" == active &&
       "${MEMBER_NOT_DELETED[$BRIDGE_ACCOUNT_ID]:-}" == t &&
       "${MEMBER_RUNTIME_READY[$BRIDGE_ACCOUNT_ID]:-}" == t &&
       "${MEMBER_SCHEDULABLE[$BRIDGE_ACCOUNT_ID]:-}" == t ]] || {
      retryable_maintenance_evidence_failure "finish_maintenance" \
        "primary_restore_snapshot_temporarily_unverifiable" || true
      return 2
    }
    guard_maintenance_group_identity "finish_maintenance" true || return 2
    transition_maintenance_marker RESTORE_ACKED RESTORED || return 2
    restored_primary=true
  fi

  if [[ "$M_PHASE" == RESTORED ]]; then
    guard_maintenance_group_identity "finish_maintenance" true || return 2
    guard_finish_foreign_fence || return 2
    guard_finish_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
    guard_finish_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" || return 2
    guard_finish_restore_receipt "$M_RESTORE_REQUEST_ID" "$M_RESTORE_LOG_ID" || return 2
    restored_primary_snapshot_matches || {
      retryable_maintenance_evidence_failure "finish_maintenance" \
        "restored_final_snapshot_temporarily_unverifiable" || true
      return 2
    }
    restored_primary=true
  fi

  guard_maintenance_group_identity "finish_maintenance" true || return 2
  load_members || return 2
  if ! guard_no_shared_schedulable_backups finish_maintenance \
    "shared_schedulable_backup_blocks_maintenance_clear"; then
    write_state "maintenance" 0 \
      "shared_schedulable_backup_requires_manual_reconciliation" "$STATE_PROOF_AFTER"
    return 2
  fi
  if [[ "$M_PHASE" == RESTORED ]]; then
    guard_finish_recorded_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" || return 2
    guard_finish_recorded_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" || return 2
    guard_finish_restore_receipt "$M_RESTORE_REQUEST_ID" "$M_RESTORE_LOG_ID" || return 2
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

# Resolve only the narrow case where a restore was already issued and sticky
# ambiguity prevented the normal state machine from adopting it. This command
# never sends a schedulability mutation. It removes the poison sidecar only
# after two FIFO fences, an unchanged full membership snapshot, unique durable
# 2xx restore evidence, and live primary convergence all agree.
resolve_restore_ambiguity() {
  local action="resolve_restore_ambiguity"
  discover_group || return 2
  if [[ ! -e "$MAINTENANCE_FILE" || ! -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    emit_event "critical" "$action" "restore_ambiguity_artifacts_required" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  fi
  if ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "$action"
    return 2
  fi
  guard_maintenance_group_identity "$action" true || return 2
  [[ "$M_AMBIGUITY_PHASE" =~ ^(RESTORE_INTENT|RESTORE_ACKED|RESTORE_AMBIGUOUS|RESTORED)$ ]] || {
    emit_event "critical" "$action" "restore_ambiguity_sidecar_phase_invalid" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  case "$M_PHASE" in
    RESTORE_AMBIGUOUS|RESTORE_ACKED) ;;
    *)
      emit_event "critical" "$action" "maintenance_phase_not_resolvable" \
        "$(printf '{\"phase\":%s,\"account_writes\":0}' "$(json_quote "$M_PHASE")")"
      return 2
      ;;
  esac
  [[ -n "$M_RESTORE_REQUEST_ID" ]] || {
    emit_event "critical" "$action" "restore_request_evidence_missing" '{"account_writes":0}'
    return 2
  }

  local membership_before membership_after receipt_log_id receipt_check
  membership_before="$(maintenance_group_membership_snapshot)" || {
    emit_event "critical" "$action" "membership_snapshot_unverifiable" '{"account_writes":0}'
    return 2
  }

  local receipt_rc=0
  verify_maintenance_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" \
    "$M_LOG_WATERMARK" || receipt_rc=$?
  (( receipt_rc == 0 )) || {
    emit_event "critical" "$action" "pause_receipt_not_uniquely_valid" '{"account_writes":0}'
    return 2
  }
  receipt_rc=0
  verify_maintenance_receipt "$M_SEAL_REQUEST_ID" "$M_SEAL_LOG_ID" \
    "$M_LOG_WATERMARK" || receipt_rc=$?
  (( receipt_rc == 0 )) || {
    emit_event "critical" "$action" "seal_receipt_not_uniquely_valid" '{"account_writes":0}'
    return 2
  }
  receipt_rc=0
  receipt_log_id="$(unique_successful_restore_receipt "$M_RESTORE_REQUEST_ID" \
    "$M_LOG_WATERMARK")" || receipt_rc=$?
  (( receipt_rc == 0 )) || {
    emit_event "critical" "$action" "restore_receipt_not_unique_2xx" '{"account_writes":0}'
    return 2
  }
  if [[ -n "$M_RESTORE_LOG_ID" && "$M_RESTORE_LOG_ID" != "$receipt_log_id" ]]; then
    emit_event "critical" "$action" "restore_receipt_log_id_conflict" '{"account_writes":0}'
    return 2
  fi

  local fence_rc=0 primary_rc=0
  verify_no_foreign_mutations "$receipt_log_id" || fence_rc=$?
  (( fence_rc == 0 )) || {
    emit_event "critical" "$action" "restore_ambiguity_foreign_fence_not_clean" \
      "$(printf '{\"fence_result\":%s,\"account_writes\":0}' \
        "$(json_quote "$MAINTENANCE_FOREIGN_FENCE_RESULT")")"
    return 2
  }
  classify_primary_api_state true || primary_rc=$?
  (( primary_rc == 0 )) || {
    emit_event "critical" "$action" "restored_primary_api_state_not_proven" '{"account_writes":0}'
    return 2
  }
  wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true \
    "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
    emit_event "critical" "$action" "restored_primary_scheduler_state_not_proven" \
      '{"account_writes":0}'
    return 2
  }
  guard_maintenance_group_identity "$action" true || return 2
  membership_after="$(maintenance_group_membership_snapshot)" || return 2
  if [[ "$membership_after" != "$membership_before" ]]; then
    emit_event "critical" "$action" "maintenance_group_membership_changed" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  fi

  # Close races created while the first live state proof was running. The
  # second sentinel orders every earlier admin event before the final snapshot.
  fence_rc=0
  verify_no_foreign_mutations "$receipt_log_id" || fence_rc=$?
  (( fence_rc == 0 )) || {
    emit_event "critical" "$action" "restore_ambiguity_final_foreign_fence_not_clean" \
      "$(printf '{\"fence_result\":%s,\"account_writes\":0}' \
        "$(json_quote "$MAINTENANCE_FOREIGN_FENCE_RESULT")")"
    return 2
  }
  receipt_rc=0
  receipt_check="$(unique_successful_restore_receipt "$M_RESTORE_REQUEST_ID" \
    "$M_LOG_WATERMARK")" || receipt_rc=$?
  [[ "$receipt_rc" == 0 && "$receipt_check" == "$receipt_log_id" ]] || {
    emit_event "critical" "$action" "restore_receipt_changed_during_resolution" \
      '{"account_writes":0}'
    return 2
  }
  primary_rc=0
  classify_primary_api_state true || primary_rc=$?
  (( primary_rc == 0 )) || {
    emit_event "critical" "$action" "restored_primary_final_state_not_proven" \
      '{"account_writes":0}'
    return 2
  }
  wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" true \
    "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || return 2
  guard_maintenance_group_identity "$action" true || return 2
  membership_after="$(maintenance_group_membership_snapshot)" || return 2
  if [[ "$membership_after" != "$membership_before" ]]; then
    emit_event "critical" "$action" "maintenance_group_membership_changed_at_commit" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  fi

  local before source_phase
  source_phase="$M_PHASE"
  before="$(maintenance_state_line)"
  M_RESTORE_LOG_ID="$receipt_log_id"
  M_RESTORE_RESPONSE_CHECKPOINT="explicitly_resolved"
  M_RESTORE_RESPONSE_UPDATED_AT=""
  transition_maintenance_marker "$source_phase" RESTORE_ACKED "$before" || {
    emit_event "critical" "$action" "restore_evidence_transition_failed" \
      '{"account_writes":0,"retryable":true}'
    return 2
  }
  [[ "$M_PHASE" == RESTORE_ACKED &&
     "$M_RESTORE_LOG_ID" == "$receipt_log_id" &&
     "$M_RESTORE_RESPONSE_CHECKPOINT" == explicitly_resolved &&
     -z "$M_RESTORE_RESPONSE_UPDATED_AT" ]] || return 2
  remove_maintenance_ambiguity || {
    emit_event "critical" "$action" "ambiguity_sidecar_remove_failed" \
      '{"account_writes":0,"retryable":true}'
    return 2
  }
  emit_event "ok" "$action" "restore_ambiguity_resolved_from_evidence" \
    "$(printf '{\"restore_log_id\":%s,\"phase\":\"RESTORE_ACKED\",\"account_writes\":0}' \
      "$receipt_log_id")"
}

# Resolve only the seal timeout case where the primary disable completed and
# both durable log streams prove that exact write, but the synchronous response
# generation was not persisted. This command never mutates any account.
resolve_seal_ambiguity() {
  local action="resolve_seal_ambiguity"
  discover_group || return 2
  if [[ ! -e "$MAINTENANCE_FILE" || ! -e "$MAINTENANCE_AMBIGUITY_FILE" ]]; then
    emit_event "critical" "$action" "seal_ambiguity_artifacts_required" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  fi
  if ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "$action"
    return 2
  fi
  local group_rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
  (( group_rc == 0 )) || {
    emit_event "critical" "$action" "maintenance_group_identity_not_proven" \
      '{"account_writes":0,"artifact_unchanged":true}'
    return 2
  }
  [[ "$M_AMBIGUITY_PHASE" == SEAL_INTENT &&
     "$M_AMBIGUITY_REASON" == ownership_seal_response_not_durable_backups_left_open ]] || {
    emit_event "critical" "$action" "seal_ambiguity_sidecar_not_resolvable" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  case "$M_PHASE" in
    PAUSE_AMBIGUOUS)
      [[ -n "$M_SEAL_REQUEST_ID" && -z "$M_SEAL_LOG_ID" &&
         -z "$M_SEAL_RESPONSE_UPDATED_AT" ]] || {
        emit_event "critical" "$action" "seal_ambiguity_marker_evidence_conflict" \
          '{"account_writes":0,"operator_action_required":true}'
        return 2
      }
      ;;
    SEAL_ACKED)
      [[ -n "$M_SEAL_REQUEST_ID" && "$M_SEAL_LOG_ID" =~ ^[1-9][0-9]*$ &&
         -n "$M_SEAL_RESPONSE_UPDATED_AT" ]] || {
        emit_event "critical" "$action" "seal_ambiguity_commit_tail_invalid" \
          '{"account_writes":0,"operator_action_required":true}'
        return 2
      }
      ;;
    *)
      emit_event "critical" "$action" "maintenance_phase_not_resolvable" \
        "$(printf '{\"phase\":%s,\"account_writes\":0}' "$(json_quote "$M_PHASE")")"
      return 2
      ;;
  esac

  local membership_before membership_after persisted_before committed_state
  local ambiguity_identity_before ambiguity_identity_after
  local seal_record seal_check seal_log_id access_at
  local audit_record audit_check audit_id audit_at audit_latency_ms
  local tuple_before tuple_after tuple_final pause_occurrences seal_occurrences
  local receipt_rc=0 primary_rc=0 fence_rc=0
  persisted_before="$(maintenance_state_line)"
  ambiguity_identity_before="$M_AMBIGUITY_RUN_ID|$M_AMBIGUITY_PRIMARY_ACCOUNT_ID|$M_AMBIGUITY_GROUP_ID|$M_AMBIGUITY_GROUP_MEMBER_IDS|$M_AMBIGUITY_BACKUP_ACCOUNT_IDS|$M_AMBIGUITY_IDENTITY_DIGEST|$M_AMBIGUITY_PHASE|$M_AMBIGUITY_REASON|$M_AMBIGUITY_CREATED_AT"
  membership_before="$(maintenance_group_membership_snapshot)" || {
    emit_event "critical" "$action" "membership_snapshot_unverifiable" '{"account_writes":0}'
    return 2
  }
  [[ "$(loaded_group_member_ids)" == "$M_GROUP_MEMBER_IDS" &&
     "$(loaded_backup_account_ids)" == "$M_BACKUP_ACCOUNT_IDS" ]] || {
    emit_event "critical" "$action" "sealed_membership_identity_changed" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  wait_for_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || {
    emit_event "critical" "$action" "sealed_backups_not_ready" '{"account_writes":0}'
    return 2
  }
  verify_maintenance_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" \
    "$M_LOG_WATERMARK" || receipt_rc=$?
  (( receipt_rc == 0 )) || {
    emit_event "critical" "$action" "pause_receipt_not_uniquely_valid" '{"account_writes":0}'
    return 2
  }
  receipt_rc=0
  seal_record="$(unique_successful_seal_receipt "$M_SEAL_REQUEST_ID" \
    "$M_LOG_WATERMARK")" || receipt_rc=$?
  (( receipt_rc == 0 )) || {
    emit_event "critical" "$action" "seal_receipt_not_unique_200" '{"account_writes":0}'
    return 2
  }
  IFS='|' read -r seal_log_id access_at <<<"$seal_record"
  audit_record="$(unique_schedulable_audit_record "$M_SEAL_REQUEST_ID" false)" || {
    emit_event "critical" "$action" "seal_audit_body_not_uniquely_valid" \
      '{"account_writes":0}'
    return 2
  }
  IFS='|' read -r audit_id audit_at audit_latency_ms <<<"$audit_record"
  pause_occurrences="$(maintenance_request_id_occurrences "$M_PAUSE_REQUEST_ID")" || return 2
  seal_occurrences="$(maintenance_request_id_occurrences "$M_SEAL_REQUEST_ID")" || return 2
  [[ "$pause_occurrences" == 1 && "$seal_occurrences" == 1 ]] || {
    emit_event "critical" "$action" "maintenance_request_id_not_unique" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  if [[ "$M_PHASE" == SEAL_ACKED && "$M_SEAL_LOG_ID" != "$seal_log_id" ]]; then
    emit_event "critical" "$action" "seal_receipt_log_id_conflict" '{"account_writes":0}'
    return 2
  fi

  primary_rc=0
  classify_primary_api_state_drained false || primary_rc=$?
  (( primary_rc == 0 )) || {
    emit_event "critical" "$action" "primary_not_active_disabled_and_drained" \
      '{"account_writes":0}'
    return 2
  }
  tuple_before="$(capture_primary_disabled_tuple)" || {
    emit_event "critical" "$action" "primary_disabled_tuple_unverifiable" \
      '{"account_writes":0}'
    return 2
  }
  seal_evidence_chronology_valid "$M_PAUSE_RESPONSE_UPDATED_AT" \
    "${tuple_before%%|*}" "$audit_at" "$audit_latency_ms" "$access_at" || {
    emit_event "critical" "$action" "seal_generation_not_bound_to_request_timeline" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  if [[ "$M_PHASE" == SEAL_ACKED &&
        "${tuple_before%%|*}" != "$M_SEAL_RESPONSE_UPDATED_AT" ]]; then
    emit_event "critical" "$action" "seal_commit_tail_database_generation_conflict" \
      '{"account_writes":0}'
    return 2
  fi
  wait_for_account_snapshot "$BRIDGE_ACCOUNT_ID" false \
    "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" "${tuple_before%%|*}" &&
  account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false "${tuple_before%%|*}" &&
  full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "${tuple_before%%|*}" || {
    emit_event "critical" "$action" "primary_scheduler_generation_not_converged" \
      '{"account_writes":0}'
    return 2
  }

  fence_rc=0
  if [[ "$M_PHASE" == PAUSE_AMBIGUOUS ]]; then
    verify_no_foreign_mutations "" "$seal_log_id" || fence_rc=$?
  else
    verify_no_foreign_mutations || fence_rc=$?
  fi
  (( fence_rc == 0 )) || {
    emit_event "critical" "$action" "seal_ambiguity_foreign_fence_not_clean" \
      "$(printf '{\"fence_result\":%s,\"account_writes\":0}' \
        "$(json_quote "$MAINTENANCE_FOREIGN_FENCE_RESULT")")"
    return 2
  }
  tuple_after="$(capture_primary_disabled_tuple)" || return 2
  [[ "$tuple_after" == "$tuple_before" ]] || {
    emit_event "critical" "$action" "primary_tuple_changed_after_first_fence" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  group_rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
  (( group_rc == 0 )) || {
    emit_event "critical" "$action" "maintenance_group_identity_changed_after_first_fence" \
      '{"account_writes":0,"artifact_unchanged":true}'
    return 2
  }
  membership_after="$(maintenance_group_membership_snapshot)" || return 2
  [[ "$membership_after" == "$membership_before" ]] || {
    emit_event "critical" "$action" "maintenance_group_membership_changed" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  wait_for_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || return 2
  receipt_rc=0
  seal_check="$(unique_successful_seal_receipt "$M_SEAL_REQUEST_ID" \
    "$M_LOG_WATERMARK")" || receipt_rc=$?
  [[ "$receipt_rc" == 0 && "$seal_check" == "$seal_record" ]] || {
    emit_event "critical" "$action" "seal_receipt_changed_during_resolution" \
      '{"account_writes":0}'
    return 2
  }
  audit_check="$(unique_schedulable_audit_record "$M_SEAL_REQUEST_ID" false)" || return 2
  [[ "$audit_check" == "$audit_record" ]] || {
    emit_event "critical" "$action" "seal_audit_changed_during_resolution" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  receipt_rc=0
  verify_maintenance_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" \
    "$M_LOG_WATERMARK" || receipt_rc=$?
  (( receipt_rc == 0 )) || return 2
  pause_occurrences="$(maintenance_request_id_occurrences "$M_PAUSE_REQUEST_ID")" || return 2
  seal_occurrences="$(maintenance_request_id_occurrences "$M_SEAL_REQUEST_ID")" || return 2
  [[ "$pause_occurrences" == 1 && "$seal_occurrences" == 1 ]] || return 2

  fence_rc=0
  if [[ "$M_PHASE" == PAUSE_AMBIGUOUS ]]; then
    verify_no_foreign_mutations "" "$seal_log_id" || fence_rc=$?
  else
    verify_no_foreign_mutations || fence_rc=$?
  fi
  (( fence_rc == 0 )) || {
    emit_event "critical" "$action" "seal_ambiguity_final_foreign_fence_not_clean" \
      "$(printf '{\"fence_result\":%s,\"account_writes\":0}' \
        "$(json_quote "$MAINTENANCE_FOREIGN_FENCE_RESULT")")"
    return 2
  }
  tuple_final="$(capture_primary_disabled_tuple)" || return 2
  [[ "$tuple_final" == "$tuple_before" ]] || {
    emit_event "critical" "$action" "primary_tuple_changed_after_final_fence" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  primary_rc=0
  classify_primary_api_state_drained false || primary_rc=$?
  (( primary_rc == 0 )) || return 2
  seal_evidence_chronology_valid "$M_PAUSE_RESPONSE_UPDATED_AT" \
    "${tuple_final%%|*}" "$audit_at" "$audit_latency_ms" "$access_at" || return 2
  account_snapshot_matches "$BRIDGE_ACCOUNT_ID" false "${tuple_before%%|*}" &&
  full_account_control_matches "$BRIDGE_ACCOUNT_ID" false "${tuple_before%%|*}" || return 2
  group_rc=0
  verify_maintenance_group_identity "$M_GROUP_ID" || group_rc=$?
  (( group_rc == 0 )) || return 2
  membership_after="$(maintenance_group_membership_snapshot)" || return 2
  [[ "$membership_after" == "$membership_before" ]] || return 2
  wait_for_backups_ready "$MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS" || return 2
  receipt_rc=0
  seal_check="$(unique_successful_seal_receipt "$M_SEAL_REQUEST_ID" \
    "$M_LOG_WATERMARK")" || receipt_rc=$?
  [[ "$receipt_rc" == 0 && "$seal_check" == "$seal_record" ]] || return 2
  audit_check="$(unique_schedulable_audit_record "$M_SEAL_REQUEST_ID" false)" || return 2
  [[ "$audit_check" == "$audit_record" ]] || return 2
  receipt_rc=0
  verify_maintenance_receipt "$M_PAUSE_REQUEST_ID" "$M_PAUSE_LOG_ID" \
    "$M_LOG_WATERMARK" || receipt_rc=$?
  (( receipt_rc == 0 )) || return 2
  pause_occurrences="$(maintenance_request_id_occurrences "$M_PAUSE_REQUEST_ID")" || return 2
  seal_occurrences="$(maintenance_request_id_occurrences "$M_SEAL_REQUEST_ID")" || return 2
  [[ "$pause_occurrences" == 1 && "$seal_occurrences" == 1 ]] || return 2

  if [[ "$M_PHASE" == PAUSE_AMBIGUOUS ]]; then
    M_SEAL_LOG_ID="$seal_log_id"
    M_SEAL_RESPONSE_UPDATED_AT="${tuple_before%%|*}"
    transition_maintenance_marker PAUSE_AMBIGUOUS SEAL_ACKED "$persisted_before" || {
      emit_event "critical" "$action" "seal_evidence_transition_failed" \
        '{"account_writes":0,"retryable":true}'
      return 2
    }
  fi
  [[ "$M_PHASE" == SEAL_ACKED && "$M_SEAL_LOG_ID" == "$seal_log_id" &&
     "$M_SEAL_RESPONSE_UPDATED_AT" == "${tuple_before%%|*}" ]] || return 2
  committed_state="$(maintenance_state_line)"
  if [[ -n "$TEST_BACKEND" && "$TEST_STOP_AFTER_SEAL_RESOLUTION_COMMIT" == 1 ]]; then
    emit_event "critical" "$action" "test_stop_after_seal_resolution_commit" \
      '{"account_writes":0,"retryable":true}'
    return 99
  fi
  if ! validate_maintenance_artifact_identity; then
    emit_event "critical" "$action" "seal_commit_tail_artifact_recheck_failed" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  fi
  ambiguity_identity_after="$M_AMBIGUITY_RUN_ID|$M_AMBIGUITY_PRIMARY_ACCOUNT_ID|$M_AMBIGUITY_GROUP_ID|$M_AMBIGUITY_GROUP_MEMBER_IDS|$M_AMBIGUITY_BACKUP_ACCOUNT_IDS|$M_AMBIGUITY_IDENTITY_DIGEST|$M_AMBIGUITY_PHASE|$M_AMBIGUITY_REASON|$M_AMBIGUITY_CREATED_AT"
  [[ "$(maintenance_state_line)" == "$committed_state" &&
     "$ambiguity_identity_after" == "$ambiguity_identity_before" &&
     "$M_PHASE" == SEAL_ACKED &&
     "$M_AMBIGUITY_PHASE" == SEAL_INTENT &&
     "$M_AMBIGUITY_REASON" == ownership_seal_response_not_durable_backups_left_open ]] || {
    emit_event "critical" "$action" "seal_commit_tail_artifact_changed_before_cleanup" \
      '{"account_writes":0,"operator_action_required":true}'
    return 2
  }
  remove_maintenance_ambiguity || {
    emit_event "critical" "$action" "ambiguity_sidecar_remove_failed" \
      '{"account_writes":0,"retryable":true}'
    return 2
  }
  emit_event "ok" "$action" "seal_ambiguity_resolved_from_evidence" \
    "$(printf '{\"seal_log_id\":%s,\"phase\":\"SEAL_ACKED\",\"account_writes\":0,\"evidence_scope\":\"logged_admin_api_and_in_resolution_tuple_stability\"}' \
      "$seal_log_id")"
}

status_command() {
  discover_group || return 2
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] &&
     ! validate_maintenance_artifact_identity; then
    reject_maintenance_identity_mismatch "status"
    return 2
  fi
  if [[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] &&
     ! guard_maintenance_group_identity "status" false; then
    return 2
  fi
  load_members || return 2
  if ! primary_is_group_member; then
    emit_event "critical" "status" "primary_not_in_group" '{}'
    return 2
  fi
  if ! primary_is_exclusive_group_member; then
    emit_event "critical" "status" "primary_shared_across_active_groups" '{}'
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
      "$([[ -e "$MAINTENANCE_FILE" || -e "$MAINTENANCE_AMBIGUITY_FILE" ]] && printf true || printf false)" \
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
  printf 'usage: %s {reconcile|status|prepare-maintenance|finish-maintenance|resolve-seal-ambiguity|resolve-restore-ambiguity}\n' "$0" >&2
}

command="${1:-reconcile}"
case "$command" in
  reconcile|status|prepare-maintenance|finish-maintenance|resolve-seal-ambiguity|resolve-restore-ambiguity) ;;
  *) usage; exit 64 ;;
esac

case "$command" in
  prepare-maintenance|finish-maintenance|resolve-seal-ambiguity|resolve-restore-ambiguity)
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
  resolve-seal-ambiguity) resolve_seal_ambiguity ;;
  resolve-restore-ambiguity) resolve_restore_ambiguity ;;
esac
