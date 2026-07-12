#!/usr/bin/env bash

set -uo pipefail

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd "$TEST_DIR/.." && pwd)"
readonly WATCHDOG="$ROOT_DIR/relay-health-watchdog.sh"
readonly SERVICE_UNIT="$ROOT_DIR/systemd/codex2api-relay-health-watchdog.service"
readonly TIMER_UNIT="$ROOT_DIR/systemd/codex2api-relay-health-watchdog.timer"
readonly SYSTEMD_SELFTEST="$TEST_DIR/systemd-selftest.sh"
readonly MUTATION_PATTERN='(\$DOCKER_BIN|(^|[/[:space:]])docker)"?[[:space:]]+(compose[[:space:]]+)?(restart|start|stop|kill|rm|update)|(^|[/[:space:]])systemctl[[:space:]]+(restart|start|stop|enable|disable|kill|daemon-reload|reset-failed)|((\$CURL_BIN)|curl).*((--request|-X)[[:space:]]*(POST|PUT|PATCH|DELETE)|--data|--form|--upload-file|-[dFT]([[:space:]]|$))|^[[:space:]]*(UPDATE|DELETE|INSERT|ALTER|DROP|TRUNCATE|MERGE|CREATE|REPLACE|GRANT|REVOKE)[[:space:]]'

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mock_bin="$tmp_dir/bin"
mkdir -p "$mock_bin"

cat > "$mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$MOCK_HEALTH_JSON"
EOF

cat > "$mock_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail

if [[ "$1" == "inspect" ]]; then
  name="${!#}"
  state="running"
  restarting="false"
  restart_count="0"
  health="healthy"

  if [[ "$name" == "codex2api" ]]; then
    state="${MOCK_CODEX_STATE:-running}"
    restarting="${MOCK_CODEX_RESTARTING:-false}"
    restart_count="${MOCK_CODEX_RESTART_COUNT:-0}"
    health="none"
  fi
  printf '%s|%s|%s|%s\n' "$state" "$restarting" "$restart_count" "$health"
  exit 0
fi

if [[ "$1" != "exec" ]]; then
  exit 99
fi

container="$2"
shift 2
joined="$*"

case "$container:$joined" in
  codex2api-postgres:pg_isready*)
    exit 0
    ;;
  codex2api-redis:redis-cli*)
    printf '%s\n' "NOAUTH Authentication required."
    exit 0
    ;;
  codex2api-postgres:*psql*)
    if [[ "${MOCK_RELAY_FIXTURE:-}" == "mixed_oauth_locked" ]]; then
      # Fixture semantics: one enabled OAuth row, one enabled+locked Relay row,
      # and one enabled+unlocked Relay row. The expected Relay counts are 2/2/2.
      if [[ "$joined" != *"credentials ->> 'upstream_type'"* ]] \
        || [[ "$joined" != *"'openai_responses'"* ]] \
        || [[ "$joined" != *"credentials ->> 'base_url'"* ]] \
        || [[ "$joined" != *"credentials ->> 'api_key'"* ]] \
        || [[ "$joined" == *".locked"* ]]; then
        exit 97
      fi
      printf '%s\n' '2|2|2'
      exit 0
    fi
    printf '%s\n' "${MOCK_RELAY_COUNTS:-3|2|2}"
    exit 0
    ;;
  sub2api-postgres:*psql*)
    printf '%s\n' "${MOCK_BRIDGE_ROW:-7692|active|t|t}"
    exit 0
    ;;
esac

exit 98
EOF

chmod +x "$mock_bin/curl" "$mock_bin/docker"

failures=0

fail() {
  printf 'not ok - %s\n' "$1"
  failures=$((failures + 1))
}

pass() {
  printf 'ok - %s\n' "$1"
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  if grep -Fq "$needle" <<< "$haystack"; then
    pass "$label"
  else
    fail "$label"
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  if grep -Fq "$needle" <<< "$haystack"; then
    fail "$label"
  else
    pass "$label"
  fi
}

assert_json_lines() {
  local content="$1"
  local label="$2"
  if printf '%s\n' "$content" | python3 -c '
import json
import sys

lines = [line for line in sys.stdin.read().splitlines() if line]
if not lines:
    raise SystemExit(1)
for line in lines:
    value = json.loads(line)
    if not isinstance(value, dict):
        raise SystemExit(1)
'; then
    pass "$label"
  else
    fail "$label"
  fi
}

contains_mutation() {
  grep -Eiq "$MUTATION_PATTERN" "$@"
}

run_watchdog() {
  local health_json="$1"
  local suffix="$2"
  shift 2

  env \
    CURL_BIN="$mock_bin/curl" \
    DOCKER_BIN="$mock_bin/docker" \
    PYTHON_BIN=python3 \
    FLOCK_BIN=flock \
    LOCK_FILE="$tmp_dir/watchdog-$suffix.lock" \
    MOCK_HEALTH_JSON="$health_json" \
    "$@" \
    "$WATCHDOG"
}

if bash -n "$WATCHDOG" && bash -n "${BASH_SOURCE[0]}" && bash -n "$SYSTEMD_SELFTEST"; then
  pass "bash syntax"
else
  fail "bash syntax"
fi

if grep -Fq 'OnBootSec=90s' "$TIMER_UNIT" \
  && grep -Fq 'OnUnitActiveSec=2min' "$TIMER_UNIT" \
  && grep -Fq 'Persistent=true' "$TIMER_UNIT" \
  && grep -Fq 'RandomizedDelaySec=10s' "$TIMER_UNIT" \
  && grep -Fq 'AccuracySec=15s' "$TIMER_UNIT" \
  && grep -Fq ' 45s ' "$SERVICE_UNIT" \
  && ! grep -Fq -- '--foreground' "$SERVICE_UNIT" \
  && grep -Fq 'KillMode=control-group' "$SERVICE_UNIT" \
  && grep -Fq 'TimeoutStopSec=5s' "$SERVICE_UNIT"; then
  pass "systemd schedule and timeout directives"
else
  fail "systemd schedule and timeout directives"
fi

if ! grep -Fq 'Requisite=docker.service' "$SERVICE_UNIT" \
  || grep -Eq '^(Requires|Wants|BindsTo)=' "$SERVICE_UNIT" \
  || grep -Fq 'ConditionPathExists=' "$SERVICE_UNIT" \
  || ! grep -Fq 'AssertPathExists=/var/run/docker.sock' "$SERVICE_UNIT" \
  || ! grep -Fq 'After=docker.service network-online.target' "$SERVICE_UNIT" \
  || ! grep -Fq 'RuntimeDirectory=codex2api-relay-health-watchdog' "$SERVICE_UNIT" \
  || ! grep -Fq 'RuntimeDirectoryPreserve=yes' "$SERVICE_UNIT" \
  || ! grep -Fq 'ReadWritePaths=/run/codex2api-relay-health-watchdog' "$SERVICE_UNIT" \
  || ! grep -Fq 'Environment=LOCK_FILE=/run/codex2api-relay-health-watchdog/watchdog.lock' "$SERVICE_UNIT" \
  || ! grep -Fq 'ProtectSystem=strict' "$SERVICE_UNIT"; then
  fail "systemd unit must not start Docker and must provide a writable lock directory"
else
  pass "systemd unit is passive and provides a writable lock directory"
fi

relay_query_source="$(sed -n '/^  relay_query="/,/^"/p' "$WATCHDOG")"
if [[ "$relay_query_source" == *"credentials ->> 'upstream_type'"* ]] \
  && [[ "$relay_query_source" == *"'openai_responses'"* ]] \
  && [[ "$relay_query_source" == *"credentials ->> 'base_url'"* ]] \
  && [[ "$relay_query_source" == *"credentials ->> 'api_key'"* ]] \
  && [[ "$relay_query_source" != *".locked"* ]]; then
  pass "Relay fallback excludes mixed OAuth rows and keeps locked Relay rows"
else
  fail "Relay fallback account-type or locked semantics"
fi

if contains_mutation "$WATCHDOG" "$SERVICE_UNIT" "$TIMER_UNIT"; then
  fail "runtime assets contain a mutating service, API, or SQL command"
else
  pass "runtime assets contain no mutating service, API, or SQL command"
fi

mutation_fixture="$tmp_dir/mutation-fixture"
mutation_detection_ok=true
for mutation_line in \
  '"$DOCKER_BIN" restart codex2api' \
  'docker compose restart codex2api' \
  '/usr/bin/docker stop codex2api' \
  '/usr/bin/systemctl enable --now codex2api' \
  '"$CURL_BIN" -X POST http://127.0.0.1/accounts/enable' \
  'curl --data enabled=true http://127.0.0.1/accounts' \
  'curl -d enabled=true http://127.0.0.1/accounts' \
  'UPDATE accounts SET enabled = false' \
  'DELETE FROM accounts'; do
  printf '%s\n' "$mutation_line" > "$mutation_fixture"
  if ! contains_mutation "$mutation_fixture"; then
    mutation_detection_ok=false
  fi
done
if [[ "$mutation_detection_ok" == "true" ]]; then
  pass "mutation detector rejects malicious command fixtures"
else
  fail "mutation detector rejects malicious command fixtures"
fi

recent_heartbeat="$(date --utc +'%Y-%m-%dT%H:%M:%SZ')"
healthy_json="{\"status\":\"ok\",\"available\":8,\"total\":9,\"guardian\":{\"enabled\":true,\"mode\":\"monitor\",\"status\":\"ok\",\"heartbeat_at\":\"$recent_heartbeat\",\"scan_interval_seconds\":60},\"relay\":{\"configured\":3,\"enabled\":2,\"schedulable\":2,\"quarantined\":0,\"probation\":0}}"
set +e
healthy_output="$(run_watchdog "$healthy_json" healthy)"
healthy_rc=$?
set -e
if (( healthy_rc == 0 )); then
  pass "healthy summary exits zero"
else
  fail "healthy summary exits zero"
fi
assert_contains "$healthy_output" '"check":"guardian","status":"ok"' "guardian health is checked"
assert_contains "$healthy_output" '"check":"relay_pool","status":"ok"' "health Relay summary is checked"
assert_contains "$healthy_output" '"check":"bridge_account","status":"ok"' "bridge 7692 is checked"
assert_contains "$healthy_output" '"check":"summary","status":"ok"' "healthy final summary"
assert_json_lines "$healthy_output" "all watchdog lines are valid JSON"

legacy_json='{"status":"ok","available":8,"total":9}'
set +e
legacy_output="$(run_watchdog "$legacy_json" legacy MOCK_RELAY_FIXTURE=mixed_oauth_locked)"
legacy_rc=$?
set -e
if (( legacy_rc == 1 )); then
  pass "legacy health payload exits degraded"
else
  fail "legacy health payload exits degraded"
fi
assert_contains "$legacy_output" '"check":"guardian","status":"skipped"' "missing Guardian summary is compatible"
assert_contains "$legacy_output" '"source":"database_fallback"' "Relay database fallback is used"
assert_contains "$legacy_output" '"configured":"2","enabled":"2","schedulable":"2"' "mixed group ignores OAuth and keeps locked Relay"
assert_contains "$legacy_output" '"message":"live_state_unknown"' "database-only Relay count is never reported healthy"
assert_json_lines "$legacy_output" "fallback lines are valid JSON"

zero_relay_json='{"status":"ok","available":8,"total":9,"guardian":{"enabled":false,"mode":"monitor","status":"disabled"},"relay":{"configured":3,"enabled":2,"schedulable":0,"quarantined":2,"probation":0}}'
set +e
zero_relay_output="$(run_watchdog "$zero_relay_json" zero-relay)"
zero_relay_rc=$?
set -e
if (( zero_relay_rc == 2 )); then
  pass "zero schedulable Relay accounts exits critical"
else
  fail "zero schedulable Relay accounts exits critical"
fi
assert_contains "$zero_relay_output" '"check":"relay_pool","status":"critical"' "zero Relay pool is reported"

set +e
container_output="$(run_watchdog "$healthy_json" bad-container MOCK_CODEX_STATE=exited)"
container_rc=$?
set -e
if (( container_rc == 2 )); then
  pass "stopped codex2api container exits critical"
else
  fail "stopped codex2api container exits critical"
fi
assert_contains "$container_output" '"message":"container_not_stably_running"' "container failure is reported"

stale_json='{"status":"ok","available":8,"total":9,"guardian":{"enabled":true,"mode":"enforce","status":"stale","heartbeat_at":"2020-01-01T00:00:00Z","scan_interval_seconds":60},"relay":{"configured":3,"enabled":2,"schedulable":2,"quarantined":0,"probation":0}}'
set +e
stale_output="$(run_watchdog "$stale_json" stale)"
stale_rc=$?
set -e
if (( stale_rc == 1 )); then
  pass "stale Guardian exits degraded"
else
  fail "stale Guardian exits degraded"
fi
assert_contains "$stale_output" '"check":"guardian","status":"degraded"' "stale Guardian is reported"

future_json='{"status":"ok","available":8,"total":9,"guardian":{"enabled":true,"mode":"enforce","status":"ok","heartbeat_at":"2099-01-01T00:00:00Z","scan_interval_seconds":60},"relay":{"configured":3,"enabled":2,"schedulable":2,"quarantined":0,"probation":0}}'
set +e
future_output="$(run_watchdog "$future_json" future)"
future_rc=$?
set -e
if (( future_rc == 1 )); then
  pass "future Guardian heartbeat exits degraded"
else
  fail "future Guardian heartbeat exits degraded"
fi
assert_contains "$future_output" '"message":"guardian_heartbeat_in_future"' "future Guardian heartbeat is explicit"

secret_url='http://watchdog-user:watchdog-password@127.0.0.1:8090/health?token=watchdog-secret'
set +e
redacted_output="$(run_watchdog "$healthy_json" redacted HEALTH_URL="$secret_url")"
redacted_rc=$?
set -e
if (( redacted_rc == 0 )); then
  pass "health URL redaction case exits zero"
else
  fail "health URL redaction case exits zero"
fi
assert_contains "$redacted_output" '"endpoint":"127.0.0.1:8090/health"' "health log keeps only host and path"
assert_not_contains "$redacted_output" 'watchdog-password' "health log removes userinfo"
assert_not_contains "$redacted_output" 'watchdog-secret' "health log removes query secrets"

control_name=$'codex2api-"\\\001-control'
set +e
control_output="$(run_watchdog "$healthy_json" control CODEX_CONTAINER="$control_name")"
control_rc=$?
set -e
if (( control_rc == 0 )); then
  pass "C0 JSON escape case exits zero"
else
  fail "C0 JSON escape case exits zero"
fi
assert_contains "$control_output" '\u0001' "C0 byte is escaped"
assert_json_lines "$control_output" "C0 output remains valid JSON"

for early_case in missing-command invalid-id lock-open; do
  set +e
  case "$early_case" in
    missing-command)
      early_output="$(run_watchdog "$healthy_json" early-missing DOCKER_BIN=/definitely/missing/docker)"
      ;;
    invalid-id)
      early_output="$(run_watchdog "$healthy_json" early-id BRIDGE_ACCOUNT_ID=not-a-number)"
      ;;
    lock-open)
      early_output="$(run_watchdog "$healthy_json" early-lock LOCK_FILE="$tmp_dir/not-created/watchdog.lock")"
      ;;
  esac
  early_rc=$?
  set -e
  if (( early_rc == 3 )); then
    pass "$early_case exits bootstrap code"
  else
    fail "$early_case exits bootstrap code"
  fi
  assert_contains "$early_output" '"check":"summary","status":"critical"' "$early_case emits final summary"
  assert_json_lines "$early_output" "$early_case output remains valid JSON"
done

if [[ "${RUN_SYSTEMD_ISOLATION_TEST:-0}" == "1" ]]; then
  set +e
  systemd_output="$(bash "$SYSTEMD_SELFTEST" 2>&1)"
  systemd_rc=$?
  set -e
  printf '%s\n' "$systemd_output"
  if (( systemd_rc == 0 )); then
    pass "isolated systemd semantics"
  else
    fail "isolated systemd semantics"
  fi
else
  printf '%s\n' "ok - isolated systemd semantics (opt-in skipped)"
fi

if (( failures > 0 )); then
  printf '%s\n' "selftest failed: $failures assertion(s)"
  exit 1
fi

printf '%s\n' "selftest passed"
