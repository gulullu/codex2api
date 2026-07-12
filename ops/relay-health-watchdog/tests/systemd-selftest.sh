#!/usr/bin/env bash
#
# Root-only isolated systemd semantics test. It creates uniquely named transient
# dummy units and an AF_UNIX socket under /run. It never references, starts, or
# stops docker.service, codex2api, sub2api, or any production unit.

set -uo pipefail

readonly TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WATCHDOG="$(cd "$TEST_DIR/.." && pwd)/relay-health-watchdog.sh"

for command_name in systemd-run systemctl systemd-socket-activate python3 flock timeout; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$command_name" >&2
    exit 1
  fi
done
if (( EUID != 0 )); then
  printf '%s\n' "systemd isolation selftest must run as root" >&2
  exit 1
fi

tmp_dir="$(mktemp -d /tmp/codex2api-watchdog-systemd-selftest.XXXXXX)"
prefix="codex2api-watchdog-selftest-$$"
dummy_unit="$prefix-dummy.service"
requisite_unit="$prefix-requisite.service"
timeout_unit="$prefix-timeout.service"
socket_pid=""

cleanup() {
  if [[ -n "$socket_pid" ]] && kill -0 "$socket_pid" 2>/dev/null; then
    kill "$socket_pid" 2>/dev/null || true
    wait "$socket_pid" 2>/dev/null || true
  fi
  systemctl stop "$requisite_unit" "$timeout_unit" "$dummy_unit" >/dev/null 2>&1 || true
  systemctl reset-failed "$requisite_unit" "$timeout_unit" "$dummy_unit" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

failures=0
pass() {
  printf 'ok - %s\n' "$1"
}
fail() {
  printf 'not ok - %s\n' "$1"
  failures=$((failures + 1))
}

# Requisite must fail when its target is inactive without activating that
# target. AssertPathExists must only stat the socket path, not connect to it.
service_marker="$tmp_dir/dummy-service-started"
socket_marker="$tmp_dir/dummy-socket-activated"
socket_path="$tmp_dir/docker.sock"

systemd-run --quiet --unit="$dummy_unit" \
  --property=Type=oneshot \
  --property=RemainAfterExit=yes \
  /usr/bin/touch "$service_marker"
systemctl stop "$dummy_unit"
rm -f "$service_marker"

systemd-socket-activate -l "$socket_path" /usr/bin/touch "$socket_marker" \
  >"$tmp_dir/socket-activate.log" 2>&1 &
socket_pid=$!
for _ in $(seq 1 100); do
  [[ -S "$socket_path" ]] && break
  sleep 0.02
done

set +e
systemd-run --quiet --wait --unit="$requisite_unit" \
  --property=Type=oneshot \
  --property="Requisite=$dummy_unit" \
  --property="After=$dummy_unit" \
  --property="AssertPathExists=$socket_path" \
  /bin/true >/dev/null 2>&1
requisite_rc=$?
set -e

if (( requisite_rc != 0 )) \
  && [[ ! -e "$service_marker" ]] \
  && [[ ! -e "$socket_marker" ]] \
  && [[ "$(systemctl is-active "$dummy_unit" 2>/dev/null || true)" != "active" ]]; then
  pass "Requisite and AssertPathExists do not activate dummy service or socket"
else
  fail "Requisite and AssertPathExists do not activate dummy service or socket"
fi

# A hung descendant that ignores TERM must be removed with the timeout service
# cgroup, and its inherited flock descriptor must not survive.
cat > "$tmp_dir/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$MOCK_HEALTH_JSON"
EOF

cat > "$tmp_dir/docker-ok" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
if [[ "$1" == "inspect" ]]; then
  name="${!#}"
  health="healthy"
  [[ "$name" == "codex2api" ]] && health="none"
  printf 'running|false|0|%s\n' "$health"
  exit 0
fi
container="$2"
shift 2
joined="$*"
case "$container:$joined" in
  codex2api-postgres:pg_isready*) exit 0 ;;
  codex2api-redis:redis-cli*) printf '%s\n' "NOAUTH Authentication required."; exit 0 ;;
  codex2api-postgres:*psql*) printf '%s\n' '2|2|2'; exit 0 ;;
  sub2api-postgres:*psql*) printf '%s\n' '7692|active|t|t'; exit 0 ;;
esac
exit 98
EOF

cat > "$tmp_dir/docker-hang" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
if [[ "$1" == "inspect" ]]; then
  (
    trap '' TERM
    printf '%s\n' "$BASHPID" > "$MOCK_HANG_PID_FILE"
    while :; do
      sleep 60
    done
  ) &
  wait "$!"
fi
exit 99
EOF
chmod +x "$tmp_dir/curl" "$tmp_dir/docker-ok" "$tmp_dir/docker-hang"

heartbeat="$(date --utc +'%Y-%m-%dT%H:%M:%SZ')"
health_json="{\"status\":\"ok\",\"available\":8,\"total\":9,\"guardian\":{\"enabled\":true,\"mode\":\"monitor\",\"status\":\"ok\",\"heartbeat_at\":\"$heartbeat\",\"scan_interval_seconds\":60},\"relay\":{\"configured\":2,\"enabled\":2,\"schedulable\":2,\"quarantined\":0,\"probation\":0}}"
lock_file="$tmp_dir/watchdog.lock"
hang_pid_file="$tmp_dir/hang.pid"

set +e
systemd-run --quiet --wait --unit="$timeout_unit" \
  --property=Type=oneshot \
  --property=KillMode=control-group \
  --property=TimeoutStartSec=5s \
  --property=TimeoutStopSec=2s \
  /usr/bin/timeout --signal=TERM --kill-after=1s 1s \
  /usr/bin/env \
    CURL_BIN="$tmp_dir/curl" \
    DOCKER_BIN="$tmp_dir/docker-hang" \
    PYTHON_BIN=/usr/bin/python3 \
    FLOCK_BIN=/usr/bin/flock \
    LOCK_FILE="$lock_file" \
    MOCK_HANG_PID_FILE="$hang_pid_file" \
    MOCK_HEALTH_JSON="$health_json" \
    "$WATCHDOG" >"$tmp_dir/timeout.log" 2>&1
systemd_run_rc=$?
set -e

exec_status="$(systemctl show "$timeout_unit" --property=ExecMainStatus --value 2>/dev/null || true)"
hang_pid=""
[[ -f "$hang_pid_file" ]] && hang_pid="$(<"$hang_pid_file")"
descendant_alive=false
if [[ "$hang_pid" =~ ^[0-9]+$ ]] && kill -0 "$hang_pid" 2>/dev/null; then
  descendant_alive=true
fi

set +e
env \
  CURL_BIN="$tmp_dir/curl" \
  DOCKER_BIN="$tmp_dir/docker-ok" \
  PYTHON_BIN=/usr/bin/python3 \
  FLOCK_BIN=/usr/bin/flock \
  LOCK_FILE="$lock_file" \
  MOCK_HEALTH_JSON="$health_json" \
  "$WATCHDOG" >"$tmp_dir/reacquire.log" 2>&1
reacquire_rc=$?
set -e

if (( systemd_run_rc != 0 )) \
  && [[ "$exec_status" == "124" ]] \
  && [[ "$descendant_alive" == "false" ]] \
  && (( reacquire_rc == 0 )); then
  pass "timeout cgroup kills hung descendants and releases flock"
else
  printf 'timeout evidence: systemd_run_rc=%s exec_status=%s descendant_alive=%s reacquire_rc=%s\n' \
    "$systemd_run_rc" "$exec_status" "$descendant_alive" "$reacquire_rc" >&2
  printf '%s\n' "--- timeout log ---" >&2
  sed -n '1,80p' "$tmp_dir/timeout.log" >&2
  printf '%s\n' "--- reacquire log ---" >&2
  sed -n '1,80p' "$tmp_dir/reacquire.log" >&2
  printf '%s\n' "--- mock files ---" >&2
  ls -la "$tmp_dir" >&2
  stat "$tmp_dir/curl" "$tmp_dir/docker-ok" "$tmp_dir/docker-hang" >&2 || true
  fail "timeout cgroup kills hung descendants and releases flock"
fi

if (( failures > 0 )); then
  printf 'systemd selftest failed: %s assertion(s)\n' "$failures"
  exit 1
fi

printf '%s\n' "systemd selftest passed"
