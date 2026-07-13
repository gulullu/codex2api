#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
controller="$root/sub2-codex-pro-failover.sh"
wrapper="$root/safe-maintenance.sh"
service_unit="$root/systemd/codex2api-sub2-codex-pro-failover.service"
timer_unit="$root/systemd/codex2api-sub2-codex-pro-failover.timer"
tmp="$(mktemp -d)"
child_pids=()

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  local pid
  for pid in "${child_pids[@]:-}"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${child_pids[@]:-}"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT INT TERM

wait_for_marker() {
  local path="$1"
  local pid="$2"
  local timeout_seconds="$3"
  local deadline=$((SECONDS + timeout_seconds))
  while [[ ! -e "$path" ]]; do
    kill -0 "$pid" 2>/dev/null || return 1
    (( SECONDS < deadline )) || return 1
    sleep 0.05
  done
}

backend="$tmp/backend.sh"
cat >"$backend" <<'BACKEND'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"
shift || true
case "$cmd" in
  discover-group)
    cat "$FAKE_DIR/group"
    ;;
  list-members)
    if [[ -s "$FAKE_DIR/external_pause_on_list_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/list_members_count" ]] || count="$(<"$FAKE_DIR/list_members_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/list_members_count"
      if [[ "$count" == "$(<"$FAKE_DIR/external_pause_on_list_call")" ]]; then
        python3 - "$FAKE_DIR/members" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
rows=[]
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == '7692':
        p[3]='f'
    rows.append('|'.join(p))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
        python3 - "$FAKE_DIR/primary_xmin" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='xmin.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write(str(value)+'\n')
os.replace(tmp,path)
PY
      fi
    fi
    if [[ -s "$FAKE_DIR/inactivate_backup_on_list_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/backup_list_members_count" ]] || count="$(<"$FAKE_DIR/backup_list_members_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/backup_list_members_count"
      IFS='|' read -r target_id target_call <"$FAKE_DIR/inactivate_backup_on_list_call"
      if [[ "$count" == "$target_call" ]]; then
        python3 - "$FAKE_DIR/members" "$target_id" <<'PY'
import os,sys,tempfile
path,account_id=sys.argv[1:]
rows=[]
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == account_id:
        p[2]='inactive'
        p[5]='f'
    rows.append('|'.join(p))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
      fi
    fi
    cat "$FAKE_DIR/members"
    ;;
  outbox-count)
    [[ "${2:-}" == account_changed ]] || exit 1
    printf '0\n'
    ;;
  buckets)
    [[ ! -e "$FAKE_DIR/buckets_fail" ]] || exit 2
    printf '%s\n' '12:openai:forced' '12:openai:single'
    ;;
  bucket-ready)
    [[ ! -e "$FAKE_DIR/bucket_ready_error" ]] || exit 2
    [[ ! -e "$FAKE_DIR/snapshot_not_ready" ]]
    ;;
  bucket-contains)
    [[ ! -e "$FAKE_DIR/snapshot_fail" ]] || exit 1
    id="$3"
    [[ ! -e "$FAKE_DIR/bucket_error_$id" ]] || exit 2
    awk -F '|' -v id="$id" '$1==id && $3=="active" && $4=="t" && $5=="t" {found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;
  meta)
    id="$1"
    python3 - "$FAKE_DIR/members" "$id" <<'PY'
import json,sys
for line in open(sys.argv[1],encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == sys.argv[2]:
        print(json.dumps({
          'Status':p[2],
          'Schedulable':p[3] == 't',
          'RateLimitResetAt':None,
          'OverloadUntil':None if p[5] == 't' else '2999-01-01T00:00:00+00:00',
          'TempUnschedulableUntil':None,
          'ExpiresAt':None,
          'AutoPauseOnExpired':False,
        }))
        raise SystemExit(0)
raise SystemExit(1)
PY
    ;;
  set-schedulable)
    id="$1"
    desired="$2"
	if [[ "$desired" == true ]]; then
	  touch "$FAKE_DIR/started_open_$id"
	  if [[ -s "$FAKE_DIR/wait_for_open_peer_$id" ]]; then
		peer="$(<"$FAKE_DIR/wait_for_open_peer_$id")"
		deadline=$((SECONDS + 4))
		while [[ ! -e "$FAKE_DIR/started_open_$peer" && SECONDS -lt deadline ]]; do
		  sleep 0.05
		done
		if [[ -e "$FAKE_DIR/started_open_$peer" ]]; then
		  touch "$FAKE_DIR/saw_open_peer_$id"
		else
		  exit 75
		fi
	  fi
	fi
	if [[ "$desired" == true && -e "$FAKE_DIR/fail_open_$id" ]]; then
	  exit 1
	fi
    # Parallel open requests share the fixture. Serialize only the tiny durable
    # mutation, never the artificial wait above, so the test can prove overlap.
    exec 8>"$FAKE_DIR/backend-write.lock"
    flock 8
    if [[ "$id" == 7692 && "$desired" == false ]]; then
      python3 - "$FAILOVER_STATE_DIR/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
if p.get('primary_disabled_by_maintenance'):
    raise SystemExit('primary ownership was claimed before disable and drain')
PY
    fi
    printf 'set:%s:%s\n' "$id" "$desired" >>"$FAKE_DIR/events"
    python3 - "$FAKE_DIR/members" "$id" "$desired" <<'PY'
import os,sys,tempfile
path,account_id,desired=sys.argv[1:]
rows=[]
found=False
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == account_id:
        p[3]='t' if desired == 'true' else 'f'
        found=True
    rows.append('|'.join(p))
if not found:
    raise SystemExit(1)
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
    if [[ "$id" == 7692 ]]; then
      python3 - "$FAKE_DIR/primary_xmin" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='xmin.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write(str(value)+'\n')
os.replace(tmp,path)
PY
    fi
    if [[ "$id" != 7692 && "$desired" == false && -e "$FAKE_DIR/flip_after_close" ]]; then
      printf 'error|0|0|0|3|7|0|0|0|0|0|critical\n' >"$FAKE_DIR/health"
    fi
    if [[ "$id" != 7692 && "$desired" == false && -e "$FAKE_DIR/unavailable_after_close" ]]; then
      printf '1|1|901|2026-07-13T16:40:00.000000+08:00|100\n' >"$FAKE_DIR/relay_evidence"
    fi
    if [[ "$id" != 7692 && "$desired" == false && -e "$FAKE_DIR/normal_drop_after_close" ]]; then
      printf 'ok|10|1|1|3|7|100|0|0|0|0|degraded\n' >"$FAKE_DIR/health"
    fi
    ;;
  get-account)
    id="$1"
    concurrency=0
    [[ "$id" == 7692 && -e "$FAKE_DIR/primary_busy" ]] && concurrency=1
    awk -F '|' -v id="$id" -v concurrency="$concurrency" '$1==id {printf "%s|%s|%s|%s\n",$3,($4=="t"?"true":"false"),concurrency,($5=="t"?"true":"false"); found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;
  primary-snapshot)
    id="$1"
    if [[ -s "$FAKE_DIR/bump_xmin_on_snapshot_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/primary_snapshot_count" ]] || count="$(<"$FAKE_DIR/primary_snapshot_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/primary_snapshot_count"
      if [[ "$count" == "$(<"$FAKE_DIR/bump_xmin_on_snapshot_call")" ]]; then
        python3 - "$FAKE_DIR/primary_xmin" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='xmin.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write(str(value)+'\n')
os.replace(tmp,path)
PY
      fi
    fi
    xmin="$(<"$FAKE_DIR/primary_xmin")"
    awk -F '|' -v id="$id" -v xmin="$xmin" '$1==id {printf "%s|%s|%s|%s|%s\n",$3,$4,$5,$6,xmin; found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;
  health)
    [[ ! -e "$FAKE_DIR/health_fail" ]] || exit 2
    cat "$FAKE_DIR/health"
    ;;
  relay-evidence)
    [[ ! -e "$FAKE_DIR/relay_evidence_fail" ]] || exit 1
    cat "$FAKE_DIR/relay_evidence"
    ;;
  primary-proof)
    [[ ! -e "$FAKE_DIR/proof_fail" ]]
    ;;
  redis)
    exit 99
    ;;
  *)
    printf 'unknown fake backend command: %s\n' "$cmd" >&2
    exit 99
    ;;
esac
BACKEND
chmod +x "$backend"

encode_name() {
  printf '%s' "$1" | base64 | tr -d '\n'
}

reset_fixture() {
  rm -rf "$tmp/state" "$tmp/run"
  install -d -m 0700 "$tmp/state" "$tmp/run"
  cat >"$tmp/state/state.json" <<'JSON'
{"schema_version":3,"mode":"normal","healthy_streak":3,"last_reason":"healthy","proof_after":null,"takeover_started_at":null,"last_trigger_at":null,"healthy_since":null,"last_unavailable_id":0,"last_unavailable_at":null,"telemetry_error_streak":0,"effective_zero_streak":0}
JSON
  : >"$tmp/events"
  : >"$tmp/controller.log"
  printf '12|codex-pro|active\n' >"$tmp/group"
  cat >"$tmp/members" <<EOF
7692|$(encode_name codex2api-pro)|active|t|t|t
7693|$(encode_name standby-active)|active|f|t|t
7845|$(encode_name standby-inactive)|inactive|f|t|f
7850|$(encode_name standby-error)|error|f|t|f
EOF
  printf '100\n' >"$tmp/primary_xmin"
  printf 'ok|10|3|3|3|7|300|0|0|0|0|ok\n' >"$tmp/health"
  printf '0|0|0||100\n' >"$tmp/relay_evidence"
  rm -f "$tmp/snapshot_fail" "$tmp/snapshot_not_ready" "$tmp/proof_fail" \
    "$tmp/primary_busy" "$tmp/traffic_outbox" "$tmp/lock-held" \
    "$tmp/flip_after_close" "$tmp/unavailable_after_close" \
    "$tmp/normal_drop_after_close" "$tmp/wrapped-started" "$tmp/relay_evidence_fail"
	rm -f "$tmp"/fail_open_* "$tmp"/bucket_error_*
  rm -f "$tmp"/started_open_* "$tmp"/wait_for_open_peer_* "$tmp"/saw_open_peer_* \
    "$tmp/backend-write.lock"
  rm -f "$tmp/buckets_fail" "$tmp/bucket_ready_error" "$tmp/health_fail" \
    "$tmp/external_pause_on_list_call" "$tmp/list_members_count" \
    "$tmp/bump_xmin_on_snapshot_call" "$tmp/primary_snapshot_count" \
    "$tmp/inactivate_backup_on_list_call" "$tmp/backup_list_members_count"
}

run_controller() {
  local command="$1"
  if FAKE_DIR="$tmp" \
    FAILOVER_TEST_BACKEND="$backend" \
    FAILOVER_STATE_DIR="$tmp/state" \
    FAILOVER_RUNTIME_DIR="$tmp/run" \
    RECOVERY_CONFIRMATIONS=3 \
    FAILOVER_MIN_HOLD_SECONDS=180 \
    RECOVERY_CLEAN_SECONDS=120 \
    RECOVERY_RELAY_SUCCESSES=20 \
    ROUTE_UNAVAILABLE_WINDOW_SECONDS=15 \
    ROUTE_UNAVAILABLE_THRESHOLD=2 \
    ROUTE_UNAVAILABLE_SPARSE_THRESHOLD=3 \
    RELAY_AVAILABILITY_WINDOW_SECONDS=15 \
    RELAY_AVAILABILITY_DETECTION_SECONDS=60 \
    RELAY_AVAILABILITY_THRESHOLD=2 \
    TELEMETRY_FAILURE_CONFIRMATIONS=2 \
    SNAPSHOT_CONFIRMATIONS=1 \
    SNAPSHOT_TIMEOUT_SECONDS=2 \
    SNAPSHOT_POLL_SECONDS=1 \
    DRAIN_TIMEOUT_SECONDS=3 \
    DRAIN_POLL_SECONDS=1 \
    LOCK_WAIT_SECONDS=1 \
    BACKUP_OPEN_PARALLELISM=4 \
    SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS=5 \
    BACKUP_OPEN_BATCH_TIMEOUT_SECONDS=10 \
      bash "$controller" "$command" >>"$tmp/controller.log" 2>&1; then
    return 0
  else
    local rc=$?
    cat "$tmp/controller.log" >&2
    return "$rc"
  fi
}

age_recovery_state() {
  python3 - "$tmp/state/state.json" <<'PY'
import datetime as dt,json,os,sys,tempfile
path=sys.argv[1]
p=json.load(open(path,encoding='utf-8'))
old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=10)).isoformat()
p['takeover_started_at']=old
p['healthy_since']=old
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='aged-state.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    json.dump(p,f,ensure_ascii=False,sort_keys=True)
    f.write('\n')
os.replace(tmp,path)
PY
}

member_schedulable() {
  local id="$1"
  awk -F '|' -v id="$id" '$1==id {print $4}' "$tmp/members"
}

assert_eq() {
  local want="$1"
  local got="$2"
  local message="$3"
  if [[ "$want" != "$got" ]]; then
    printf 'FAIL: %s: want=%s got=%s\n' "$message" "$want" "$got" >&2
    exit 1
  fi
}

assert_no_forbidden_writes() {
  if grep -Eq '^set:(7845|7850):' "$tmp/events"; then
    printf 'FAIL: inactive/error account was modified\n' >&2
    cat "$tmp/events" >&2
    exit 1
  fi
}

bash -n "$controller" "$wrapper" "$0"
grep -Fq 'LoadCredential=sub2api_admin_key:/root/.sub2api_admin.key' "$service_unit"
grep -Fq 'ProtectHome=true' "$service_unit"
grep -Fq 'OnUnitInactiveSec=10s' "$timer_unit"
grep -Fq 'RandomizedDelaySec=0' "$timer_unit"
grep -Fq 'ROUTE_UNAVAILABLE_SPARSE_THRESHOLD=3' "$service_unit"
grep -Fq 'RELAY_AVAILABILITY_WINDOW_SECONDS=15' "$service_unit"
grep -Fq 'RELAY_AVAILABILITY_DETECTION_SECONDS=60' "$service_unit"
grep -Fq 'RELAY_AVAILABILITY_THRESHOLD=2' "$service_unit"
grep -Fq 'BACKUP_OPEN_PARALLELISM=4' "$service_unit"
grep -Fq 'SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS=5' "$service_unit"
grep -Fq 'BACKUP_OPEN_BATCH_TIMEOUT_SECONDS=120' "$service_unit"
grep -Fq 'redis-cli -e --raw' "$controller"
if ! grep -Fq "AND LOWER(route_source) <> 'probe'" "$controller" ||
   ! grep -Fq "AND LOWER(finals.route_source) <> 'probe'" "$controller"; then
  printf 'FAIL: probe routes are not excluded from both unavailable and recovery evidence\n' >&2
  exit 1
fi
grep -Fq 'latest_unavailable AS (' "$controller"
grep -Fq 'CROSS JOIN latest_unavailable latest' "$controller"
grep -Fq 'ROW_NUMBER() OVER (PARTITION BY logical_request_id ORDER BY created_at DESC, id DESC)' "$controller"
grep -Fq 'RELAY_UNAVAILABLE_NEW_BURST=true' "$controller"
grep -Fq 'availability_failures AS (' "$controller"
grep -Fq "AND upstream_account_type = 'openai_responses'" "$controller"
grep -Fq 'status_code IN (502, 503, 504)' "$controller"
grep -Fq "'cyber_policy', 'content_policy', 'content_filter', 'safety', 'policy_violation'" "$controller"
grep -Fq 'AND account_id > 0' "$controller"
grep -Fq "'rate_limited', 'rate_limited_5h', 'rate_limited_7d'" "$controller"
grep -Fq "'usage_limit', 'rate_limited_model', 'model_capacity'" "$controller"
grep -Fq 'status_code = 598' "$controller"
grep -Fq "IN ('transport', 'timeout')" "$controller"
grep -Fq 'COUNT(DISTINCT logical_request_id)' "$controller"
grep -Fq 'RELAY_AVAILABILITY_NEW_BURST=true' "$controller"
grep -Fq '(( RELAY_AVAILABILITY_120S == 0 )) || return 1' "$controller"
grep -Fq 'timeout --kill-after=2s 10s bash "$wrapper"' "$0"
for availability_setting in \
  RELAY_AVAILABILITY_WINDOW_SECONDS \
  RELAY_AVAILABILITY_DETECTION_SECONDS \
  RELAY_AVAILABILITY_THRESHOLD; do
  grep -Fq "\"${availability_setting}:\$${availability_setting}\"" "$controller"
  invalid_config_log="$tmp/invalid-${availability_setting}.log"
  set +e
  env "${availability_setting}=not-a-number" bash "$controller" status >"$invalid_config_log" 2>&1
  invalid_config_rc=$?
  set -e
  if (( invalid_config_rc == 0 )); then
    printf 'FAIL: invalid %s was accepted at bootstrap\n' "$availability_setting" >&2
    exit 1
  fi
  grep -Fq "${availability_setting}_must_be_positive_integer" "$invalid_config_log"
done

# Standby opening uses one dynamic inventory snapshot and submits a bounded
# parallel batch. A slow/failing first account must overlap a later healthy
# account instead of consuming the whole service deadline before it is tried.
reset_fixture
cat >>"$tmp/members" <<EOF
7694|$(encode_name standby-second-healthy)|active|f|t|t
EOF
printf '7694\n' >"$tmp/wait_for_open_peer_7693"
touch "$tmp/fail_open_7693"
rm -f "$tmp/state/state.json"
run_controller reconcile
test -e "$tmp/saw_open_peer_7693"
assert_eq f "$(member_schedulable 7693)" 'slow failing first standby remained paused'
assert_eq t "$(member_schedulable 7694)" 'later healthy standby opened in same batch'
assert_eq 'set:7694:true' "$(cat "$tmp/events")" 'only dynamic healthy standby was changed'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: parallel backup batch changed primary 7692\n' >&2
  exit 1
fi
assert_no_forbidden_writes

# The initial dynamic target set is revalidated before each parallel batch. An
# operator transition to inactive between discovery and submission is skipped;
# the later still-active dynamic account protects the group and no status write
# (or stale schedulable=true write) is issued for the inactive member.
reset_fixture
cat >>"$tmp/members" <<EOF
7694|$(encode_name standby-after-inactive)|active|f|t|t
EOF
printf '7693|2\n' >"$tmp/inactivate_backup_on_list_call"
rm -f "$tmp/state/state.json"
run_controller reconcile
assert_eq inactive "$(awk -F '|' '$1==7693 {print $3}' "$tmp/members")" 'operator-inactivated standby status preserved'
assert_eq f "$(member_schedulable 7693)" 'operator-inactivated standby was not enabled'
assert_eq t "$(member_schedulable 7694)" 'later active standby opened after revalidation'
assert_eq 'set:7694:true' "$(cat "$tmp/events")" 'revalidation skipped stale account and changed only healthy peer'
grep -Fq 'backup_became_ineligible_before_submit' "$tmp/controller.log"
assert_no_forbidden_writes
if grep -Eq 'status_code[[:space:]]*=[[:space:]]*500|status_code[[:space:]]+IN[[:space:]]*\([^)]*500' "$controller"; then
  printf 'FAIL: ordinary upstream 500 entered the terminal failover stream\n' >&2
  exit 1
fi
if grep -R -Fq '/root/reset-bridge-7692.sh' "$controller" "$wrapper" "$service_unit"; then
  printf 'FAIL: controller invokes legacy reset helper\n' >&2
  exit 1
fi
reconcile_source="$(sed -n '/^reconcile() {$/,/^}$/p' "$controller")"
if grep -Eq 'set_schedulable_guarded[[:space:]]+"?\$BRIDGE_ACCOUNT_ID|api_set_schedulable[[:space:]]+"?\$BRIDGE_ACCOUNT_ID' <<<"$reconcile_source"; then
  printf 'FAIL: automatic reconcile contains a primary write path\n' >&2
  exit 1
fi
if grep -Eqi 'recover-state|clear-error|method[[:space:]]*=[[:space:]]*PUT|UPDATE[[:space:]]+accounts' "$controller" "$wrapper"; then
  printf 'FAIL: forbidden account mutation path found\n' >&2
  exit 1
fi
if grep -Fq 'X-Api-Key: $key"' "$controller"; then
  printf 'FAIL: admin key is passed in process arguments\n' >&2
  exit 1
fi
grep -Fq 'trap cleanup_current_sensitive_files EXIT' "$controller"
grep -Fq 'cleanup_stale_sensitive_files' "$controller"

# safe-maintenance owns an independent lifecycle lock across prepare, the
# wrapped rebuild, and finish. A second manual deployment must be rejected.
fake_controller="$tmp/fake-controller.sh"
cat >"$fake_controller" <<'FAKE_CONTROLLER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$FAKE_CONTROLLER_LOG"
FAKE_CONTROLLER
chmod +x "$fake_controller"
install -d -m 0700 "$tmp/lifecycle-run"
: >"$tmp/fake-controller.log"
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-run" \
  timeout --kill-after=2s 10s bash "$wrapper" -- bash -c 'touch "$1"; sleep 3' _ "$tmp/wrapped-started" \
  >"$tmp/wrapper-1.log" 2>&1 &
wrapper_pid=$!
child_pids=("$wrapper_pid")
if ! wait_for_marker "$tmp/wrapped-started" "$wrapper_pid" 5; then
  printf 'FAIL: first safe-maintenance wrapper did not start within timeout\n' >&2
  exit 1
fi
set +e
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-run" \
  bash "$wrapper" -- true >"$tmp/wrapper-2.log" 2>&1
wrapper_rc=$?
set -e
if (( wrapper_rc == 0 )); then
  printf 'FAIL: concurrent safe-maintenance lifecycle was accepted\n' >&2
  exit 1
fi
if ! wait "$wrapper_pid"; then
  printf 'FAIL: first safe-maintenance wrapper timed out or failed\n' >&2
  exit 1
fi
child_pids=()
assert_eq $'prepare-maintenance\nfinish-maintenance' "$(cat "$tmp/fake-controller.log")" 'only one lifecycle reached controller'

# Reconcile/status may harmlessly skip a busy controller, but maintenance must
# fail non-zero instead of letting a wrapper rebuild without a prepared standby.
reset_fixture
printf 'stale-secret\n' >"$tmp/run/admin-header.stale"
(
  exec 8>"$tmp/run/controller.lock"
  flock 8
  touch "$tmp/lock-held"
  sleep 4
) &
lock_holder=$!
child_pids=("$lock_holder")
if ! wait_for_marker "$tmp/lock-held" "$lock_holder" 2; then
  printf 'FAIL: controller lock holder did not start within timeout\n' >&2
  exit 1
fi
run_controller reconcile
test -e "$tmp/run/admin-header.stale"
set +e
run_controller prepare-maintenance
lock_rc=$?
set -e
if (( lock_rc == 0 )); then
  printf 'FAIL: prepare-maintenance treated lock contention as success\n' >&2
  exit 1
fi
wait "$lock_holder"
child_pids=()
assert_eq '' "$(cat "$tmp/events")" 'lock contention caused no writes'
run_controller status
test ! -e "$tmp/run/admin-header.stale"

# Missing, malformed, or forward-incompatible controller state is never allowed
# to leave the primary as the only path. Reconcile opens active standby capacity
# without touching 7692 and atomically rebuilds a schema-v3 failover record.
for state_case in missing malformed incompatible; do
  reset_fixture
  case "$state_case" in
    missing) rm -f "$tmp/state/state.json" ;;
    malformed) printf '{broken\n' >"$tmp/state/state.json" ;;
    incompatible)
      cat >"$tmp/state/state.json" <<'JSON'
{"schema_version":99,"mode":"normal","healthy_streak":3}
JSON
      ;;
  esac
  run_controller reconcile
  assert_eq t "$(member_schedulable 7693)" "$state_case state opened standby"
  python3 - "$tmp/state/state.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['schema_version'] == 3
assert p['mode'] == 'failover'
assert p['proof_after']
PY
  if grep -q '^set:7692:' "$tmp/events"; then
    printf 'FAIL: state fail-open changed primary 7692\n' >&2
    exit 1
  fi
done

# A fail-open rebuild must not report success when its atomic state replacement
# fails. Standby intent remains availability-safe, but the controller exits
# non-zero so systemd and operators can see that durable control evidence was
# not restored.
reset_fixture
rm -f "$tmp/state/state.json"
mkdir "$tmp/state/state.json"
set +e
run_controller reconcile
state_write_rc=$?
set -e
if (( state_write_rc == 0 )); then
  printf 'FAIL: failed state rebuild was reported as success\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'state write failure still requested standby capacity'
if grep -q 'standbys_open_state_rebuilt' "$tmp/controller.log"; then
  printf 'FAIL: failed state rebuild emitted a success event\n' >&2
  exit 1
fi

# Losing only the 7692 group association is itself a failover signal, not a
# reason to discard the otherwise trustworthy standby inventory. Automatic
# reconcile opens active standbys, while planned maintenance fails after that
# protection is ready and never attempts a primary write.
reset_fixture
sed -i '/^7692|/d' "$tmp/members"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'missing primary group membership opened standby'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: reconcile wrote missing primary 7692\n' >&2
  exit 1
fi

reset_fixture
sed -i '/^7692|/d' "$tmp/members"
set +e
run_controller prepare-maintenance
missing_primary_maintenance_rc=$?
set -e
if (( missing_primary_maintenance_rc == 0 )); then
  printf 'FAIL: maintenance accepted missing primary group membership\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'missing-primary maintenance opened standby first'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: missing-primary maintenance attempted a 7692 write\n' >&2
  exit 1
fi

# Guardian degradation alone does not trigger failover. Healthy recovery closes
# the active standby only after the minimum hold/clean windows, direct Relay
# success proof and three complete healthy samples.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
printf 'ok|10|3|3|3|7|300|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'standby remains through healthy sample 1'
age_recovery_state
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'standby remains through healthy sample 2'
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'standby closes after proof windows plus 3 healthy samples'
assert_no_forbidden_writes

# A health flip immediately after the last standby is paused must reopen it and
# return non-zero so callers cannot treat the close as stable.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
touch "$tmp/flip_after_close"
run_controller reconcile
age_recovery_state
run_controller reconcile
set +e
run_controller reconcile
flip_rc=$?
set -e
if (( flip_rc == 0 )); then
  printf 'FAIL: post-close health flip was treated as success\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'post-close health flip reopened standby'
assert_eq $'set:7693:false\nset:7693:true' "$(tail -n 2 "$tmp/events")" 'post-close flip close/reopen order'

# With multiple standbys, a condition flip between account writes must restore
# the already-paused prefix immediately rather than waiting for the next timer.
reset_fixture
printf '7694|%s|active|t|t|t\n' "$(encode_name standby-active-2)" >>"$tmp/members"
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
age_recovery_state
run_controller reconcile
touch "$tmp/flip_after_close"
set +e
run_controller reconcile
mid_close_rc=$?
set -e
if (( mid_close_rc == 0 )); then
  printf 'FAIL: mid-close health flip was treated as success\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'mid-close flip restored first standby'
assert_eq t "$(member_schedulable 7694)" 'mid-close flip kept second standby open'
assert_eq $'set:7693:false\nset:7693:true' "$(tail -n 2 "$tmp/events")" 'mid-close partial prefix restored immediately'

# The complete recovery proof, not only the immediate health condition, is
# re-read after the final standby write. One new terminal failure must reopen it
# even though the short failover threshold still requires two.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
age_recovery_state
run_controller reconcile
touch "$tmp/unavailable_after_close"
set +e
run_controller reconcile
unavailable_close_rc=$?
set -e
if (( unavailable_close_rc == 0 )); then
  printf 'FAIL: post-close terminal failure was treated as recovered\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'post-close terminal failure reopened standby'
assert_eq $'set:7693:false\nset:7693:true' "$(tail -n 2 "$tmp/events")" 'post-close terminal failure close/reopen order'

# Likewise, one remaining normal Relay entrance is usable for live traffic but
# insufficient proof to remove the sub2 safety net when three are enabled.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
age_recovery_state
run_controller reconcile
touch "$tmp/normal_drop_after_close"
set +e
run_controller reconcile
normal_drop_rc=$?
set -e
if (( normal_drop_rc == 0 )); then
  printf 'FAIL: post-close normal-capacity drop was treated as recovered\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'post-close normal-capacity drop reopened standby'

# Database runtime readiness is mandatory before closing a standby.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|t|t/7692|\1|active|t|t|f/' "$tmp/members"
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
run_controller reconcile
run_controller reconcile
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'runtime-blocked primary keeps standby open'

# A healthy-looking primary without successful post-failover traffic proof also
# keeps the standby open.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
touch "$tmp/proof_fail"
run_controller reconcile
run_controller reconcile
run_controller reconcile
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'missing primary success proof keeps standby open'

# An already-unschedulable primary opens standby but automatic reconcile never
# writes primary account 7692.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|/7692|\1|active|f|/' "$tmp/members"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'primary unschedulable opens standby'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: reconcile modified primary\n' >&2
  exit 1
fi
assert_no_forbidden_writes

# Relay zero opens standby immediately; a single account Guardian degradation
# did not, as covered above.
reset_fixture
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'relay zero opens standby'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: relay failure reconcile modified primary\n' >&2
  exit 1
fi

# A completely unreachable or unparsable /health response is a direct service
# availability signal. It must open standby capacity on the first pass; only
# the auxiliary canonical-outcome query receives a one-pass debounce.
reset_fixture
touch "$tmp/health_fail"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'health endpoint failure opened standby immediately'

# Effective capacity can momentarily reach zero while a bounded cohort drains.
# One zero sample is pending, but two consecutive 10-second samples open the
# sub2 safety net.
reset_fixture
printf 'ok|10|3|3|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'first effective-slot zero sample was debounced'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'second effective-slot zero sample opened standby'

# One zero-slot sample resets the recovery clock. A single later positive slot
# cannot immediately close the already-open standby.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
age_recovery_state
run_controller reconcile
printf 'ok|10|3|3|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
printf 'ok|10|3|3|3|7|300|0|0|0|0|ok\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'one recovered slot did not close standby'

# Recovery requires the entire Relay pool to leave suspect/recovery/open and
# last-resort states. Each counter independently blocks the third close sample.
for degraded_health in \
  'ok|10|3|3|3|7|300|1|0|0|0|degraded' \
  'ok|10|3|3|3|7|300|0|1|0|0|degraded' \
  'ok|10|3|3|3|7|300|0|0|1|0|degraded' \
  'ok|10|3|3|3|7|300|0|0|0|1|degraded'; do
  reset_fixture
  sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
  run_controller reconcile
  age_recovery_state
  run_controller reconcile
  printf '%s\n' "$degraded_health" >"$tmp/health"
  run_controller reconcile
  assert_eq t "$(member_schedulable 7693)" 'non-normal Relay state kept standby open'
done

# Opening standbys is best-effort across the whole active pool. A failed first
# admin write must not prevent a later healthy standby from protecting traffic.
reset_fixture
printf '7694|%s|active|f|t|t\n' "$(encode_name standby-active-2)" >>"$tmp/members"
touch "$tmp/fail_open_7693"
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'failed first standby remained unchanged'
assert_eq t "$(member_schedulable 7694)" 'later healthy standby opened after first write failure'
assert_eq 'set:7694:true' "$(cat "$tmp/events")" 'healthy standby write was still attempted'

# Runtime-ready standbys are submitted first. A cooldown-only active account is
# still requested best-effort, but cannot delay proof from the healthy account.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|t|t/7693|\1|active|f|t|f/' "$tmp/members"
printf '7694|%s|active|f|t|t\n' "$(encode_name standby-active-2)" >>"$tmp/members"
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7694)" 'runtime-ready standby opened'
assert_eq t "$(member_schedulable 7693)" 'cooldown standby schedulable intent was also requested'
assert_eq 'set:7694:true' "$(sed -n '1p' "$tmp/events")" 'runtime-ready standby was prioritized'

# A known zero-capacity health response outranks an auxiliary evidence-query
# failure and opens standby capacity on the first controller pass.
reset_fixture
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
touch "$tmp/relay_evidence_fail"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'known relay zero is not hidden by evidence telemetry failure'

# A single final unavailable request is not enough to fan traffic out to the
# paid standby pool. Two distinct canonical finals inside the 15 second window
# are direct user-visible evidence and open standbys immediately.
reset_fixture
printf '1|1|101|2026-07-13T16:36:28.000000+08:00|100\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'single terminal unavailable did not open standby'
printf '2|2|102|2026-07-13T16:36:29.000000+08:00|100\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'two terminal unavailable requests opened standby'

# The unified terminal stream protects against an upstream front that still
# has nominal local capacity but is returning real terminal failures. One
# canonical 502 is deliberately insufficient; a second distinct logical
# request in the 15-second cohort opens the standby and records its own
# independent timestamp-plus-ID watermark.
reset_fixture
printf '0|0|0||100|1|1|201|2026-07-13T16:38:28.000000+08:00\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'single canonical upstream 502 did not open standby'
assert_eq 201 "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["last_availability_id"])' "$tmp/state/state.json")" 'single terminal failure advanced availability watermark'
printf '0|0|0||100|2|2|202|2026-07-13T16:38:29.000000+08:00\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'two canonical terminal failures opened standby'
assert_eq relay_user_visible_availability_failure "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["last_reason"])' "$tmp/state/state.json")" 'terminal stream recorded the failover reason'

# The two-event cohort is unified, so one upstream 502 plus one exact
# relay_route_unavailable final is actionable even though neither individual
# subtype reaches its own two-event threshold.
reset_fixture
printf '1|1|301|2026-07-13T16:39:28.000000+08:00|100|2|2|302|2026-07-13T16:39:29.000000+08:00\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'mixed 502 and unavailable cohort opened standby'
assert_eq relay_user_visible_availability_failure "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["last_reason"])' "$tmp/state/state.json")" 'mixed cohort used unified terminal trigger'

# Only exact relay_route_unavailable retains the sparse 3-in-120-second
# trigger. Three generic terminal failures outside the 15-second cohort are
# recovery evidence, but cannot start a new takeover.
reset_fixture
printf '0|0|0||100|0|3|401|2026-07-13T16:40:29.000000+08:00\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'sparse generic terminal failures did not trigger takeover'

# Transition/rollback rows may carry a policy kind with a stale 503 status.
# The SQL classifier excludes those rows before aggregation, so even two such
# finals produce no terminal cohort and cannot open paid standby capacity.
reset_fixture
printf '0|0|0||100|0|0|0|\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'two legacy policy 503 finals did not trigger takeover'

# Any supported terminal failure blocks recovery for the full clean window,
# even when it was a single event and therefore never triggered failover by
# itself. Once the window is clean, the existing hold and three-proof
# hysteresis can close the standby normally.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
printf '0|0|0||100|0|1|501|2026-07-13T16:41:29.000000+08:00\n' >"$tmp/relay_evidence"
run_controller reconcile
age_recovery_state
run_controller reconcile
run_controller reconcile
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'single terminal failure held standby through recovery window'
printf '0|0|0||100|0|0|501|2026-07-13T16:41:29.000000+08:00\n' >"$tmp/relay_evidence"
age_recovery_state
run_controller reconcile
run_controller reconcile
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'clean terminal window allowed proven standby recovery'

# Sparse but sustained user-visible exhaustion is also actionable. Three final
# failures inside 120 seconds trigger even when only one belongs to the newest
# 15-second cohort.
reset_fixture
printf '1|3|103|2026-07-13T16:37:29.000000+08:00|100\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'three sparse terminal failures opened standby'

# A persisted latest-ID watermark prevents an old two-request burst from
# reopening standbys forever after its clean/recovery windows have elapsed.
reset_fixture
cat >"$tmp/state/state.json" <<'JSON'
{"schema_version":2,"mode":"normal","healthy_streak":3,"last_reason":"healthy","proof_after":null,"last_unavailable_id":102,"last_unavailable_at":"2026-07-13T16:36:29+08:00","telemetry_error_streak":0}
JSON
printf '2|0|102|2026-07-13T16:36:29.000000+08:00|100\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'already-seen terminal burst did not retrigger failover'

# A database restore can move the sequence backwards. The timestamp-plus-ID
# watermark still recognizes a chronologically newer final with a smaller ID.
reset_fixture
cat >"$tmp/state/state.json" <<'JSON'
{"schema_version":3,"mode":"normal","healthy_streak":3,"last_reason":"healthy","proof_after":null,"last_unavailable_id":500,"last_unavailable_at":"2026-07-13T16:36:29+08:00","telemetry_error_streak":0,"effective_zero_streak":0}
JSON
printf '2|2|5|2026-07-13T16:37:29.000000+08:00|100\n' >"$tmp/relay_evidence"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'newer event after sequence rollback opened standby'

# Schema v1 state remains readable and is atomically upgraded on the next
# successful reconciliation.
reset_fixture
cat >"$tmp/state/state.json" <<'JSON'
{"schema_version":1,"mode":"normal","healthy_streak":3,"last_reason":"healthy","proof_after":null}
JSON
run_controller reconcile
assert_eq 3 "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"])' "$tmp/state/state.json")" 'v1 state upgraded to v3'

# Legacy half-open/probation capacity may still expose a bounded proving slot,
# but health.normal_schedulable=0 must open sub2 standby capacity.
reset_fixture
printf 'ok|10|1|0|3|7|1|0|1|0|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'recovery-only Relay did not masquerade as normal capacity'

# Telemetry blindness is debounced once, then fails toward availability. An
# unknown sample can never be used as recovery evidence to close a standby.
reset_fixture
touch "$tmp/relay_evidence_fail"
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'first telemetry failure was debounced'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'second telemetry failure opened standby'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'unknown telemetry never closed standby'

# Direct Relay success proof is independently required before recovery.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
printf '0|0|0||19\n' >"$tmp/relay_evidence"
run_controller reconcile
age_recovery_state
run_controller reconcile
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'insufficient direct Relay successes kept standby open'

# Redis scheduler evidence is three-state. An enumeration/read error is never
# equivalent to an empty bucket or an absent account, so maintenance cannot
# pause 7692 on partial control-plane evidence.
reset_fixture
touch "$tmp/buckets_fail"
set +e
run_controller prepare-maintenance
redis_buckets_rc=$?
set -e
if (( redis_buckets_rc == 0 )); then
  printf 'FAIL: maintenance accepted failed Redis bucket enumeration\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7692)" 'bucket enumeration error left primary schedulable'

reset_fixture
touch "$tmp/bucket_error_7693"
set +e
run_controller prepare-maintenance
redis_contains_rc=$?
set -e
if (( redis_contains_rc == 0 )); then
  printf 'FAIL: maintenance accepted failed Redis membership read\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7692)" 'backup membership error left primary schedulable'

# A Redis error while proving 7692 absent must not be mistaken for a successful
# exclusion. The write may already have paused 7692, but the rebuild is blocked
# and standby capacity remains open.
reset_fixture
touch "$tmp/bucket_error_7692"
set +e
run_controller prepare-maintenance
redis_exclude_rc=$?
set -e
if (( redis_exclude_rc == 0 )); then
  printf 'FAIL: maintenance treated failed exclusion read as account absence\n' >&2
  exit 1
fi
assert_eq f "$(member_schedulable 7692)" 'ambiguous exclusion aborted after conservative primary pause'
assert_eq t "$(member_schedulable 7693)" 'ambiguous exclusion kept standby open'

# Planned maintenance proves standby readiness before pausing primary. Finish
# restores only the primary that this maintenance command paused.
reset_fixture
run_controller prepare-maintenance
assert_eq t "$(member_schedulable 7693)" 'maintenance opened standby'
assert_eq f "$(member_schedulable 7692)" 'maintenance paused primary'
first_set="$(sed -n '1p' "$tmp/events")"
second_set="$(sed -n '2p' "$tmp/events")"
assert_eq 'set:7693:true' "$first_set" 'standby opens first'
assert_eq 'set:7692:false' "$second_set" 'primary pauses second'
test -s "$tmp/state/maintenance.json"
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['schema_version'] == 2
assert p['primary_disabled_by_maintenance'] is True
assert p['primary_row_version'] == '101'
assert p.get('pending_primary_row_version') is None
PY
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'maintenance restored primary'
assert_eq t "$(member_schedulable 7693)" 'standby held during recovery confirmation'
test ! -e "$tmp/state/maintenance.json"
run_controller reconcile
age_recovery_state
run_controller reconcile
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'standby closes after recovery hysteresis'
assert_no_forbidden_writes

# Ownership is granted only when this controller actually issued the primary
# pause. Simulate sub2 pausing 7692 between prepare's outer inventory read and
# the guarded write's fresh read: maintenance remains safe, but finish must not
# claim or restore that externally paused account.
reset_fixture
printf '6\n' >"$tmp/external_pause_on_list_call"
run_controller prepare-maintenance
assert_eq f "$(member_schedulable 7692)" 'external race paused primary'
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['primary_disabled_by_maintenance'] is False
assert p.get('primary_row_version') is None
assert p.get('pending_primary_row_version') is None
PY
if grep -q '^set:7692:false' "$tmp/events"; then
  printf 'FAIL: prepare claimed an externally paused primary write\n' >&2
  exit 1
fi
run_controller finish-maintenance
assert_eq f "$(member_schedulable 7692)" 'finish did not restore externally paused primary'
if grep -q '^set:7692:true' "$tmp/events"; then
  printf 'FAIL: finish restored a primary not paused by maintenance\n' >&2
  exit 1
fi

# If the same external-pause race also leaves Redis exclusion evidence
# unreadable, prepare fails closed instead of submitting an idempotent pause and
# falsely converting the external state into controller ownership.
reset_fixture
printf '6\n' >"$tmp/external_pause_on_list_call"
touch "$tmp/bucket_error_7692"
set +e
run_controller prepare-maintenance
external_pause_ambiguous_rc=$?
set -e
if (( external_pause_ambiguous_rc == 0 )); then
  printf 'FAIL: ambiguous external pause was accepted as maintenance-owned\n' >&2
  exit 1
fi
assert_eq f "$(member_schedulable 7692)" 'ambiguous external pause remained unchanged'
assert_eq t "$(member_schedulable 7693)" 'ambiguous external pause kept standby open'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: ambiguous external pause caused a 7692 write\n' >&2
  exit 1
fi

# Finish checks the owned xmin once for the operator-facing ownership error and
# again immediately before the admin write. A mutation inside that former
# validation gap must keep the marker and standby open without restoring 7692.
reset_fixture
run_controller prepare-maintenance
rm -f "$tmp/primary_snapshot_count"
printf '2\n' >"$tmp/bump_xmin_on_snapshot_call"
set +e
run_controller finish-maintenance
late_xmin_finish_rc=$?
set -e
if (( late_xmin_finish_rc == 0 )); then
  printf 'FAIL: finish ignored a mutation between ownership check and restore\n' >&2
  exit 1
fi
assert_eq f "$(member_schedulable 7692)" 'late xmin mutation was not overwritten'
assert_eq t "$(member_schedulable 7693)" 'late xmin mutation kept standby open'
test -e "$tmp/state/maintenance.json"
if grep -q '^set:7692:true' "$tmp/events"; then
  printf 'FAIL: late xmin mutation was followed by a restore write\n' >&2
  exit 1
fi

# xmin fences maintenance ownership. Any external/sub2 account mutation after
# our confirmed drain invalidates ownership, so finish leaves 7692 untouched
# and keeps the standby plus marker for explicit operator resolution.
reset_fixture
run_controller prepare-maintenance
python3 - "$tmp/primary_xmin" <<'PY'
import sys
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
open(path,'w',encoding='utf-8').write(str(value)+'\n')
PY
set +e
run_controller finish-maintenance
xmin_finish_rc=$?
set -e
if (( xmin_finish_rc == 0 )); then
  printf 'FAIL: finish overrode a newer primary row version\n' >&2
  exit 1
fi
assert_eq f "$(member_schedulable 7692)" 'external primary mutation was not overwritten'
assert_eq t "$(member_schedulable 7693)" 'external primary mutation kept standby open'
test -e "$tmp/state/maintenance.json"
if grep -q '^set:7692:true' "$tmp/events"; then
  printf 'FAIL: external primary mutation was followed by a restore write\n' >&2
  exit 1
fi

# A durable maintenance marker outranks a damaged state file. Reconcile opens
# standby capacity first and atomically replaces state.json with schema v3.
reset_fixture
cat >"$tmp/state/maintenance.json" <<'JSON'
{"schema_version":2,"reason":"planned_codex2api_maintenance","primary_disabled_by_maintenance":false,"primary_row_version":null,"pending_primary_row_version":null}
JSON
printf '{broken\n' >"$tmp/state/state.json"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'corrupt state with maintenance marker opened standby'
python3 - "$tmp/state/state.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['schema_version'] == 3
assert p['mode'] == 'maintenance'
PY
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: state repair changed primary 7692\n' >&2
  exit 1
fi

# Continuous account_last_used outbox traffic is unrelated to schedulability
# and must not prevent the account_changed event from being considered drained.
reset_fixture
touch "$tmp/traffic_outbox"
run_controller prepare-maintenance
assert_eq f "$(member_schedulable 7692)" 'last-used traffic does not block maintenance preparation'
run_controller finish-maintenance

# If the only standby becomes inactive during maintenance, finish must still
# restore a maintenance-owned healthy primary and must not touch that inactive
# standby.
reset_fixture
run_controller prepare-maintenance
events_before="$(wc -l <"$tmp/events")"
sed -i 's/7693|\([^|]*\)|active|t|t|t/7693|\1|inactive|f|t|f/' "$tmp/members"
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'inactive standby does not block owned primary restore'
events_after="$(wc -l <"$tmp/events")"
assert_eq "$((events_before + 1))" "$events_after" 'finish only restored primary after standby became inactive'
assert_no_forbidden_writes

# A drain timeout records only a pending xmin, never ownership. A later prepare
# may promote that unchanged row version after drain and then finish can restore.
reset_fixture
touch "$tmp/primary_busy"
set +e
run_controller prepare-maintenance
drain_rc=$?
set -e
if (( drain_rc == 0 )); then
  printf 'FAIL: busy primary unexpectedly drained\n' >&2
  exit 1
fi
assert_eq f "$(member_schedulable 7692)" 'failed prepare already paused primary'
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['primary_disabled_by_maintenance'] is False
assert p['primary_row_version'] is None
assert p['pending_primary_row_version'] == '101'
PY
rm -f "$tmp/primary_busy"
python3 - "$tmp/primary_xmin" <<'PY'
import sys
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
open(path,'w',encoding='utf-8').write(str(value)+'\n')
PY
run_controller prepare-maintenance
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['primary_disabled_by_maintenance'] is True
assert p['primary_row_version'] == '102'
assert p.get('pending_primary_row_version') is None
PY
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'prepare retry preserved ownership for finish restore'

# Service recovery is enough to restore a maintenance-owned primary. Relay zero
# keeps standby open after the marker is removed.
reset_fixture
run_controller prepare-maintenance
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'service health restores maintenance primary'
assert_eq t "$(member_schedulable 7693)" 'relay zero holds standby'
test ! -e "$tmp/state/maintenance.json"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'relay zero continues standby takeover'

# Snapshot confirmation failure must never pause primary.
reset_fixture
touch "$tmp/snapshot_fail"
set +e
run_controller prepare-maintenance
rc=$?
set -e
if (( rc == 0 )); then
  printf 'FAIL: maintenance succeeded without scheduler snapshot proof\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7692)" 'snapshot failure leaves primary untouched'
if grep -q '^set:7692:false' "$tmp/events"; then
  printf 'FAIL: primary paused before snapshot proof\n' >&2
  exit 1
fi

# Ambiguous active group discovery performs zero writes.
reset_fixture
printf '%s\n' '12|codex-pro|active' '99|codex-pro|active' >"$tmp/group"
set +e
run_controller reconcile
rc=$?
set -e
if (( rc == 0 )); then
  printf 'FAIL: ambiguous group discovery succeeded\n' >&2
  exit 1
fi
assert_eq '' "$(cat "$tmp/events")" 'ambiguous group caused no writes'

python3 - "$tmp/controller.log" <<'PY'
import json,sys
for number,line in enumerate(open(sys.argv[1],encoding='utf-8'),1):
    line=line.strip()
    if line.startswith('{'):
        try:
            json.loads(line)
        except Exception as exc:
            raise SystemExit(f'invalid controller event JSON at line {number}: {exc}')
PY

printf 'sub2 codex-pro failover selftest: PASS\n'
