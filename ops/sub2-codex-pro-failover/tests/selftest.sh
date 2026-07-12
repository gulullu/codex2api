#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
controller="$root/sub2-codex-pro-failover.sh"
wrapper="$root/safe-maintenance.sh"
service_unit="$root/systemd/codex2api-sub2-codex-pro-failover.service"
timer_unit="$root/systemd/codex2api-sub2-codex-pro-failover.timer"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

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
    cat "$FAKE_DIR/members"
    ;;
  outbox-count)
    [[ "${2:-}" == account_changed ]] || exit 1
    printf '0\n'
    ;;
  buckets)
    printf '%s\n' '12:openai:forced' '12:openai:single'
    ;;
  bucket-ready)
    [[ ! -e "$FAKE_DIR/snapshot_not_ready" ]]
    ;;
  bucket-contains)
    [[ ! -e "$FAKE_DIR/snapshot_fail" ]] || exit 1
    id="$3"
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
          'OverloadUntil':None,
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
    if [[ "$id" == 7692 && "$desired" == false ]]; then
      python3 - "$FAILOVER_STATE_DIR/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
if not p.get('primary_disabled_by_maintenance'):
    raise SystemExit('primary ownership intent was not durable before disable')
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
    if [[ "$id" != 7692 && "$desired" == false && -e "$FAKE_DIR/flip_after_close" ]]; then
      printf 'error|0|0|critical\n' >"$FAKE_DIR/health"
    fi
    ;;
  get-account)
    id="$1"
    concurrency=0
    [[ "$id" == 7692 && -e "$FAKE_DIR/primary_busy" ]] && concurrency=1
    awk -F '|' -v id="$id" -v concurrency="$concurrency" '$1==id {printf "%s|%s|%s|%s\n",$3,($4=="t"?"true":"false"),concurrency,($5=="t"?"true":"false"); found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;
  health)
    cat "$FAKE_DIR/health"
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
  : >"$tmp/events"
  : >"$tmp/controller.log"
  printf '12|codex-pro|active\n' >"$tmp/group"
  cat >"$tmp/members" <<EOF
7692|$(encode_name codex2api-pro)|active|t|t|t
7693|$(encode_name standby-active)|active|f|t|t
7845|$(encode_name standby-inactive)|inactive|f|t|f
7850|$(encode_name standby-error)|error|f|t|f
EOF
  printf 'ok|10|3|ok\n' >"$tmp/health"
  rm -f "$tmp/snapshot_fail" "$tmp/snapshot_not_ready" "$tmp/proof_fail" \
    "$tmp/primary_busy" "$tmp/traffic_outbox" "$tmp/lock-held" \
    "$tmp/flip_after_close" "$tmp/wrapped-started"
}

run_controller() {
  local command="$1"
  if FAKE_DIR="$tmp" \
    FAILOVER_TEST_BACKEND="$backend" \
    FAILOVER_STATE_DIR="$tmp/state" \
    FAILOVER_RUNTIME_DIR="$tmp/run" \
    RECOVERY_CONFIRMATIONS=3 \
    SNAPSHOT_CONFIRMATIONS=1 \
    SNAPSHOT_TIMEOUT_SECONDS=2 \
    SNAPSHOT_POLL_SECONDS=1 \
    DRAIN_TIMEOUT_SECONDS=3 \
    DRAIN_POLL_SECONDS=1 \
    LOCK_WAIT_SECONDS=1 \
      bash "$controller" "$command" >>"$tmp/controller.log" 2>&1; then
    return 0
  else
    local rc=$?
    cat "$tmp/controller.log" >&2
    return "$rc"
  fi
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
grep -Fq 'OnUnitInactiveSec=30s' "$timer_unit"
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
  bash "$wrapper" -- bash -c 'touch "$1"; sleep 3' _ "$tmp/wrapped-started" \
  >"$tmp/wrapper-1.log" 2>&1 &
wrapper_pid=$!
while [[ ! -e "$tmp/wrapped-started" ]]; do sleep 0.05; done
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
wait "$wrapper_pid"
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
while [[ ! -e "$tmp/lock-held" ]]; do sleep 0.05; done
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
assert_eq '' "$(cat "$tmp/events")" 'lock contention caused no writes'
run_controller status
test ! -e "$tmp/run/admin-header.stale"

# Guardian degradation alone does not trigger failover. Healthy recovery closes
# the active standby only after one proof-watermark run plus three complete
# healthy samples.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
printf 'ok|10|3|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'standby remains through healthy sample 1'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'standby remains through healthy sample 2'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'standby remains through healthy sample 3'
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'standby closes after proof anchor plus 3 healthy samples'
assert_no_forbidden_writes

# A health flip immediately after the last standby is paused must reopen it and
# return non-zero so callers cannot treat the close as stable.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
touch "$tmp/flip_after_close"
run_controller reconcile
run_controller reconcile
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
printf 'ok|10|0|degraded\n' >"$tmp/health"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'relay zero opens standby'
if grep -q '^set:7692:' "$tmp/events"; then
  printf 'FAIL: relay failure reconcile modified primary\n' >&2
  exit 1
fi

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
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'maintenance restored primary'
assert_eq t "$(member_schedulable 7693)" 'standby held during recovery confirmation'
test ! -e "$tmp/state/maintenance.json"
run_controller reconcile
run_controller reconcile
run_controller reconcile
assert_eq f "$(member_schedulable 7693)" 'standby closes after recovery hysteresis'
assert_no_forbidden_writes

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

# Ownership intent is monotonic. A drain timeout after primary disable, followed
# by prepare retry, must keep ownership=true so finish still restores primary.
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
assert json.load(open(sys.argv[1],encoding='utf-8'))['primary_disabled_by_maintenance'] is True
PY
rm -f "$tmp/primary_busy"
run_controller prepare-maintenance
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'prepare retry preserved ownership for finish restore'

# Service recovery is enough to restore a maintenance-owned primary. Relay zero
# keeps standby open after the marker is removed.
reset_fixture
run_controller prepare-maintenance
printf 'ok|10|0|degraded\n' >"$tmp/health"
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

printf 'sub2 codex-pro failover selftest: PASS\n'
