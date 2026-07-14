#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
controller="$root/sub2-codex-pro-failover.sh"
wrapper="$root/safe-maintenance.sh"
service_unit="$root/systemd/codex2api-sub2-codex-pro-failover.service"
timer_unit="$root/systemd/codex2api-sub2-codex-pro-failover.timer"
env_example="$root/systemd/codex2api-sub2-codex-pro-failover.env.example"
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

wait_for_phase() {
  local path="$1"
  local phase="$2"
  local pid="$3"
  local timeout_seconds="$4"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if [[ -s "$path" ]] && python3 - "$path" "$phase" <<'PY'
import json,sys
try:
    raise SystemExit(0 if json.load(open(sys.argv[1],encoding='utf-8')).get('phase') == sys.argv[2] else 1)
except Exception:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.05
  done
  return 1
}

backend="$tmp/backend.sh"
cat >"$backend" <<'BACKEND'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"
shift || true
bridge_id="${FAKE_BRIDGE_ID:-7692}"

current_generation() {
  local id="$1"
  cat "$FAKE_DIR/meta_generation_$id"
}

next_generation() {
  local id="$1"
  local value
  value="$(<"$FAKE_DIR/generation_counter")"
  value=$((value + 1))
  printf '%s\n' "$value" >"$FAKE_DIR/generation_counter"
  local generation
  generation="$(printf '2026-07-14T00:00:00.%06dZ' "$value")"
  printf '%s\n' "$generation" >"$FAKE_DIR/meta_generation_$id"
  printf '%s\n' "$generation"
}

append_access_log() {
  local request_id="$1"
  local status="$2"
  local path="$3"
  local method="${4:-POST}"
  local primary_receipt=false
  [[ "$method" == POST && "$path" == "/api/v1/admin/accounts/$bridge_id/schedulable" ]] && primary_receipt=true
  if [[ "$primary_receipt" == true && -e "$FAKE_DIR/omit_next_receipt_clean" ]]; then
    rm -f "$FAKE_DIR/omit_next_receipt_clean"
    return 0
  fi
  if [[ "$primary_receipt" == true && -e "$FAKE_DIR/drop_next_receipt" ]]; then
    rm -f "$FAKE_DIR/drop_next_receipt"
    printf '%s\n' "$(( $(<"$FAKE_DIR/sink_dropped") + 1 ))" >"$FAKE_DIR/sink_dropped"
    return 0
  fi
  if [[ "$primary_receipt" == true && -e "$FAKE_DIR/fail_next_receipt" ]]; then
    rm -f "$FAKE_DIR/fail_next_receipt"
    printf '%s\n' "$(( $(<"$FAKE_DIR/sink_failed") + 1 ))" >"$FAKE_DIR/sink_failed"
    return 0
  fi
  local copies=1
  if [[ "$primary_receipt" == true && -e "$FAKE_DIR/duplicate_next_receipt" ]]; then
    rm -f "$FAKE_DIR/duplicate_next_receipt"
    copies=2
  fi
  local i id
  for ((i=0; i<copies; i++)); do
    id=$(( $(<"$FAKE_DIR/log_counter") + 1 ))
    printf '%s\n' "$id" >"$FAKE_DIR/log_counter"
    printf '%s|%s|%s|%s|%s|http.access|http request completed\n' \
      "$id" "$request_id" "$status" "$path" "$method" >>"$FAKE_DIR/access_logs"
    printf '%s\n' "$(( $(<"$FAKE_DIR/sink_written") + 1 ))" >"$FAKE_DIR/sink_written"
  done
}

close_first_active_backup() {
  local backup_id
  backup_id="$(awk -F '|' -v bridge="$bridge_id" \
    '$1!=bridge && $3=="active" && $5=="t" {print $1; exit}' "$FAKE_DIR/members")"
  [[ -n "$backup_id" ]] || return 0
  FAKE_DIR="$FAKE_DIR" FAKE_BRIDGE_ID="$bridge_id" \
    "$0" set-schedulable "$backup_id" false >/dev/null
  append_access_log "external-backup-close-$(date +%s%N)" 200 \
    "/api/v1/admin/accounts/$backup_id/schedulable" POST
}

case "$cmd" in
  discover-group)
    discover_group_count=0
    [[ ! -s "$FAKE_DIR/discover_group_count" ]] || discover_group_count="$(<"$FAKE_DIR/discover_group_count")"
    discover_group_count=$((discover_group_count + 1))
    printf '%s\n' "$discover_group_count" >"$FAKE_DIR/discover_group_count"
    if [[ -e "$FAKE_DIR/fail_group_once_after_primary_paused" ]] &&
       [[ -e "$FAKE_DIR/primary_paused_get_seen" ]] &&
       awk -F '|' -v id="$bridge_id" '$1==id && $4=="f" {found=1} END {exit !found}' "$FAKE_DIR/members"; then
      rm -f "$FAKE_DIR/fail_group_once_after_primary_paused"
      touch "$FAKE_DIR/drain_group_fault_seen"
      exit 75
    fi
    if [[ -s "$FAKE_DIR/fail_group_on_discover_call" &&
          "$discover_group_count" == "$(<"$FAKE_DIR/fail_group_on_discover_call")" ]]; then
      rm -f "$FAKE_DIR/fail_group_on_discover_call"
      exit 75
    fi
    if [[ -s "$FAKE_DIR/flip_group_on_discover_call" ]]; then
      IFS='|' read -r flip_call replacement_id <"$FAKE_DIR/flip_group_on_discover_call"
      if [[ "$discover_group_count" == "$flip_call" ]]; then
        printf '%s|codex-pro|active\n' "$replacement_id" >"$FAKE_DIR/group"
        rm -f "$FAKE_DIR/flip_group_on_discover_call"
      fi
    fi
    cat "$FAKE_DIR/group"
    ;;
  list-members)
    if [[ -e "$FAKE_DIR/fail_list_once_after_primary_paused" ]] &&
       [[ -e "$FAKE_DIR/drain_group_fault_seen" ]] &&
       awk -F '|' -v id="$bridge_id" '$1==id && $4=="f" {found=1} END {exit !found}' "$FAKE_DIR/members"; then
      rm -f "$FAKE_DIR/fail_list_once_after_primary_paused"
      touch "$FAKE_DIR/drain_list_fault_seen"
      exit 75
    fi
    if [[ -e "$FAKE_DIR/fail_next_list_members" ]]; then
      rm -f "$FAKE_DIR/fail_next_list_members"
      exit 75
    fi
    if [[ -s "$FAKE_DIR/external_pause_on_list_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/list_members_count" ]] || count="$(<"$FAKE_DIR/list_members_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/list_members_count"
      if [[ "$count" == "$(<"$FAKE_DIR/external_pause_on_list_call")" ]]; then
        python3 - "$FAKE_DIR/members" "$bridge_id" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
rows=[]
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == sys.argv[2]:
        p[3]='f'
    rows.append('|'.join(p))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
        next_generation "$bridge_id" >/dev/null
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
    id="$1"
    if [[ -e "$FAKE_DIR/outbox_pending_$id" ]]; then
      printf '1\n'
    else
      printf '0\n'
    fi
    ;;
  buckets)
    [[ ! -e "$FAKE_DIR/buckets_fail" ]] || exit 2
    printf '%s\n' '12:openai:forced' '12:openai:single'
    ;;
  bucket-ready)
    [[ ! -e "$FAKE_DIR/bucket_ready_error" ]] || exit 2
    if [[ -s "$FAKE_DIR/snapshot_not_ready_until" ]] &&
       (( $(date +%s) < $(<"$FAKE_DIR/snapshot_not_ready_until") )); then
      exit 2
    fi
    [[ ! -e "$FAKE_DIR/snapshot_not_ready" ]]
    ;;
  bucket-contains)
    [[ ! -e "$FAKE_DIR/snapshot_fail" ]] || exit 1
    id="$3"
    [[ ! -e "$FAKE_DIR/bucket_error_$id" ]] || exit 2
    [[ ! -e "$FAKE_DIR/stale_bucket_contains_$id" ]] || exit 0
    awk -F '|' -v id="$id" '$1==id && $3=="active" && $4=="t" && $5=="t" {found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;
  meta)
    id="$1"
    [[ ! -e "$FAKE_DIR/meta_error_$id" ]] || exit 2
    if [[ -e "$FAKE_DIR/meta_error_when_unsched_$id" ]] &&
       awk -F '|' -v id="$id" '$1==id && $4=="f" {found=1} END {exit !found}' "$FAKE_DIR/members"; then
      exit 2
    fi
    if [[ -e "$FAKE_DIR/count_meta_reads_$id" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/meta_read_count_$id" ]] || count="$(<"$FAKE_DIR/meta_read_count_$id")"
      printf '%s\n' "$((count + 1))" >"$FAKE_DIR/meta_read_count_$id"
    fi
    if [[ "$id" == "$bridge_id" && -s "$FAKE_DIR/bump_generation_on_meta_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/meta_call_count" ]] || count="$(<"$FAKE_DIR/meta_call_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/meta_call_count"
      if [[ "$count" == "$(<"$FAKE_DIR/bump_generation_on_meta_call")" ]]; then
        next_generation "$id" >/dev/null
      fi
    fi
    python3 - "$FAKE_DIR/members" "$id" "$FAKE_DIR/meta_generation_$id" "$FAKE_DIR/meta_sched_override_$id" <<'PY'
import json,os,sys
for line in open(sys.argv[1],encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == sys.argv[2]:
        schedulable=p[3] == 't'
        if os.path.exists(sys.argv[4]):
            schedulable=open(sys.argv[4],encoding='utf-8').read().strip() == 'true'
        print(json.dumps({
          'Status':p[2],
          'Schedulable':schedulable,
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
  full-account|full-account-state)
    id="$1"
    [[ ! -e "$FAKE_DIR/full_account_error_$id" ]] || exit 2
    if [[ -e "$FAKE_DIR/full_account_error_when_unsched_$id" ]] &&
       awk -F '|' -v id="$id" '$1==id && $4=="f" {found=1} END {exit !found}' "$FAKE_DIR/members"; then
      exit 2
    fi
    if [[ "$cmd" == full-account && "$id" == "$bridge_id" && -s "$FAKE_DIR/bump_cache_generation_on_full_account_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/full_account_call_count" ]] || count="$(<"$FAKE_DIR/full_account_call_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/full_account_call_count"
      if [[ "$count" == "$(<"$FAKE_DIR/bump_cache_generation_on_full_account_call")" ]]; then
        phase="$(python3 - "$FAKE_DIR/state/maintenance.json" <<'PY'
import json,os,sys
path=sys.argv[1]
if not os.path.exists(path):
    print('MISSING')
else:
    try:
        print(json.load(open(path,encoding='utf-8')).get('phase','UNKNOWN'))
    except Exception:
        print('INVALID')
PY
)"
        printf '%s|%s\n' "$count" "$phase" >"$FAKE_DIR/full_account_injection_phase"
        value="$(<"$FAKE_DIR/generation_counter")"
        value=$((value + 1))
        printf '%s\n' "$value" >"$FAKE_DIR/generation_counter"
        printf '2026-07-14T00:00:00.%06dZ\n' "$value" \
          >"$FAKE_DIR/cache_generation_override_$id"
      fi
    fi
    if [[ "$cmd" == full-account && "$id" == "$bridge_id" && -s "$FAKE_DIR/bump_generation_on_full_account_call" ]]; then
      count=0
      [[ ! -s "$FAKE_DIR/full_account_call_count" ]] || count="$(<"$FAKE_DIR/full_account_call_count")"
      count=$((count + 1))
      printf '%s\n' "$count" >"$FAKE_DIR/full_account_call_count"
      if [[ "$count" == "$(<"$FAKE_DIR/bump_generation_on_full_account_call")" ]]; then
        phase="$(python3 - "$FAKE_DIR/state/maintenance.json" <<'PY'
import json,os,sys
path=sys.argv[1]
if not os.path.exists(path):
    print('MISSING')
else:
    try:
        print(json.load(open(path,encoding='utf-8')).get('phase','UNKNOWN'))
    except Exception:
        print('INVALID')
PY
)"
        printf '%s|%s\n' "$count" "$phase" >"$FAKE_DIR/full_account_injection_phase"
        next_generation "$id" >/dev/null
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
    generation_path="$FAKE_DIR/meta_generation_$id"
    if [[ "$id" == "$bridge_id" && -s "$FAKE_DIR/cache_generation_override_$id" ]]; then
      generation_path="$FAKE_DIR/cache_generation_override_$id"
    fi
    python3 - "$FAKE_DIR/members" "$id" "$generation_path" "$FAKE_DIR/full_account_sched_override_$id" <<'PY'
import json,os,sys
for line in open(sys.argv[1],encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == sys.argv[2]:
        schedulable=p[3] == 't'
        if os.path.exists(sys.argv[4]):
            schedulable=open(sys.argv[4],encoding='utf-8').read().strip() == 'true'
        print(json.dumps({
          'Status':p[2],
          'Schedulable':schedulable,
          'UpdatedAt':open(sys.argv[3],encoding='utf-8').read().strip(),
        }))
        raise SystemExit(0)
raise SystemExit(1)
PY
    ;;
  before-backup-open-submit)
    id="$1"
    flip_file="$FAKE_DIR/inactivate_backup_at_submit_$id"
    if [[ -e "$flip_file" ]]; then
      exec 8>"$FAKE_DIR/backend-write.lock"
      flock 8
      python3 - "$FAKE_DIR/members" "$id" <<'PY'
import os,sys,tempfile
path,account_id=sys.argv[1:]
rows=[]
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == account_id:
        p[2]='inactive'
        p[3]='f'
        p[5]='f'
    rows.append('|'.join(p))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
      rm -f "$flip_file"
    fi
    ;;
  set-schedulable|set-schedulable-receipted|set-schedulable-requested)
    receipted=false
    requested=false
    [[ "$cmd" == set-schedulable-receipted ]] && receipted=true
    [[ "$cmd" == set-schedulable-requested ]] && requested=true
    id="$1"
    desired="$2"
    request_id="${3:-}"
	if [[ "$receipted" == true ]]; then
	  receipted_call=0
	  [[ ! -s "$FAKE_DIR/receipted_call_count" ]] || receipted_call="$(<"$FAKE_DIR/receipted_call_count")"
	  receipted_call=$((receipted_call + 1))
	  printf '%s\n' "$receipted_call" >"$FAKE_DIR/receipted_call_count"
	fi
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
    if [[ "$id" == "$bridge_id" && "$desired" == false && ! -e "$FAKE_DIR/allow_external_primary_write" ]]; then
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
    if [[ "$id" == "$bridge_id" ]]; then
      python3 - "$FAKE_DIR/primary_xmin" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='xmin.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write(str(value)+'\n')
os.replace(tmp,path)
PY
      if [[ "$desired" == false && -e "$FAKE_DIR/bucket_error_after_primary_pause" ]]; then
        touch "$FAKE_DIR/bucket_error_$id"
      fi
      if [[ "$desired" == true && -e "$FAKE_DIR/bucket_error_after_primary_restore" ]]; then
        touch "$FAKE_DIR/bucket_error_$id"
      fi
      if [[ "$desired" == true && "$receipted" == true &&
            -e "$FAKE_DIR/flip_group_after_primary_restore" ]]; then
        rm -f "$FAKE_DIR/flip_group_after_primary_restore"
        printf '13|codex-pro|active\n' >"$FAKE_DIR/group"
      fi
    fi
    generation="$(next_generation "$id")"
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/block_after_primary_apply" ]]; then
      touch "$FAKE_DIR/primary_apply_blocked"
      while [[ ! -e "$FAKE_DIR/release_primary_apply" ]]; do sleep 0.05; done
    fi
    if [[ "$receipted" == true || "$requested" == true ]]; then
      receipt_status="$(cat "$FAKE_DIR/receipt_status_override" 2>/dev/null || printf 200)"
      append_access_log "$request_id" "$receipt_status" \
        "/api/v1/admin/accounts/$id/schedulable"
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/apply_then_fail" ]]; then
      exit 75
    fi
    if [[ "$id" == "$bridge_id" && "$receipted" == true &&
          -s "$FAKE_DIR/apply_then_fail_on_receipted_call" &&
          "$receipted_call" == "$(<"$FAKE_DIR/apply_then_fail_on_receipted_call")" ]]; then
      exit 75
    fi
    if [[ "$id" != "$bridge_id" && "$desired" == false && -e "$FAKE_DIR/flip_after_close" ]]; then
      printf 'error|0|0|0|3|7|0|0|0|0|0|critical\n' >"$FAKE_DIR/health"
    fi
    if [[ "$id" != "$bridge_id" && "$desired" == false && -e "$FAKE_DIR/unavailable_after_close" ]]; then
      printf '1|1|901|2026-07-13T16:40:00.000000+08:00|100\n' >"$FAKE_DIR/relay_evidence"
    fi
    if [[ "$id" != "$bridge_id" && "$desired" == false && -e "$FAKE_DIR/normal_drop_after_close" ]]; then
      printf 'ok|10|1|1|3|7|100|0|0|0|0|degraded\n' >"$FAKE_DIR/health"
    fi
    case "$(cat "$FAKE_DIR/bad_primary_response" 2>/dev/null || true)" in
      invalid-json) printf '{not-json\n';;
      wrong-id) printf '{"data":{"id":999999,"status":"active","schedulable":%s,"updated_at":"%s"}}\n' "$desired" "$generation";;
      wrong-desired) printf '{"data":{"id":%s,"status":"active","schedulable":%s,"updated_at":"%s"}}\n' "$id" "$([[ "$desired" == true ]] && printf false || printf true)" "$generation";;
      missing-generation) printf '{"data":{"id":%s,"status":"active","schedulable":%s}}\n' "$id" "$desired";;
      *) printf '{"data":{"id":%s,"status":"active","schedulable":%s,"updated_at":"%s"}}\n' "$id" "$desired" "$generation";;
    esac
    ;;
  get-account)
    id="$1"
    if [[ -e "$FAKE_DIR/malformed_next_get_account" ]]; then
      rm -f "$FAKE_DIR/malformed_next_get_account"
      printf '|false|0\n'
      exit 0
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/share_primary_on_first_drain" ]]; then
      rm -f "$FAKE_DIR/share_primary_on_first_drain"
      python3 - "$FAKE_DIR/members" "$bridge_id" <<'PY'
import os,sys,tempfile
path,account_id=sys.argv[1:]
rows=[]
for line in open(path,encoding='utf-8'):
    p=line.rstrip('\n').split('|')
    if p[0] == account_id:
        p[6]='2'
    rows.append('|'.join(p))
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='members.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write('\n'.join(rows)+'\n')
os.replace(tmp,path)
PY
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/drain_list_fault_seen" &&
          -e "$FAKE_DIR/fail_get_once_after_primary_paused" ]]; then
      rm -f "$FAKE_DIR/fail_get_once_after_primary_paused"
      touch "$FAKE_DIR/drain_get_fault_seen"
      exit 75
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/fail_next_get_account" ]]; then
      rm -f "$FAKE_DIR/fail_next_get_account"
      exit 75
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/flip_group_on_first_drain" ]]; then
      rm -f "$FAKE_DIR/flip_group_on_first_drain"
      printf '13|codex-pro|active\n' >"$FAKE_DIR/group"
    fi
    if [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/close_backup_on_first_drain" ]]; then
      rm -f "$FAKE_DIR/close_backup_on_first_drain"
      close_first_active_backup
    fi
    concurrency=0
    [[ "$id" == "$bridge_id" && -e "$FAKE_DIR/primary_busy" ]] && concurrency=1
    account_row="$(awk -F '|' -v id="$id" -v concurrency="$concurrency" '$1==id {printf "%s|%s|%s\n",$3,($4=="t"?"true":"false"),concurrency; found=1} END {exit !found}' "$FAKE_DIR/members")"
    printf '%s\n' "$account_row"
    if [[ "$id" == "$bridge_id" && "$account_row" == active\|false\|* ]]; then
      # The first successful disabled-primary GET is the PAUSE_ACKED API-state
      # fence. Later chained fault markers can now target only drain sampling.
      touch "$FAKE_DIR/primary_paused_get_seen"
    fi
    ;;
  primary-snapshot)
    id="$1"
    if [[ -e "$FAKE_DIR/fail_next_primary_snapshot" ]]; then
      rm -f "$FAKE_DIR/fail_next_primary_snapshot"
      exit 75
    fi
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
        next_generation "$id" >/dev/null
      fi
    fi
    xmin="$(<"$FAKE_DIR/primary_xmin")"
    updated_at="$(current_generation "$id")"
    awk -F '|' -v id="$id" -v updated_at="$updated_at" -v xmin="$xmin" '$1==id {printf "%s|%s|%s|%s|%s|%s\n",$3,$4,$5,$6,updated_at,xmin; found=1} END {exit !found}' "$FAKE_DIR/members"
    ;;

  bump-primary-tuple)
    id="$1"
    next_generation "$id" >/dev/null
    python3 - "$FAKE_DIR/primary_xmin" <<'PY'
import os,sys,tempfile
path=sys.argv[1]
value=int(open(path,encoding='utf-8').read().strip())+1
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='xmin.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    f.write(str(value)+'\n')
os.replace(tmp,path)
PY
    ;;
  incarnation)
    cat "$FAKE_DIR/incarnation"
    ;;
  log-sink-health)
    if [[ -e "$FAKE_DIR/fail_next_log_sink_health" ]]; then
      rm -f "$FAKE_DIR/fail_next_log_sink_health"
      exit 75
    fi
    printf '0|%s|%s|%s\n' "$(<"$FAKE_DIR/sink_dropped")" \
      "$(<"$FAKE_DIR/sink_failed")" "$(<"$FAKE_DIR/sink_written")"
    append_access_log "self-health-$(date +%s%N)" 200 \
      "/api/v1/admin/ops/system-logs/health" GET
    ;;
  runtime-logging)
    if [[ -e "$FAKE_DIR/fail_next_runtime_logging" ]]; then
      rm -f "$FAKE_DIR/fail_next_runtime_logging"
      exit 75
    fi
    cat "$FAKE_DIR/runtime_logging"
    runtime_logging_count=0
    [[ ! -s "$FAKE_DIR/runtime_logging_count" ]] || runtime_logging_count="$(<"$FAKE_DIR/runtime_logging_count")"
    runtime_logging_count=$((runtime_logging_count + 1))
    printf '%s\n' "$runtime_logging_count" >"$FAKE_DIR/runtime_logging_count"
    if [[ -s "$FAKE_DIR/close_backup_on_runtime_logging_call" &&
          "$runtime_logging_count" == "$(<"$FAKE_DIR/close_backup_on_runtime_logging_call")" ]]; then
      close_first_active_backup
    fi
    append_access_log "self-runtime-logging-$(date +%s%N)" 200 \
      "/api/v1/admin/ops/runtime/logging" GET
    ;;
  log-watermark)
    cat "$FAKE_DIR/log_counter"
    ;;
  request-id-count)
    request_id="$1"
    awk -F '|' -v request_id="$request_id" '$2==request_id {count++} END {print count+0}' "$FAKE_DIR/access_logs"
    ;;
  sentinel)
    request_id="$1"
    if [[ -e "$FAKE_DIR/inject_foreign_before_sentinel_once" &&
          -e "$FAILOVER_STATE_DIR/maintenance.json" ]]; then
      rm -f "$FAKE_DIR/inject_foreign_before_sentinel_once"
      foreign_path="$(cat "$FAKE_DIR/foreign_before_sentinel_path" 2>/dev/null || printf '/api/v1/admin/accounts/%s/schedulable' "$bridge_id")"
      foreign_request_id="$(cat "$FAKE_DIR/foreign_before_sentinel_request_id" 2>/dev/null || printf 'foreign-before-fence-%s' "$(date +%s%N)")"
      foreign_status="$(cat "$FAKE_DIR/foreign_before_sentinel_status" 2>/dev/null || printf 200)"
      foreign_method="$(cat "$FAKE_DIR/foreign_before_sentinel_method" 2>/dev/null || printf POST)"
      if [[ -s "$FAKE_DIR/remove_member_before_foreign_sentinel" ]]; then
        removed_id="$(<"$FAKE_DIR/remove_member_before_foreign_sentinel")"
        sed -i "/^${removed_id}|/d" "$FAKE_DIR/members"
      fi
      if [[ -s "$FAKE_DIR/add_member_before_foreign_sentinel" ]]; then
        cat "$FAKE_DIR/add_member_before_foreign_sentinel" >>"$FAKE_DIR/members"
      fi
      append_access_log "$foreign_request_id" "$foreign_status" "$foreign_path" "$foreign_method"
    fi
    background_count="$(cat "$FAKE_DIR/background_access_per_sentinel" 2>/dev/null || printf 0)"
    for ((i=0; i<background_count; i++)); do
      append_access_log "background-before-$request_id-$i" 200 \
        "/api/v1/admin/dashboard" GET
    done
    append_access_log "$request_id" 200 \
      "/api/v1/admin/ops/system-logs/health" GET
    for ((i=0; i<background_count; i++)); do
      append_access_log "background-after-$request_id-$i" 200 \
        "/api/v1/admin/dashboard" GET
    done
    ;;
  sentinel-receipt-record)
    request_id="$1"
    watermark="$2"
    awk -F '|' -v request_id="$request_id" -v watermark="$watermark" \
      -v path="/api/v1/admin/ops/system-logs/health" '
      $1>watermark && $2==request_id && $4==path && $5=="GET" &&
      $6=="http.access" && $7=="http request completed" {
        count++; if (min==0 || $1<min) min=$1; if (status=="" || $3<status) status=$3
      }
      END {printf "%d|%d|%s\n",count+0,min+0,status}' "$FAKE_DIR/access_logs"
    ;;
  receipt-record)
    case "$1" in
      *-seal)
        if [[ -e "$FAKE_DIR/fail_next_seal_receipt_record" ]]; then
          rm -f "$FAKE_DIR/fail_next_seal_receipt_record"
          exit 75
        fi
        ;;
      *-restore)
        if [[ -e "$FAKE_DIR/fail_next_restore_receipt_record" ]]; then
          rm -f "$FAKE_DIR/fail_next_restore_receipt_record"
          exit 75
        fi
        ;;
    esac
    if [[ -e "$FAKE_DIR/fail_next_receipt_record" ]]; then
      rm -f "$FAKE_DIR/fail_next_receipt_record"
      exit 75
    fi
    request_id="$1"
    watermark="$2"
    account_id="$3"
    awk -F '|' -v request_id="$request_id" -v watermark="$watermark" \
      -v path="/api/v1/admin/accounts/$account_id/schedulable" '
      $1>watermark && $2==request_id && $4==path && $5=="POST" &&
      $6=="http.access" && $7=="http request completed" {
        count++; if (min==0 || $1<min) min=$1; if (status=="" || $3<status) status=$3
      }
      END {printf "%d|%d|%s\n",count+0,min+0,status}' "$FAKE_DIR/access_logs"
    ;;
  foreign-mutation-count)
    if [[ -e "$FAKE_DIR/fail_foreign_once_after_primary_paused" ]] &&
       [[ -e "$FAKE_DIR/drain_get_fault_seen" ]] &&
       awk -F '|' -v id="$bridge_id" '$1==id && $4=="f" {found=1} END {exit !found}' "$FAKE_DIR/members"; then
      rm -f "$FAKE_DIR/fail_foreign_once_after_primary_paused"
      exit 75
    fi
    if [[ -e "$FAKE_DIR/fail_next_foreign_mutation_query" ]]; then
      rm -f "$FAKE_DIR/fail_next_foreign_mutation_query"
      exit 75
    fi
    watermark="$1"
    upper_log_id="$2"
    account_id="$3"
    pause_id="${4:-}"
    pause_log_id="${5:-}"
    seal_id="${6:-}"
    seal_log_id="${7:-}"
    restore_id="${8:-}"
    restore_log_id="${9:-}"
    restore_allow_2xx="${10:-false}"
    foreign_count="$(awk -F '|' -v watermark="$watermark" -v upper_log_id="$upper_log_id" \
      -v account_id="$account_id" -v pause_id="$pause_id" -v pause_log_id="$pause_log_id" \
      -v seal_id="$seal_id" -v seal_log_id="$seal_log_id" \
      -v restore_id="$restore_id" -v restore_log_id="$restore_log_id" \
      -v restore_allow_2xx="$restore_allow_2xx" '
      function mutating(method) { return method=="POST" || method=="PUT" || method=="PATCH" || method=="DELETE" }
      function positive_bigint(token) {
        return token~/^[1-9][0-9]*$/ && length(token)<=19 &&
          !(length(token)==19 && ("x" token)>("x9223372036854775807"))
      }
      function harmless_external(path,method) {
        return method=="POST" && path=="/api/v1/admin/accounts/today-stats/batch"
      }
      function owned(row_log_id,row_request_id,path,method,status) {
        if (method!="POST" || path!="/api/v1/admin/accounts/" account_id "/schedulable") return 0
        if (row_log_id==pause_log_id && row_request_id==pause_id && status=="200") return 1
        if (row_log_id==seal_log_id && row_request_id==seal_id && status=="200") return 1
        if (row_log_id==restore_log_id && row_request_id==restore_id) {
          if (restore_allow_2xx=="true") return status~/^2[0-9][0-9]$/
          return status=="200"
        }
        return 0
      }
      BEGIN {
        if (restore_allow_2xx!="true" && restore_allow_2xx!="false") exit 2
        if ((pause_id=="") != (pause_log_id=="") ||
            (seal_id=="") != (seal_log_id=="") ||
            (restore_id=="") != (restore_log_id=="")) exit 2
        if ((pause_log_id!="" && !positive_bigint(pause_log_id)) ||
            (seal_log_id!="" && !positive_bigint(seal_log_id)) ||
            (restore_log_id!="" && !positive_bigint(restore_log_id))) exit 2
        count=0
      }
      $1>watermark && $1<=upper_log_id && $6=="http.access" && $7=="http request completed" &&
      !($3~/^[0-9][0-9][0-9]$/ && $3>=400 && $3<=499) && mutating($5) &&
      index($4,"/api/v1/admin/")==1 &&
      !owned($1,$2,$4,$5,$3) && !harmless_external($4,$5) {count++}
      END {print count+0}' "$FAKE_DIR/access_logs")"
    printf '%s\n' "$foreign_count"
    ;;
  inject-foreign)
    id="$1"
    desired="$2"
    path="${3:-/api/v1/admin/accounts/$id/schedulable}"
    FAKE_DIR="$FAKE_DIR" FAKE_BRIDGE_ID="$bridge_id" "$0" set-schedulable "$id" "$desired" >/dev/null
    append_access_log "foreign-$(date +%s%N)" 200 "$path"
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
  : >"$tmp/access_logs"
  printf '0\n' >"$tmp/log_counter"
  printf '0\n' >"$tmp/sink_dropped"
  printf '0\n' >"$tmp/sink_failed"
  printf '0\n' >"$tmp/sink_written"
  printf 'fake-sub2-container-1@2026-07-14T00:00:00Z\n' >"$tmp/incarnation"
  printf 'info|false\n' >"$tmp/runtime_logging"
  printf '0\n' >"$tmp/receipted_call_count"
  printf '12|codex-pro|active\n' >"$tmp/group"
  cat >"$tmp/members" <<EOF
7692|$(encode_name codex2api-pro)|active|t|t|t|1
7693|$(encode_name standby-active)|active|f|t|t|1
7845|$(encode_name standby-inactive)|inactive|f|t|f|1
7850|$(encode_name standby-error)|error|f|t|f|1
EOF
  printf '100\n' >"$tmp/primary_xmin"
  printf '100\n' >"$tmp/generation_counter"
  printf '2026-07-14T00:00:00.000100Z\n' >"$tmp/meta_generation_7692"
  printf '2026-07-14T00:00:00.000090Z\n' >"$tmp/meta_generation_7693"
  printf '2026-07-14T00:00:00.000080Z\n' >"$tmp/meta_generation_7845"
  printf '2026-07-14T00:00:00.000070Z\n' >"$tmp/meta_generation_7850"
  printf 'ok|10|3|3|3|7|300|0|0|0|0|ok\n' >"$tmp/health"
  printf '0|0|0||100\n' >"$tmp/relay_evidence"
  rm -f "$tmp/snapshot_fail" "$tmp/snapshot_not_ready" "$tmp/proof_fail" \
    "$tmp/primary_busy" "$tmp/traffic_outbox" "$tmp/lock-held" \
    "$tmp/flip_after_close" "$tmp/unavailable_after_close" \
    "$tmp/normal_drop_after_close" "$tmp/wrapped-started" "$tmp/relay_evidence_fail"
	rm -f "$tmp"/fail_open_* "$tmp"/bucket_error_*
	rm -f "$tmp"/stale_bucket_contains_* "$tmp"/outbox_pending_* \
	  "$tmp"/meta_sched_override_* "$tmp"/full_account_sched_override_* \
	  "$tmp"/meta_error_* "$tmp"/full_account_error_* \
	  "$tmp"/meta_error_when_unsched_* "$tmp"/full_account_error_when_unsched_* \
	  "$tmp"/count_meta_reads_* "$tmp"/meta_read_count_*
  rm -f "$tmp"/started_open_* "$tmp"/wait_for_open_peer_* "$tmp"/saw_open_peer_* \
    "$tmp"/inactivate_backup_at_submit_* "$tmp/backend-write.lock"
  rm -f "$tmp/buckets_fail" "$tmp/bucket_ready_error" "$tmp/health_fail" \
    "$tmp/external_pause_on_list_call" "$tmp/list_members_count" \
    "$tmp/bump_xmin_on_snapshot_call" "$tmp/primary_snapshot_count" \
    "$tmp/inactivate_backup_on_list_call" "$tmp/backup_list_members_count"
  rm -f "$tmp/apply_then_fail" "$tmp/bad_primary_response" \
    "$tmp/block_after_primary_apply" "$tmp/primary_apply_blocked" "$tmp/release_primary_apply" \
    "$tmp"/response-barrier.* \
    "$tmp/bucket_error_after_primary_pause" "$tmp/bucket_error_after_primary_restore" \
    "$tmp/bump_generation_on_meta_call" "$tmp/meta_call_count" "$tmp/snapshot_not_ready_until" \
    "$tmp/bump_generation_on_full_account_call" \
    "$tmp/bump_cache_generation_on_full_account_call" "$tmp/full_account_call_count" \
    "$tmp/full_account_injection_phase" "$tmp/cache_generation_override_7692" \
    "$tmp/apply_then_fail_on_receipted_call" "$tmp/drop_next_receipt" \
    "$tmp/fail_next_receipt" "$tmp/duplicate_next_receipt" \
    "$tmp/receipt_status_override" "$tmp/omit_next_receipt_clean" \
    "$tmp/inject_foreign_before_sentinel_once" "$tmp/background_access_per_sentinel" \
    "$tmp/foreign_before_sentinel_path" "$tmp/foreign_before_sentinel_request_id" \
    "$tmp/foreign_before_sentinel_status" "$tmp/foreign_before_sentinel_method" \
    "$tmp/remove_member_before_foreign_sentinel" "$tmp/add_member_before_foreign_sentinel"
  rm -f "$tmp/runtime_logging_count" "$tmp/close_backup_on_runtime_logging_call" \
    "$tmp/close_backup_on_first_drain" "$tmp/discover_group_count" \
    "$tmp/flip_group_on_discover_call" "$tmp/flip_group_on_first_drain" \
    "$tmp/fail_group_on_discover_call" "$tmp/fail_next_list_members" \
    "$tmp/fail_next_get_account" "$tmp/fail_next_foreign_mutation_query" \
    "$tmp/fail_group_once_after_primary_paused" "$tmp/fail_list_once_after_primary_paused" \
    "$tmp/fail_get_once_after_primary_paused" "$tmp/fail_foreign_once_after_primary_paused"
  rm -f "$tmp/primary_paused_get_seen" "$tmp/drain_group_fault_seen" \
    "$tmp/drain_list_fault_seen" "$tmp/drain_get_fault_seen"
  rm -f "$tmp/share_primary_on_first_drain" "$tmp/fail_next_receipt_record" \
    "$tmp/fail_next_seal_receipt_record" "$tmp/fail_next_restore_receipt_record" \
    "$tmp/fail_next_primary_snapshot" "$tmp/flip_group_after_primary_restore" \
    "$tmp/fail_next_runtime_logging" "$tmp/fail_next_log_sink_health" \
    "$tmp/malformed_next_get_account"
  rm -f "$tmp/allow_external_primary_write"
}

run_controller() {
  local command="$1"
  if FAKE_DIR="$tmp" \
    FAKE_BRIDGE_ID="${TEST_BRIDGE_ACCOUNT_ID:-7692}" \
    FAILOVER_TEST_BACKEND="$backend" \
    FAILOVER_TEST_FAIL_MAINTENANCE_MARKER_WRITE_NUMBER="${TEST_FAIL_MARKER_WRITE_NUMBER:-0}" \
    MAINTENANCE_TEST_RESPONSE_BARRIER_PREFIX="${TEST_RESPONSE_BARRIER_PREFIX:-}" \
    FAILOVER_STATE_DIR="$tmp/state" \
    FAILOVER_RUNTIME_DIR="$tmp/run" \
    BRIDGE_ACCOUNT_ID="${TEST_BRIDGE_ACCOUNT_ID:-7692}" \
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
    SNAPSHOT_CONFIRMATIONS="${TEST_SNAPSHOT_CONFIRMATIONS:-1}" \
    SNAPSHOT_TIMEOUT_SECONDS="${TEST_SNAPSHOT_TIMEOUT_SECONDS:-2}" \
    MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS="${TEST_MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS:-2}" \
    MAINTENANCE_RECEIPT_TIMEOUT_SECONDS="${TEST_MAINTENANCE_RECEIPT_TIMEOUT_SECONDS:-3}" \
    MAINTENANCE_DRAIN_SETTLE_SECONDS="${TEST_MAINTENANCE_DRAIN_SETTLE_SECONDS:-1}" \
    SNAPSHOT_POLL_SECONDS=1 \
    DRAIN_TIMEOUT_SECONDS="${TEST_DRAIN_TIMEOUT_SECONDS:-3}" \
    DRAIN_POLL_SECONDS=1 \
    LOCK_WAIT_SECONDS=1 \
    BACKUP_OPEN_PARALLELISM="${TEST_BACKUP_OPEN_PARALLELISM:-4}" \
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

run_controller_from_config() {
  local config_file="$1"
  local command="$2"
  if env -u BRIDGE_ACCOUNT_ID \
    FAKE_DIR="$tmp" \
    FAKE_BRIDGE_ID=7692 \
    FAILOVER_CONFIG_FILE="$config_file" \
    FAILOVER_TEST_BACKEND="$backend" \
    FAILOVER_STATE_DIR="$tmp/state" \
    FAILOVER_RUNTIME_DIR="$tmp/run" \
    SNAPSHOT_CONFIRMATIONS=1 \
    SNAPSHOT_TIMEOUT_SECONDS=2 \
      bash "$controller" "$command" >>"$tmp/controller.log" 2>&1; then
    return 0
  else
    local rc=$?
    cat "$tmp/controller.log" >&2
    return "$rc"
  fi
}

start_controller_background() {
  local command="$1"
  FAKE_DIR="$tmp" \
    FAKE_BRIDGE_ID="${TEST_BRIDGE_ACCOUNT_ID:-7692}" \
    FAILOVER_TEST_BACKEND="$backend" \
    MAINTENANCE_TEST_RESPONSE_BARRIER_PREFIX="${TEST_RESPONSE_BARRIER_PREFIX:-}" \
    FAILOVER_STATE_DIR="$tmp/state" \
    FAILOVER_RUNTIME_DIR="$tmp/run" \
    BRIDGE_ACCOUNT_ID="${TEST_BRIDGE_ACCOUNT_ID:-7692}" \
    RECOVERY_CONFIRMATIONS=3 FAILOVER_MIN_HOLD_SECONDS=180 RECOVERY_CLEAN_SECONDS=120 \
    RECOVERY_RELAY_SUCCESSES=20 ROUTE_UNAVAILABLE_WINDOW_SECONDS=15 \
    ROUTE_UNAVAILABLE_THRESHOLD=2 ROUTE_UNAVAILABLE_SPARSE_THRESHOLD=3 \
    RELAY_AVAILABILITY_WINDOW_SECONDS=15 RELAY_AVAILABILITY_DETECTION_SECONDS=60 \
    RELAY_AVAILABILITY_THRESHOLD=2 TELEMETRY_FAILURE_CONFIRMATIONS=2 \
    SNAPSHOT_CONFIRMATIONS=1 SNAPSHOT_TIMEOUT_SECONDS=2 \
    MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS=2 SNAPSHOT_POLL_SECONDS=1 \
    MAINTENANCE_RECEIPT_TIMEOUT_SECONDS=3 MAINTENANCE_DRAIN_SETTLE_SECONDS=1 \
    DRAIN_TIMEOUT_SECONDS=3 DRAIN_POLL_SECONDS=1 LOCK_WAIT_SECONDS=1 \
    BACKUP_OPEN_PARALLELISM=4 SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS=5 \
    BACKUP_OPEN_BATCH_TIMEOUT_SECONDS=10 \
      bash "$controller" "$command" >>"$tmp/controller.log" 2>&1 &
  CONTROLLER_PID=$!
  child_pids+=("$CONTROLLER_PID")
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
grep -Fxq 'EnvironmentFile=/etc/default/codex2api-sub2-codex-pro-failover' "$service_unit"
if grep -Eq '^Environment=BRIDGE_ACCOUNT_ID=' "$service_unit"; then
  printf 'FAIL: systemd unit still has an inline bridge account id\n' >&2
  exit 1
fi
grep -Fxq 'BRIDGE_ACCOUNT_ID=' "$env_example"
if grep -Eq '^BRIDGE_ACCOUNT_ID=[0-9]+' "$env_example"; then
  printf 'FAIL: deployment-specific bridge account id leaked into env example\n' >&2
  exit 1
fi
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
  env BRIDGE_ACCOUNT_ID=7692 "${availability_setting}=not-a-number" \
    bash "$controller" status >"$invalid_config_log" 2>&1
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
7694|$(encode_name standby-second-healthy)|active|f|t|t|1
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
7694|$(encode_name standby-after-inactive)|active|f|t|t|1
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

# Each parallel child re-loads live eligibility immediately before its POST.
# This hook flips 7693 after the parent's batch check but before the child's
# submit fence; the stale target receives no schedulable write.
reset_fixture
cat >>"$tmp/members" <<EOF
7694|$(encode_name standby-after-submit-flip)|active|f|t|t|1
EOF
touch "$tmp/inactivate_backup_at_submit_7693"
rm -f "$tmp/state/state.json"
TEST_BACKUP_OPEN_PARALLELISM=1
run_controller reconcile
unset TEST_BACKUP_OPEN_PARALLELISM
assert_eq inactive "$(awk -F '|' '$1==7693 {print $3}' "$tmp/members")" \
  'submit-time operator transition preserved inactive status'
assert_eq f "$(member_schedulable 7693)" 'submit-time stale standby was not enabled'
assert_eq t "$(member_schedulable 7694)" 'submit-time live peer still opened'
assert_eq 'set:7694:true' "$(cat "$tmp/events")" \
  'child submit fence allowed only the live eligible peer write'
grep -Fq 'backup_live_revalidation_failed_at_submit' "$tmp/controller.log"
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

# Help and argument errors are pure parser paths. They must return before the
# wrapper creates a runtime directory, takes a lock, reads primary config, or
# invokes prepare-maintenance.
for help_option in -h --help; do
  help_runtime="$tmp/wrapper-parse-${help_option#-}"
  rm -rf "$help_runtime"
  FAILOVER_CONTROLLER_BIN="$tmp/controller-must-not-run" \
  FAILOVER_RUNTIME_DIR="$help_runtime" \
  FAILOVER_CONFIG_FILE="$tmp/config-must-not-be-read" \
    bash "$wrapper" "$help_option" >"$tmp/wrapper-help.log" 2>&1
  grep -Fq 'usage:' "$tmp/wrapper-help.log"
  test ! -e "$help_runtime"
done

set +e
FAILOVER_CONTROLLER_BIN="$tmp/controller-must-not-run" \
FAILOVER_RUNTIME_DIR="$tmp/wrapper-parse-empty" \
FAILOVER_CONFIG_FILE="$tmp/config-must-not-be-read" \
  bash "$wrapper" >"$tmp/wrapper-empty.log" 2>&1
wrapper_empty_rc=$?
FAILOVER_CONTROLLER_BIN="$tmp/controller-must-not-run" \
FAILOVER_RUNTIME_DIR="$tmp/wrapper-parse-unknown" \
FAILOVER_CONFIG_FILE="$tmp/config-must-not-be-read" \
  bash "$wrapper" --unknown-maintenance-option >"$tmp/wrapper-unknown.log" 2>&1
wrapper_unknown_rc=$?
set -e
assert_eq 64 "$wrapper_empty_rc" 'wrapper rejected an absent maintenance command'
assert_eq 64 "$wrapper_unknown_rc" 'wrapper rejected an unknown option before prepare'
test ! -e "$tmp/wrapper-parse-empty"
test ! -e "$tmp/wrapper-parse-unknown"

# safe-maintenance owns an independent lifecycle lock across prepare, the
# wrapped rebuild, and finish. A second manual deployment must be rejected.
fake_controller="$tmp/fake-controller.sh"
cat >"$fake_controller" <<'FAKE_CONTROLLER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$FAKE_CONTROLLER_LOG"
printf '%s|%s\n' "$1" "${BRIDGE_ACCOUNT_ID:-missing}" >>"$FAKE_CONTROLLER_ID_LOG"
FAKE_CONTROLLER
chmod +x "$fake_controller"
install -d -m 0700 "$tmp/lifecycle-run"
: >"$tmp/fake-controller.log"
: >"$tmp/fake-controller-id.log"
printf 'BRIDGE_ACCOUNT_ID=7692\n' >"$tmp/wrapper.env"
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAKE_CONTROLLER_ID_LOG="$tmp/fake-controller-id.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-run" \
FAILOVER_CONFIG_FILE="$tmp/wrapper.env" \
  timeout --kill-after=2s 10s bash "$wrapper" -- bash -c 'touch "$1"; sleep 3' _ "$tmp/wrapped-started" \
  >"$tmp/wrapper-1.log" 2>&1 &
wrapper_pid=$!
child_pids=("$wrapper_pid")
if ! wait_for_marker "$tmp/wrapped-started" "$wrapper_pid" 5; then
  printf 'FAIL: first safe-maintenance wrapper did not start within timeout\n' >&2
  exit 1
fi
printf 'BRIDGE_ACCOUNT_ID=7693\n' >"$tmp/wrapper.env"
set +e
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAKE_CONTROLLER_ID_LOG="$tmp/fake-controller-id.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-run" \
FAILOVER_CONFIG_FILE="$tmp/wrapper.env" \
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
assert_eq $'prepare-maintenance|7692\nfinish-maintenance|7692' "$(cat "$tmp/fake-controller-id.log")" 'wrapper froze one primary id across config edit'

# An explicit environment id bypasses an unreadable file but is still frozen
# and exported to both controller calls.
: >"$tmp/fake-controller.log"
: >"$tmp/fake-controller-id.log"
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAKE_CONTROLLER_ID_LOG="$tmp/fake-controller-id.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-explicit" \
FAILOVER_CONFIG_FILE="$tmp/does-not-exist" \
BRIDGE_ACCOUNT_ID=7692 \
  bash "$wrapper" -- true
assert_eq $'prepare-maintenance|7692\nfinish-maintenance|7692' "$(cat "$tmp/fake-controller-id.log")" 'wrapper honored explicit primary id'

# Invalid config fails before either controller call or wrapped command.
: >"$tmp/fake-controller.log"
printf 'BRIDGE_ACCOUNT_ID=\n' >"$tmp/wrapper-invalid.env"
set +e
FAKE_CONTROLLER_LOG="$tmp/fake-controller.log" \
FAKE_CONTROLLER_ID_LOG="$tmp/fake-controller-id.log" \
FAILOVER_CONTROLLER_BIN="$fake_controller" \
FAILOVER_RUNTIME_DIR="$tmp/lifecycle-invalid" \
FAILOVER_CONFIG_FILE="$tmp/wrapper-invalid.env" \
  bash "$wrapper" -- true >"$tmp/wrapper-invalid.log" 2>&1
wrapper_invalid_rc=$?
set -e
assert_eq 64 "$wrapper_invalid_rc" 'wrapper rejected empty primary config'
assert_eq '' "$(cat "$tmp/fake-controller.log")" 'invalid wrapper config reached no controller call'

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

# A retained outbox row and an old bucket member are asynchronous cleanup
# details, not evidence that a paused account can still receive new work. Once
# DB, sched:meta and sched:acc all say false, closing succeeds without the
# false->true oscillation seen with long-running production streams.
reset_fixture
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
age_recovery_state
run_controller reconcile
touch "$tmp/outbox_pending_7693" "$tmp/stale_bucket_contains_7693"
touch "$tmp/count_meta_reads_7693"
TEST_SNAPSHOT_CONFIRMATIONS=2
# Two one-second polling intervals can straddle a SECONDS boundary; give the
# deterministic two-confirmation test enough wall-clock budget without changing
# the controller's production defaults.
TEST_SNAPSHOT_TIMEOUT_SECONDS=4
run_controller reconcile
unset TEST_SNAPSHOT_CONFIRMATIONS TEST_SNAPSHOT_TIMEOUT_SECONDS
assert_eq f "$(member_schedulable 7693)" 'cleanup lag did not reopen a logically paused standby'
assert_eq 'set:7693:false' "$(cat "$tmp/events")" 'cleanup lag produced one close and no reopen'
if (( $(<"$tmp/meta_read_count_7693") < 2 )); then
  printf 'FAIL: close was accepted without two scheduler-state confirmations\n' >&2
  exit 1
fi

# Both Redis scheduler views are safety gates for a close. A stale true value
# in either view makes the close unconfirmed and the controller reopens the
# standby, while the timeout event identifies the failed projection.
for stale_cache in meta full_account; do
  reset_fixture
  sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
  run_controller reconcile
  age_recovery_state
  run_controller reconcile
  printf 'true\n' >"$tmp/${stale_cache}_sched_override_7693"
  TEST_SNAPSHOT_TIMEOUT_SECONDS=1
  set +e
  run_controller reconcile
  stale_cache_rc=$?
  set -e
  unset TEST_SNAPSHOT_TIMEOUT_SECONDS
  if (( stale_cache_rc == 0 )); then
    printf 'FAIL: %s true cache was accepted as a confirmed close\n' "$stale_cache" >&2
    exit 1
  fi
  assert_eq t "$(member_schedulable 7693)" "$stale_cache true cache forced a safe standby reopen"
  assert_eq $'set:7693:false\nset:7693:true' "$(tail -n 2 "$tmp/events")" \
    "$stale_cache mismatch close/reopen order"
  python3 - "$tmp/controller.log" "$stale_cache" <<'PY'
import json,sys
events=[]
for line in open(sys.argv[1],encoding='utf-8'):
    try:
        event=json.loads(line)
    except Exception:
        continue
    if event.get('reason') == 'scheduler_snapshot_not_confirmed':
        events.append(event)
assert events
snapshot=events[-1]['details']['snapshot']
assert snapshot['db_ok'] is True
assert snapshot['bucket_cleanup_complete'] is True
assert snapshot['outbox_rows'] == 0
if sys.argv[2] == 'meta':
    assert snapshot['meta_ok'] is False and snapshot['full_ok'] is True
else:
    assert snapshot['meta_ok'] is True and snapshot['full_ok'] is False
PY
done

# Read failures in either Redis scheduler view also fail closed. The recovery
# attempt still writes the active standby back to true, but the controller does
# not claim convergence while that cache remains unverifiable.
for error_cache in meta full_account; do
  reset_fixture
  sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
  run_controller reconcile
  age_recovery_state
  run_controller reconcile
  touch "$tmp/${error_cache}_error_when_unsched_7693"
  TEST_SNAPSHOT_TIMEOUT_SECONDS=1
  set +e
  run_controller reconcile
  cache_error_rc=$?
  set -e
  unset TEST_SNAPSHOT_TIMEOUT_SECONDS
  if (( cache_error_rc == 0 )); then
    printf 'FAIL: %s read error was accepted as scheduler convergence\n' "$error_cache" >&2
    exit 1
  fi
  assert_eq t "$(member_schedulable 7693)" "$error_cache read error issued fail-safe reopen"
  assert_eq $'set:7693:false\nset:7693:true' "$(tail -n 2 "$tmp/events")" \
    "$error_cache read error close/reopen order"
done

# Opening is intentionally stricter than closing: standby protection is not
# declared until at least one active candidate has converged in DB, metadata,
# full-account cache, and every current ready bucket.
reset_fixture
printf 'false\n' >"$tmp/full_account_sched_override_7693"
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
TEST_SNAPSHOT_TIMEOUT_SECONDS=1
set +e
run_controller reconcile
stale_open_rc=$?
set -e
unset TEST_SNAPSHOT_TIMEOUT_SECONDS
if (( stale_open_rc == 0 )); then
  printf 'FAIL: stale false full-account cache was accepted as a confirmed open\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'unconfirmed open left the active standby available rather than rolling it back'
grep -Fq 'no_backup_reached_scheduler_snapshot' "$tmp/controller.log"
rm -f "$tmp/full_account_sched_override_7693"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'open completed after the full account cache converged'

# schedulable is global across groups. If a standby that is open during a
# recovery generation becomes shared with another active group, the controller
# must neither close it globally nor hide it by declaring this group normal.
reset_fixture
printf '7694|%s|active|t|t|t|1\n' "$(encode_name standby-exclusive-peer)" >>"$tmp/members"
printf '2026-07-14T00:00:00.000091Z\n' >"$tmp/meta_generation_7694"
sed -i 's/7693|\([^|]*\)|active|f|/7693|\1|active|t|/' "$tmp/members"
run_controller reconcile
sed -i 's/^7693|\(.*\)|1$/7693|\1|2/' "$tmp/members"
age_recovery_state
run_controller reconcile
set +e
run_controller reconcile
shared_drift_rc=$?
set -e
if (( shared_drift_rc == 0 )); then
  printf 'FAIL: shared schedulable standby drift was treated as normal recovery\n' >&2
  exit 1
fi
assert_eq t "$(member_schedulable 7693)" 'shared standby was not closed globally'
assert_eq t "$(member_schedulable 7694)" 'exclusive peer was not partly closed before shared drift abort'
assert_eq recovery_pending "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mode"])' "$tmp/state/state.json")" \
  'shared standby drift did not declare normal'
grep -Fq 'shared_schedulable_backup_requires_manual_reconciliation' "$tmp/controller.log"

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
printf '7694|%s|active|t|t|t|1\n' "$(encode_name standby-active-2)" >>"$tmp/members"
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
printf '7694|%s|active|f|t|t|1\n' "$(encode_name standby-active-2)" >>"$tmp/members"
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
printf '7694|%s|active|f|t|t|1\n' "$(encode_name standby-active-2)" >>"$tmp/members"
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
TEST_BACKUP_OPEN_PARALLELISM=1
run_controller reconcile
unset TEST_BACKUP_OPEN_PARALLELISM
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

# Maintenance evidence is receipt based. Redis scheduler projections prove
# convergence only; they are never treated as a durable mutation generation.
grep -Fq 'X-Request-ID: $request_id' "$controller"
grep -Fq "extra->>'path'='/api/v1/admin/ops/system-logs/health'" "$controller"
grep -Fq 'sched:acc:${account_id}' "$controller"
grep -Fq 'readonly SNAPSHOT_TIMEOUT_SECONDS="${SNAPSHOT_TIMEOUT_SECONDS:-20}"' "$controller"
grep -Fq 'readonly MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS="${MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS:-90}"' "$controller"
grep -Fq 'readonly MAINTENANCE_RECEIPT_TIMEOUT_SECONDS="${MAINTENANCE_RECEIPT_TIMEOUT_SECONDS:-90}"' "$controller"
grep -Fq 'readonly MAINTENANCE_DRAIN_SETTLE_SECONDS="${MAINTENANCE_DRAIN_SETTLE_SECONDS:-10}"' "$controller"
grep -Fq "extra->>'path' LIKE '/api/v1/admin/%'" "$controller"
foreign_contract="$(awk '/^foreign_account_mutation_count\(\)/,/^}/' "$controller")"
grep -Fq 'id=${M_PAUSE_LOG_ID}' <<<"$foreign_contract"
grep -Fq 'id=${M_SEAL_LOG_ID}' <<<"$foreign_contract"
grep -Fq 'local provisional_restore_log_id="${3:-}"' <<<"$foreign_contract"
if grep -Fq 'request_id IN' <<<"$foreign_contract" ||
   grep -Fq 'c2m-' <<<"$foreign_contract"; then
  printf 'FAIL: foreign mutation fence still has a request-id-pattern exemption\n' >&2
  exit 1
fi
grep -Fq 'MAINTENANCE_AMBIGUITY_FILE' "$controller"
grep -Fq '[[ "$desired" == true && "$account_id" != "$BRIDGE_ACCOUNT_ID"' "$controller"
grep -Fq 'readonly FAILOVER_CONFIG_FILE="${FAILOVER_CONFIG_FILE:-/etc/default/codex2api-sub2-codex-pro-failover}"' "$controller"
if grep -Eq '(^|[[:space:]])(source|\.)[[:space:]].*FAILOVER_CONFIG_FILE' "$controller" "$wrapper"; then
  printf 'FAIL: failover configuration is executed instead of parsed as data\n' >&2
  exit 1
fi
if grep -Fq 'pause_generation' "$controller"; then
  printf 'FAIL: obsolete scheduler generation ownership remains in controller\n' >&2
  exit 1
fi

# The configured primary has one non-executable source of truth. Manual direct
# invocations load it through the controller; an explicit environment value
# wins. Missing, duplicate, empty, executable-looking, and out-of-range values
# all fail with usage status before the controller creates state or writes an
# account.
bridge_config="$tmp/failover.env"
printf '# deployment-selected sub2 account id\nBRIDGE_ACCOUNT_ID=7692\n' >"$bridge_config"
reset_fixture
run_controller_from_config "$bridge_config" status
grep -Fq '"bridge_account_id":"7692"' "$tmp/controller.log"

explicit_override_log="$tmp/explicit-account-id.log"
set +e
BRIDGE_ACCOUNT_ID=7692 \
  FAILOVER_CONFIG_FILE="$tmp/does-not-exist" \
  FAILOVER_STATE_DIR="$tmp/explicit-state" \
  FAILOVER_RUNTIME_DIR="$tmp/explicit-run" \
  bash "$controller" definitely-not-a-command >"$explicit_override_log" 2>&1
explicit_override_rc=$?
set -e
assert_eq 64 "$explicit_override_rc" 'explicit bridge id bypassed missing config and reached usage validation'
grep -Fq 'usage:' "$explicit_override_log"
if grep -Fq 'BRIDGE_ACCOUNT_ID_required_config_unreadable' "$explicit_override_log"; then
  printf 'FAIL: explicit bridge account id did not override missing config\n' >&2
  exit 1
fi

missing_id_log="$tmp/missing-account-id.log"
set +e
env -u BRIDGE_ACCOUNT_ID FAILOVER_CONFIG_FILE="$tmp/does-not-exist" \
  bash "$controller" status >"$missing_id_log" 2>&1
missing_id_rc=$?
set -e
if (( missing_id_rc == 0 )); then
  printf 'FAIL: missing bridge account id was accepted\n' >&2
  exit 1
fi
assert_eq 64 "$missing_id_rc" 'missing bridge account id failed with usage status'
grep -Fq 'BRIDGE_ACCOUNT_ID_required_config_unreadable' "$missing_id_log"

env_example_events_before="$(wc -l <"$tmp/events")"
set +e
env -u BRIDGE_ACCOUNT_ID FAILOVER_CONFIG_FILE="$env_example" \
  bash "$controller" status >"$tmp/empty-env-example.log" 2>&1
empty_env_example_rc=$?
set -e
assert_eq 64 "$empty_env_example_rc" 'empty env example failed with usage status'
assert_eq "$env_example_events_before" "$(wc -l <"$tmp/events")" \
  'empty env example made zero account writes'

for config_case in missing-key empty duplicate executable; do
  invalid_config="$tmp/invalid-bridge-$config_case.env"
  case "$config_case" in
    missing-key) printf 'GROUP_NAME=codex-pro\n' >"$invalid_config" ;;
    empty) printf 'BRIDGE_ACCOUNT_ID=\n' >"$invalid_config" ;;
    duplicate) printf 'BRIDGE_ACCOUNT_ID=7692\nBRIDGE_ACCOUNT_ID=7693\n' >"$invalid_config" ;;
    executable) printf 'BRIDGE_ACCOUNT_ID=$(touch %s)\n' "$tmp/config-executed" >"$invalid_config" ;;
  esac
  invalid_config_log="$tmp/invalid-bridge-$config_case.log"
  set +e
  env -u BRIDGE_ACCOUNT_ID FAILOVER_CONFIG_FILE="$invalid_config" \
    bash "$controller" status >"$invalid_config_log" 2>&1
  invalid_config_rc=$?
  set -e
  assert_eq 64 "$invalid_config_rc" "invalid bridge config $config_case failed with usage status"
done
test ! -e "$tmp/config-executed"

for invalid_id in 0 +7692 9223372036854775808; do
  invalid_id_log="$tmp/invalid-account-id-${invalid_id//[^0-9]/x}.log"
  set +e
  BRIDGE_ACCOUNT_ID="$invalid_id" bash "$controller" status >"$invalid_id_log" 2>&1
  invalid_id_rc=$?
  set -e
  if (( invalid_id_rc == 0 )); then
    printf 'FAIL: invalid bridge account id %s was accepted\n' "$invalid_id" >&2
    exit 1
  fi
  assert_eq 64 "$invalid_id_rc" "invalid bridge account id $invalid_id failed with usage status"
done
grep -Fq 'BRIDGE_ACCOUNT_ID_out_of_bigint_range' "$tmp/invalid-account-id-9223372036854775808.log"

marker_phase() {
  python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['phase'])
PY
}

event_count() {
  local pattern="$1"
  grep -c -- "$pattern" "$tmp/events" 2>/dev/null || true
}

expect_controller_failure() {
  local command="$1"
  if run_controller "$command"; then
    printf 'FAIL: %s unexpectedly succeeded\n' "$command" >&2
    exit 1
  fi
}

assert_primary_not_written() {
  if grep -q '^set:7692:' "$tmp/events"; then
    printf 'FAIL: primary received an unexpected write\n' >&2
    cat "$tmp/events" >&2
    exit 1
  fi
}

# Incomplete Redis control-plane evidence never reaches a primary write.
reset_fixture
sed -i 's/^7692|\(.*\)|1$/7692|\1|2/' "$tmp/members"
expect_controller_failure prepare-maintenance
assert_eq '' "$(cat "$tmp/events")" 'shared primary caused zero account writes'
assert_eq t "$(member_schedulable 7692)" 'shared primary remained schedulable'
assert_eq f "$(member_schedulable 7693)" 'shared primary did not open standby during maintenance'

reset_fixture
sed -i 's/^7693|\(.*\)|1$/7693|\1|2/' "$tmp/members"
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
expect_controller_failure reconcile
assert_eq '' "$(cat "$tmp/events")" 'shared standby was never opened'
assert_eq f "$(member_schedulable 7693)" 'shared standby stayed unschedulable'

reset_fixture
touch "$tmp/buckets_fail"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'bucket enumeration failure left primary schedulable'
assert_primary_not_written

reset_fixture
touch "$tmp/bucket_error_7693"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'backup membership failure left primary schedulable'
assert_primary_not_written

# A primary that is active but runtime-blocked is not paused.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|t|t/7692|\1|active|t|t|f/' "$tmp/members"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'runtime-blocked primary remained schedulable'
assert_primary_not_written

# Info-level unsampled access logging is a hard evidence prerequisite. The
# controller opens standby capacity first but never changes the primary.
for logging_state in 'warn|false' 'info|true'; do
  reset_fixture
  printf '%s\n' "$logging_state" >"$tmp/runtime_logging"
  expect_controller_failure prepare-maintenance
  assert_eq t "$(member_schedulable 7692)" "logging gate $logging_state left primary schedulable"
  assert_eq t "$(member_schedulable 7693)" "logging gate $logging_state left standby open"
  assert_primary_not_written
done

# If the last standby is closed after the initial readiness proof but before the
# primary POST, the controller reopens it with a run-scoped backup request id,
# records the foreign close at the FIFO fence, and leaves the primary untouched.
reset_fixture
printf '2|13\n' >"$tmp/flip_group_on_discover_call"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'initial group replacement left primary schedulable'
assert_eq t "$(member_schedulable 7693)" 'initial group replacement retained opened standby'
assert_eq 0 "$(event_count '^set:7692:false$')" 'initial group replacement made no primary write'
test ! -e "$tmp/state/maintenance.json"

reset_fixture
printf '3\n' >"$tmp/close_backup_on_runtime_logging_call"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'pre-pause standby race left primary schedulable'
assert_eq t "$(member_schedulable 7693)" 'pre-pause standby race reopened standby'
assert_eq PREPARING "$(marker_phase)" 'pre-pause standby race retained preparing marker'
assert_eq 0 "$(event_count '^set:7692:false$')" 'pre-pause standby race made no primary write'
grep -Eq 'c2m-[a-f0-9-]{36}-b-7693' "$tmp/access_logs"
expect_controller_failure prepare-maintenance
assert_eq 0 "$(event_count '^set:7692:false$')" 'pre-pause foreign fence remained sticky on retry'

# A config rotation while PREPARING cannot retarget the marker to a new primary.
# Every entry point rejects the immutable identity before any account write.
cat >>"$tmp/members" <<EOF
7694|$(encode_name third-standby)|active|f|t|t|1
EOF
printf '2026-07-14T00:00:00.000091Z\n' >"$tmp/meta_generation_7694"
rotation_events_before="$(wc -l <"$tmp/events")"
TEST_BRIDGE_ACCOUNT_ID=7693
for rotated_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$rotated_command"
  assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" \
    "PREPARING config rotation $rotated_command made zero account writes"
done
unset TEST_BRIDGE_ACCOUNT_ID
assert_eq f "$(member_schedulable 7694)" 'PREPARING config mismatch did not guess a third standby'

# The marker boundary seals backup authorization before the primary write. An
# inactive member becoming eligible after PREPARING is never opened or adopted.
reset_fixture
TEST_FAIL_MARKER_WRITE_NUMBER=2
expect_controller_failure prepare-maintenance
unset TEST_FAIL_MARKER_WRITE_NUMBER
assert_eq PREPARING "$(marker_phase)" 'failed pause-intent CAS retained preparing marker'
assert_eq t "$(member_schedulable 7692)" 'pause-intent CAS failure left primary schedulable'
sed -i 's/7845|\([^|]*\)|inactive|f|t|f/7845|\1|active|f|t|f/' "$tmp/members"
sealed_events_before="$(wc -l <"$tmp/events")"
for sealed_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$sealed_command"
  assert_eq "$sealed_events_before" "$(wc -l <"$tmp/events")" \
    "newly eligible unsealed backup $sealed_command made zero account writes"
done
assert_eq t "$(member_schedulable 7692)" 'unsealed backup drift never paused primary'
assert_eq f "$(member_schedulable 7845)" 'unsealed backup drift never opened new backup'
grep -Fq 'unsealed_backup_became_eligible' "$tmp/controller.log"

# Transient group, inventory, primary-API, and foreign-log reads inside the
# drain loop reset the zero-sample streak but recover within the drain budget.
reset_fixture
touch "$tmp/fail_group_once_after_primary_paused" \
  "$tmp/fail_list_once_after_primary_paused" \
  "$tmp/fail_get_once_after_primary_paused" \
  "$tmp/fail_foreign_once_after_primary_paused"
TEST_DRAIN_TIMEOUT_SECONDS=12
run_controller prepare-maintenance
unset TEST_DRAIN_TIMEOUT_SECONDS
assert_eq OWNED "$(marker_phase)" 'transient drain reads recovered within deadline'
test ! -e "$tmp/state/maintenance-ambiguous.json"
run_controller finish-maintenance

# Read-side receipt outages preserve the exact write-ahead INTENT and never
# replay a primary mutation. The original durable receipt is adopted on retry.
reset_fixture
touch "$tmp/fail_next_receipt_record"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_INTENT "$(marker_phase)" 'pause receipt read outage kept pause intent'
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['pause_response_checkpoint'] == 'validated'
assert p['pause_response_updated_at']
PY
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 1 "$(event_count '^set:7692:false$')" 'pause receipt outage issued one pause only'
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'pause intent retry adopted exact receipt and reached owned'
assert_eq 2 "$(event_count '^set:7692:false$')" 'pause intent retry did not replay pause'
run_controller finish-maintenance

reset_fixture
touch "$tmp/fail_next_seal_receipt_record"
expect_controller_failure prepare-maintenance
assert_eq SEAL_INTENT "$(marker_phase)" 'seal receipt read outage kept seal intent'
test ! -e "$tmp/state/maintenance-ambiguous.json"
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['seal_response_updated_at']
PY
assert_eq 2 "$(event_count '^set:7692:false$')" 'seal receipt outage issued pause plus one seal'
assert_eq 1 "$(awk -F '|' '$2 ~ /-seal$/ && $3=="200" && \
  $4=="/api/v1/admin/accounts/7692/schedulable" && $5=="POST" {n++} \
  END {print n+0}' "$tmp/access_logs")" 'seal receipt outage logged exactly one seal write'
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'seal intent retry adopted exact receipt and reached owned'
assert_eq 2 "$(event_count '^set:7692:false$')" 'seal intent retry did not replay seal'
assert_eq 1 "$(awk -F '|' '$2 ~ /-seal$/ && $3=="200" && \
  $4=="/api/v1/admin/accounts/7692/schedulable" && $5=="POST" {n++} \
  END {print n+0}' "$tmp/access_logs")" 'seal intent retry retained exactly one seal write'
run_controller finish-maintenance

reset_fixture
touch "$tmp/primary_busy"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_ACKED "$(marker_phase)" 'busy drain timeout remained retryable pause acknowledged'
test ! -e "$tmp/state/maintenance-ambiguous.json"
pause_acked_hash="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
touch "$tmp/malformed_next_get_account"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_ACKED "$(marker_phase)" 'malformed primary GET kept pause acknowledged'
assert_eq "$pause_acked_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'malformed primary GET left pause marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
touch "$tmp/fail_next_runtime_logging"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_ACKED "$(marker_phase)" 'runtime logging read outage kept pause acknowledged'
assert_eq "$pause_acked_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'runtime logging read outage left marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
touch "$tmp/fail_next_receipt_record"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_ACKED "$(marker_phase)" 'receipt query failure kept pause acknowledged'
assert_eq "$pause_acked_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'receipt query failure left marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
touch "$tmp/full_account_error_7692"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_ACKED "$(marker_phase)" 'snapshot read failure kept pause acknowledged'
assert_eq "$pause_acked_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'snapshot read failure left marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
rm -f "$tmp/full_account_error_7692"
rm -f "$tmp/primary_busy"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'busy drain retry reached owned without new pause'
run_controller finish-maintenance

for recorded_receipt_case in missing duplicate non200 wrong-log-id; do
  reset_fixture
  touch "$tmp/primary_busy"
  expect_controller_failure prepare-maintenance
  rm -f "$tmp/primary_busy"
  python3 - "$tmp/state/maintenance.json" "$tmp/access_logs" "$recorded_receipt_case" <<'PY'
import json,sys
marker_path,logs_path,case=sys.argv[1:]
p=json.load(open(marker_path,encoding='utf-8'))
rid=p['pause_request_id']
rows=[line.rstrip('\n').split('|') for line in open(logs_path,encoding='utf-8')]
matches=[i for i,row in enumerate(rows) if len(row)>2 and row[1]==rid]
assert len(matches)==1
i=matches[0]
if case=='missing':
    rows.pop(i)
elif case=='duplicate':
    duplicate=rows[i].copy()
    duplicate[0]=str(max(int(row[0]) for row in rows)+1)
    rows.append(duplicate)
elif case=='non200':
    rows[i][2]='500'
elif case=='wrong-log-id':
    rows[i][0]=str(int(rows[i][0])+1000)
else:
    raise AssertionError(case)
open(logs_path,'w',encoding='utf-8').write('\n'.join('|'.join(row) for row in rows)+'\n')
PY
  expect_controller_failure prepare-maintenance
  assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" \
    "recorded receipt $recorded_receipt_case became definitive conflict"
  test -s "$tmp/state/maintenance-ambiguous.json"
done

reset_fixture
touch "$tmp/flip_group_on_first_drain"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" 'drain-time group replacement became ambiguous'
assert_eq f "$(member_schedulable 7692)" 'drain-time group replacement kept old primary paused'
assert_eq t "$(member_schedulable 7693)" 'drain-time group replacement kept standby open'
test -s "$tmp/state/maintenance-ambiguous.json"

reset_fixture
touch "$tmp/share_primary_on_first_drain"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" 'primary added to a second active group became ambiguous after pause'
assert_eq f "$(member_schedulable 7692)" 'shared-during-drain primary remained paused'
assert_eq t "$(member_schedulable 7693)" 'shared-during-drain standby remained open'
test -s "$tmp/state/maintenance-ambiguous.json"

reset_fixture
touch "$tmp/close_backup_on_first_drain"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" 'drain-time standby loss became ambiguous'
assert_eq t "$(member_schedulable 7693)" 'drain-time standby loss was reopened'
test -s "$tmp/state/maintenance-ambiguous.json"

# Normal prepare establishes two exact primary receipts: pause then idempotent
# ownership seal. Continuous unrelated access traffic must not block the FIFO
# sentinel fence or produce a false foreign-mutation finding.
reset_fixture
printf '3\n' >"$tmp/background_access_per_sentinel"
run_controller prepare-maintenance
assert_eq t "$(member_schedulable 7693)" 'maintenance opened dynamic standby first'
assert_eq f "$(member_schedulable 7692)" 'maintenance paused primary'
assert_eq 2 "$(event_count '^set:7692:false$')" 'prepare issued exactly pause plus seal'
python3 - "$tmp/state/maintenance.json" <<'PY'
import hashlib,json,re,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['schema_version'] == 7
assert p['primary_account_id'] == 7692
assert p['group_id'] == 12
assert p['group_member_ids'] == [7692,7693,7845,7850]
assert p['backup_account_ids'] == [7693]
identity={key:p[key] for key in (
  'schema_version','run_id','primary_account_id','group_id','group_member_ids',
  'backup_account_ids','log_watermark','sub2_incarnation','sink_dropped_base',
  'sink_failed_base','sink_written_base',
)}
canonical=json.dumps(identity,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
assert p['identity_digest'] == hashlib.sha256(canonical).hexdigest()
assert p['pause_response_checkpoint'] == 'validated'
assert p['pause_response_updated_at']
assert p['restore_response_checkpoint'] == 'none'
assert p['restore_response_updated_at'] is None
assert p['phase'] == 'OWNED'
assert p['primary_disabled_by_maintenance'] is True
for kind in ('pause','seal'):
    rid=p[f'{kind}_request_id']
    assert re.fullmatch(rf'codex2api-maint-[a-f0-9-]{{36}}-{kind}',rid)
    assert 0 < len(rid) <= 64
    assert isinstance(p[f'{kind}_log_id'],int) and p[f'{kind}_log_id'] > p['log_watermark']
assert p['seal_response_updated_at'] == p['owned_updated_at']
assert str(p['owned_xmin']).isdigit()
assert p['sink_dropped_base'] == 0
assert p['sink_failed_base'] == 0
PY
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'finish restored owned primary'
assert_eq 1 "$(event_count '^set:7692:true$')" 'finish issued exactly one restore'
assert_eq 3 "$(<"$tmp/receipted_call_count")" 'normal run used pause seal restore'
test ! -e "$tmp/state/maintenance.json"
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_no_forbidden_writes

# An OWNED marker is bound to the original primary and group. Rotating the
# configured id cannot restore the old primary, pause the new one, or open a
# third account under the wrong ownership generation.
reset_fixture
cat >>"$tmp/members" <<EOF
7694|$(encode_name third-owned-standby)|active|f|t|t|1
EOF
printf '2026-07-14T00:00:00.000091Z\n' >"$tmp/meta_generation_7694"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'rotation fixture reached owned'
rotation_events_before="$(wc -l <"$tmp/events")"
TEST_BRIDGE_ACCOUNT_ID=7693
for rotated_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$rotated_command"
  assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" \
    "OWNED config rotation $rotated_command made zero account writes"
done
unset TEST_BRIDGE_ACCOUNT_ID
assert_eq f "$(member_schedulable 7692)" 'OWNED mismatch did not restore old primary'
assert_eq t "$(member_schedulable 7693)" 'OWNED mismatch did not pause newly configured primary'
assert_eq t "$(member_schedulable 7694)" 'third standby was opened by original maintenance preparation only'

# The sealed full membership is part of marker identity, not advisory metadata.
# A syntactically valid but changed set cannot be adopted by a later process.
reset_fixture
run_controller prepare-maintenance
identity_events_before="$(wc -l <"$tmp/events")"
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,os,sys,tempfile
path=sys.argv[1]
p=json.load(open(path,encoding='utf-8'))
p['group_member_ids']=[7692,7693,7845]
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='maintenance-tamper.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    json.dump(p,f,sort_keys=True)
    f.write('\n')
os.replace(tmp,path)
PY
expect_controller_failure status
assert_eq "$identity_events_before" "$(wc -l <"$tmp/events")" \
  'changed sealed member identity made zero account writes'
expect_controller_failure finish-maintenance
assert_eq "$identity_events_before" "$(wc -l <"$tmp/events")" \
  'changed sealed member identity could not restore primary'

# Transient group discovery or membership reads never poison an otherwise valid
# OWNED artifact. status is strictly read-only and finish can be retried.
reset_fixture
run_controller prepare-maintenance
owned_hash="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
owned_events="$(wc -l <"$tmp/events")"
discover_calls="$(<"$tmp/discover_group_count")"
printf '%s\n' "$((discover_calls + 2))" >"$tmp/fail_group_on_discover_call"
expect_controller_failure finish-maintenance
assert_eq "$owned_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'transient group query left owned marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq "$owned_events" "$(wc -l <"$tmp/events")" 'transient group query made zero account writes'
touch "$tmp/fail_next_list_members"
expect_controller_failure status
assert_eq "$owned_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'transient status membership read left owned marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq "$owned_events" "$(wc -l <"$tmp/events")" 'transient status read made zero account writes'
run_controller finish-maintenance
# A timer may reopen a sealed standby to preserve service after marker creation,
# but that post-watermark write has no receipt manifest in the marker. It is
# therefore never guessed as controller-owned and later ownership fails closed.
reset_fixture
run_controller prepare-maintenance
sed -i 's/7693|\([^|]*\)|active|t|t|t/7693|\1|active|f|t|t/' "$tmp/members"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'timer reopened maintenance standby'
grep -Eq 'c2m-[a-f0-9-]{36}-b-7693' "$tmp/access_logs"
expect_controller_failure finish-maintenance
assert_eq f "$(member_schedulable 7692)" 'post-watermark backup reopen did not authorize restore'
test -s "$tmp/state/maintenance-ambiguous.json"
grep -Fq 'foreign_admin_mutation_confirmed_after_ownership' "$tmp/controller.log"

# A marker-present controller may use only its sealed backup collection. A
# formerly inactive member becoming eligible blocks every entry point before
# either the primary or any backup is written.
reset_fixture
run_controller prepare-maintenance
sed -i 's/7845|\([^|]*\)|inactive|f|t|f/7845|\1|active|f|t|f/' "$tmp/members"
sealed_events_before="$(wc -l <"$tmp/events")"
for sealed_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$sealed_command"
  assert_eq "$sealed_events_before" "$(wc -l <"$tmp/events")" \
    "owned unsealed backup $sealed_command made zero account writes"
done
assert_eq f "$(member_schedulable 7692)" 'owned primary remained paused on unsealed drift'
assert_eq t "$(member_schedulable 7693)" 'sealed backup remained untouched on unsealed drift'
assert_eq f "$(member_schedulable 7845)" 'new unsealed backup was never opened'
grep -Fq 'unsealed_backup_became_eligible' "$tmp/controller.log"

# An externally opened, newly eligible member is not adopted and is not closed.
# The external write is outside the captured authorization collection.
reset_fixture
run_controller prepare-maintenance
sed -i 's/7845|\([^|]*\)|inactive|f|t|f/7845|\1|active|f|t|f/' "$tmp/members"
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 \
  "$backend" set-schedulable-receipted 7845 true external-new-eligible >/dev/null
sealed_events_before="$(wc -l <"$tmp/events")"
for sealed_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$sealed_command"
  assert_eq "$sealed_events_before" "$(wc -l <"$tmp/events")" \
    "externally opened unsealed backup $sealed_command made zero controller writes"
done
assert_eq f "$(member_schedulable 7692)" 'external unsealed backup never authorized restore'
assert_eq t "$(member_schedulable 7845)" 'controller did not close external unsealed backup'

# A primary that was already paused is never adopted or actively restored. The
# marker and standby remain until an external actor restores it.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|t|t/7692|\1|active|f|t|t/' "$tmp/members"
run_controller prepare-maintenance
assert_eq EXTERNAL_PAUSED "$(marker_phase)" 'external pause recorded without ownership'
assert_eq 0 "$(<"$tmp/receipted_call_count")" 'external pause caused no owned request'
expect_controller_failure finish-maintenance
test -e "$tmp/state/maintenance.json"
assert_eq t "$(member_schedulable 7693)" 'external pause held standby open'
grep -Fq 'external_primary_pause_preserved_backups_held_operator_action_required' "$tmp/controller.log"
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 "$backend" set-schedulable 7692 true >/dev/null
run_controller finish-maintenance
test ! -e "$tmp/state/maintenance.json"
assert_eq 0 "$(<"$tmp/receipted_call_count")" 'controller did not restore external pause itself'

# EXTERNAL_PAUSED is identity-bound as well. A later config rotation is not
# interpreted as permission to adopt either primary.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|t|t/7692|\1|active|f|t|t/' "$tmp/members"
cat >>"$tmp/members" <<EOF
7694|$(encode_name third-external-standby)|active|f|t|t|1
EOF
printf '2026-07-14T00:00:00.000091Z\n' >"$tmp/meta_generation_7694"
run_controller prepare-maintenance
assert_eq EXTERNAL_PAUSED "$(marker_phase)" 'rotation fixture reached external paused'
rotation_events_before="$(wc -l <"$tmp/events")"
TEST_BRIDGE_ACCOUNT_ID=7693
for rotated_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$rotated_command"
  assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" \
    "EXTERNAL_PAUSED config rotation $rotated_command made zero account writes"
done
unset TEST_BRIDGE_ACCOUNT_ID
assert_eq f "$(member_schedulable 7692)" 'external mismatch did not restore old primary'
assert_eq t "$(member_schedulable 7693)" 'external mismatch did not pause newly configured primary'
assert_eq t "$(member_schedulable 7694)" 'third standby was opened by original external preparation only'

# A transport/non-200 pause result is never auto-adopted from its receipt. The
# durable checkpoint and sidecar keep the applied outcome sticky without replay.
reset_fixture
printf '1\n' >"$tmp/apply_then_fail_on_receipted_call"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" 'pause transport result became sticky ambiguity'
test -s "$tmp/state/maintenance-ambiguous.json"
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['pause_response_checkpoint'] == 'transport_or_non200'
assert p['pause_response_updated_at'] is None
PY
assert_eq 1 "$(event_count '^set:7692:false$')" 'pause transport result was submitted once'
expect_controller_failure prepare-maintenance
assert_eq 1 "$(event_count '^set:7692:false$')" 'pause transport ambiguity was not replayed'

# Missing, dropped, failed, duplicate, or non-200 receipts fail closed and leave
# the standby open. No case can become OWNED.
for receipt_case in missing dropped failed duplicate non200; do
  reset_fixture
  case "$receipt_case" in
    missing) touch "$tmp/omit_next_receipt_clean" ;;
    dropped) touch "$tmp/drop_next_receipt" ;;
    failed) touch "$tmp/fail_next_receipt" ;;
    duplicate) touch "$tmp/duplicate_next_receipt" ;;
    non200) printf '500\n' >"$tmp/receipt_status_override" ;;
  esac
  expect_controller_failure prepare-maintenance
  assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" "$receipt_case receipt became ambiguous"
  test -s "$tmp/state/maintenance-ambiguous.json"
  assert_eq f "$(member_schedulable 7692)" "$receipt_case may have paused primary"
  assert_eq t "$(member_schedulable 7693)" "$receipt_case kept standby open"
  if grep -q '"reason":"maintenance_ready"' "$tmp/controller.log"; then
    printf 'FAIL: %s receipt emitted maintenance_ready\n' "$receipt_case" >&2
    exit 1
  fi
done

# A malformed synchronous HTTP 200 cannot be rescued by an access receipt.
for bad_response in invalid-json wrong-id wrong-desired missing-generation; do
  reset_fixture
  printf '%s\n' "$bad_response" >"$tmp/bad_primary_response"
  expect_controller_failure prepare-maintenance
  assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" "bad response $bad_response became ambiguous"
  test -s "$tmp/state/maintenance-ambiguous.json"
  assert_eq 1 "$(<"$tmp/receipted_call_count")" "bad response $bad_response stopped before seal"
done
# A crash after a valid HTTP body was parsed but before the durable checkpoint
# leaves PAUSE_INTENT=pending. A later process poisons first and never adopts the
# receipt or replays the request.
reset_fixture
TEST_RESPONSE_BARRIER_PREFIX="$tmp/response-barrier"
start_controller_background prepare-maintenance
wait_for_marker "$tmp/response-barrier.pause.reached" "$CONTROLLER_PID" 8
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['phase'] == 'PAUSE_INTENT'
assert p['pause_response_checkpoint'] == 'pending'
assert p['pause_response_updated_at'] is None
PY
kill -KILL "$CONTROLLER_PID" 2>/dev/null || true
set +e
wait "$CONTROLLER_PID" 2>/dev/null
set -e
unset TEST_RESPONSE_BARRIER_PREFIX
pause_calls_before="$(event_count '^set:7692:false$')"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" \
  'pause response/checkpoint crash gap became sticky ambiguity'
assert_eq "$pause_calls_before" "$(event_count '^set:7692:false$')" \
  'pause response/checkpoint crash gap did not replay request'
test -s "$tmp/state/maintenance-ambiguous.json"


# If the PAUSE_ACKED marker fsync/readback fails after the API receipt, the
# durable PAUSE_INTENT is resumed by the same request id with no duplicate call.
reset_fixture
TEST_FAIL_MARKER_WRITE_NUMBER=4
expect_controller_failure prepare-maintenance
unset TEST_FAIL_MARKER_WRITE_NUMBER
assert_eq PAUSE_INTENT "$(marker_phase)" 'failed ACK persistence retained pause intent'
assert_eq 1 "$(<"$tmp/receipted_call_count")" 'pause was submitted once before ACK failure'
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'retry recovered exact pause receipt then sealed'
assert_eq 2 "$(<"$tmp/receipted_call_count")" 'retry added only seal request'
run_controller finish-maintenance

# If persisting PAUSE_AMBIGUOUS itself fails, the independently fsynced poison
# sidecar prevents a later process from recovering the still-INTENT marker.
reset_fixture
printf 'invalid-json\n' >"$tmp/bad_primary_response"
TEST_FAIL_MARKER_WRITE_NUMBER=4
expect_controller_failure prepare-maintenance
unset TEST_FAIL_MARKER_WRITE_NUMBER
assert_eq PAUSE_INTENT "$(marker_phase)" 'main marker stayed intent after injected ambiguity write failure'
test -s "$tmp/state/maintenance-ambiguous.json"
calls_before="$(<"$tmp/receipted_call_count")"
expect_controller_failure prepare-maintenance
assert_eq "$calls_before" "$(<"$tmp/receipted_call_count")" 'poison sidecar prevented request replay'
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'sidecar made reconcile hold standby'

# A seal transport error remains ambiguous even when its access receipt exists:
# ownership requires a normal validated synchronous seal response as well.
reset_fixture
printf '2\n' >"$tmp/apply_then_fail_on_receipted_call"
expect_controller_failure prepare-maintenance
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" 'unknown seal outcome became ambiguous'
assert_eq 2 "$(event_count '^set:7692:false$')" 'seal unknown was not retried'
test -s "$tmp/state/maintenance-ambiguous.json"

# A pre-pause foreign-log read outage is retryable because no primary write was
# issued. It keeps PREPARING and can continue once the exact window is readable.
reset_fixture
touch "$tmp/fail_next_foreign_mutation_query"
expect_controller_failure prepare-maintenance
assert_eq PREPARING "$(marker_phase)" 'pre-pause foreign read outage kept PREPARING'
assert_eq 0 "$(event_count '^set:7692:false$')" \
  'pre-pause foreign read outage made zero controller primary writes'
assert_eq t "$(member_schedulable 7693)" \
  'pre-pause foreign read outage kept standby protection open'
test ! -e "$tmp/state/maintenance-ambiguous.json"
grep -Fq '"reason":"foreign_mutation_fence_temporarily_unverifiable_before_primary_pause"' \
  "$tmp/controller.log"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'pre-pause foreign read retry reached OWNED'
run_controller finish-maintenance

# The known today-stats POST is read-only despite its method.
reset_fixture
touch "$tmp/inject_foreign_before_sentinel_once"
printf 'POST\n' >"$tmp/foreign_before_sentinel_method"
printf '/api/v1/admin/accounts/today-stats/batch\n' >"$tmp/foreign_before_sentinel_path"
printf 'harmless-before-fence\n' >"$tmp/foreign_before_sentinel_request_id"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'read-only today-stats did not poison ownership'
test ! -e "$tmp/state/maintenance-ambiguous.json"
run_controller finish-maintenance

# Account deletion can cascade account_groups before the access receipt is
# queried.  The marker's sealed full member set still fences that former member
# even though it has disappeared from the current inventory.
reset_fixture
touch "$tmp/inject_foreign_before_sentinel_once"
printf 'DELETE\n' >"$tmp/foreign_before_sentinel_method"
printf '/api/v1/admin/accounts/7693\n' >"$tmp/foreign_before_sentinel_path"
printf '7693\n' >"$tmp/remove_member_before_foreign_sentinel"
printf 'former-member-delete\n' >"$tmp/foreign_before_sentinel_request_id"
expect_controller_failure prepare-maintenance
assert_eq PREPARING "$(marker_phase)" 'cascaded former-member delete remained fenced'
assert_eq 0 "$(event_count '^set:7692:false$')" \
  'cascaded former-member delete caused no primary write'
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['schema_version'] == 7
assert p['group_member_ids'] == [7692,7693,7845,7850]
assert p['backup_account_ids'] == [7693]
assert len(p['identity_digest']) == 64
PY

# Conversely, a newly added live member is protected by the current inventory
# even though it was not present in the immutable marker set.
reset_fixture
touch "$tmp/inject_foreign_before_sentinel_once"
printf 'PUT\n' >"$tmp/foreign_before_sentinel_method"
printf '/api/v1/admin/accounts/9004\n' >"$tmp/foreign_before_sentinel_path"
printf 'new-member-update\n' >"$tmp/foreign_before_sentinel_request_id"
printf '9004|%s|active|f|t|t|1\n' "$(encode_name newly-added)" \
  >"$tmp/add_member_before_foreign_sentinel"
expect_controller_failure prepare-maintenance
assert_eq PREPARING "$(marker_phase)" 'new live member update remained fenced'
assert_eq 0 "$(event_count '^set:7692:false$')" \
  'new live member update caused no primary write'

# Every account-item mutation is fail-closed, including an apparently unrelated
# dynamic id: endpoint access logs cannot prove that the account was not added
# and removed again inside the same fence window. Bulk and group writes are
# equally protected. Each is stopped before the primary pause.
while IFS='|' read -r protected_method protected_path; do
  reset_fixture
  touch "$tmp/inject_foreign_before_sentinel_once"
  printf '%s\n' "$protected_method" >"$tmp/foreign_before_sentinel_method"
  printf '%s\n' "$protected_path" >"$tmp/foreign_before_sentinel_path"
  printf 'protected-before-fence\n' >"$tmp/foreign_before_sentinel_request_id"
  expect_controller_failure prepare-maintenance
  assert_eq PREPARING "$(marker_phase)" \
    "protected $protected_method $protected_path remained fenced"
  assert_eq 0 "$(event_count '^set:7692:false$')" \
    "protected $protected_method $protected_path caused no primary write"
  assert_eq t "$(member_schedulable 7692)" \
    "protected $protected_method $protected_path left primary schedulable"
  assert_eq t "$(member_schedulable 7693)" \
    "protected $protected_method $protected_path kept standby protection"
  test ! -e "$tmp/state/maintenance-ambiguous.json"
done <<'EOF'
PUT|/api/v1/admin/accounts/7692
DELETE|/api/v1/admin/accounts/7693
PUT|/api/v1/admin/accounts/9001
PATCH|/api/v1/admin/accounts/9002
DELETE|/api/v1/admin/accounts/9003
POST|/api/v1/admin/accounts/bulk-update
PUT|/api/v1/admin/groups/12
POST|/api/v1/admin/groups/12/accounts/9004
EOF

# The sentinel catches any prior admin mutation, including log cleanup and an
# unknown future endpoint. Even a canonical non-primary schedulable POST is
# foreign after the watermark; a c2m-shaped request id is never ownership proof.
for foreign_path in \
  '/api/v1/admin/accounts/7692/schedulable' \
  '/api/v1/admin/accounts/07692/schedulable' \
  '/api/v1/admin/accounts/+7692/schedulable' \
  '/api/v1/admin/accounts/9999/schedulable' \
  '/api/v1/admin/accounts/9223372036854775807/schedulable' \
  '/api/v1/admin/accounts/9223372036854775808/schedulable' \
  '/api/v1/admin/accounts/123456789012345678901/schedulable' \
  '/api/v1/admin/ops/system-logs/cleanup' \
  '/api/v1/admin/future/mutate'; do
  reset_fixture
  touch "$tmp/inject_foreign_before_sentinel_once"
  printf '%s\n' "$foreign_path" >"$tmp/foreign_before_sentinel_path"
  printf 'foreign-before-fence\n' >"$tmp/foreign_before_sentinel_request_id"
  expect_controller_failure prepare-maintenance
  assert_eq PREPARING "$(marker_phase)" "foreign path $foreign_path stopped before primary pause"
  assert_eq 0 "$(event_count '^set:7692:false$')" \
    "foreign path $foreign_path caused no controller primary write"
  assert_eq t "$(member_schedulable 7692)" \
    "foreign path $foreign_path left fixture primary at its original tuple"
  assert_eq t "$(member_schedulable 7693)" \
    "foreign path $foreign_path left standby protection open"
  test ! -e "$tmp/state/maintenance-ambiguous.json"
  expect_controller_failure prepare-maintenance
  assert_eq PREPARING "$(marker_phase)" \
    "foreign path $foreign_path remained a manual PREPARING fence on retry"
  assert_eq 0 "$(event_count '^set:7692:false$')" \
    "foreign path $foreign_path retry still made zero controller primary writes"
  assert_eq t "$(member_schedulable 7693)" \
    "foreign path $foreign_path retry kept standby protection open"
  test ! -e "$tmp/state/maintenance-ambiguous.json"
  python3 - "$tmp/state/maintenance.json" "$tmp/access_logs" \
    "$tmp/controller.log" "$foreign_path" <<'PY'
import json,sys
marker_path,logs_path,controller_log,expected_path=sys.argv[1:]
marker=json.load(open(marker_path,encoding='utf-8'))
rows=[line.rstrip('\n').split('|') for line in open(logs_path,encoding='utf-8')]
matches=[i for i,row in enumerate(rows)
         if len(row)>=7 and row[1]=='foreign-before-fence']
assert len(matches)==1
i=matches[0]
foreign=rows[i]
assert foreign[2:] == ['200',expected_path,'POST','http.access','http request completed']
assert int(foreign[0]) > marker['log_watermark']
assert i+1 < len(rows)
sentinel=rows[i+1]
assert int(sentinel[0]) == int(foreign[0])+1
assert sentinel[2:] == ['200','/api/v1/admin/ops/system-logs/health','GET',
                       'http.access','http request completed']
events=[]
for line in open(controller_log,encoding='utf-8'):
    try:
        event=json.loads(line)
    except Exception:
        continue
    if event.get('reason') == 'foreign_admin_mutation_before_primary_pause_primary_unchanged':
        events.append(event)
assert len(events)>=2
for event in events[-2:]:
    assert event['details'] == {
      'operator_action_required':True,
      'manual_marker_rebase_required':True,
      'primary_writes':0,
      'phase':'PREPARING',
      'backups_left_open':True,
    }
PY
done

# A structurally valid completed 4xx admin request is a confirmed rejection,
# not a confirmed mutation. It remains auditable but does not poison ownership.
reset_fixture
touch "$tmp/inject_foreign_before_sentinel_once"
printf '/api/v1/admin/future/mutate\n' >"$tmp/foreign_before_sentinel_path"
printf '400\n' >"$tmp/foreign_before_sentinel_status"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'rejected foreign admin request did not poison ownership'
test ! -e "$tmp/state/maintenance-ambiguous.json"
run_controller finish-maintenance

# Reusing an owned high-entropy request id on a bulk endpoint never inherits the
# primary schedulable exemption.
reset_fixture
run_controller prepare-maintenance
python3 - "$tmp/state/maintenance.json" "$tmp/foreign_before_sentinel_request_id" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
open(sys.argv[2],'w',encoding='utf-8').write(p['pause_request_id']+'\n')
PY
touch "$tmp/inject_foreign_before_sentinel_once"
printf '/api/v1/admin/accounts/bulk-update\n' >"$tmp/foreign_before_sentinel_path"
expect_controller_failure finish-maintenance
assert_eq 0 "$(event_count '^set:7692:true$')" 'owned id reuse on bulk did not restore primary'
test -e "$tmp/state/maintenance.json"
# Exact request ids are insufficient authority. A second primary receipt with
# the same request id but a different log id (successful or 5xx) is foreign.
for replay_status in 200 500; do
  reset_fixture
  run_controller prepare-maintenance
  python3 - "$tmp/state/maintenance.json" "$tmp/foreign_before_sentinel_request_id" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
open(sys.argv[2],'w',encoding='utf-8').write(p['pause_request_id']+'\n')
PY
  touch "$tmp/inject_foreign_before_sentinel_once"
  printf '/api/v1/admin/accounts/7692/schedulable\n' >"$tmp/foreign_before_sentinel_path"
  printf '%s\n' "$replay_status" >"$tmp/foreign_before_sentinel_status"
  expect_controller_failure finish-maintenance
  assert_eq 0 "$(event_count '^set:7692:true$')" \
    "primary request-id replay ${replay_status} did not restore primary"
  grep -Fq 'foreign_admin_mutation_confirmed_after_ownership' "$tmp/controller.log"
done

# Post-watermark backup writes are never inferred as controller-owned from a
# c2m request-id pattern. This applies to both sealed and unsealed account ids.
for replay_backup_id in 7693 7845; do
  reset_fixture
  run_controller prepare-maintenance
  python3 - "$tmp/state/maintenance.json" "$tmp/foreign_before_sentinel_request_id" \
    "$replay_backup_id" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
open(sys.argv[2],'w',encoding='utf-8').write(
    f'c2m-{p["run_id"]}-b-{sys.argv[3]}\n')
PY
  touch "$tmp/inject_foreign_before_sentinel_once"
  printf '/api/v1/admin/accounts/%s/schedulable\n' "$replay_backup_id" \
    >"$tmp/foreign_before_sentinel_path"
  expect_controller_failure finish-maintenance
  assert_eq 0 "$(event_count '^set:7692:true$')" \
    "backup c2m replay ${replay_backup_id} did not restore primary"
  grep -Fq 'foreign_admin_mutation_confirmed_after_ownership' "$tmp/controller.log"
done

# A true->false external ABA leaves the visible primary state unchanged but
# changes its database generation and remains a definitive ownership conflict.
reset_fixture
run_controller prepare-maintenance
touch "$tmp/allow_external_primary_write"
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 FAILOVER_STATE_DIR="$tmp/state" \
  "$backend" set-schedulable-receipted 7692 true external-aba-open >/dev/null
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 FAILOVER_STATE_DIR="$tmp/state" \
  "$backend" set-schedulable-receipted 7692 false external-aba-close >/dev/null
aba_true_writes_before="$(event_count '^set:7692:true$')"
expect_controller_failure finish-maintenance
assert_eq "$aba_true_writes_before" "$(event_count '^set:7692:true$')" \
  'external ABA did not trigger a controller restore'
assert_eq f "$(member_schedulable 7692)" 'external ABA ended at the original visible state'
test -s "$tmp/state/maintenance-ambiguous.json"


# Sink loss/failure, sub2 process reincarnation, and a changed DB/full-cache
# control tuple invalidate ownership before any restore request.
reset_fixture
run_controller prepare-maintenance
printf '1\n' >"$tmp/sink_dropped"
printf '1\n' >"$tmp/sink_failed"
expect_controller_failure finish-maintenance
assert_eq 0 "$(event_count '^set:7692:true$')" 'sink counter change blocked restore'
test -s "$tmp/state/maintenance-ambiguous.json"

reset_fixture
run_controller prepare-maintenance
printf 'fake-sub2-container-2@2026-07-14T01:00:00Z\n' >"$tmp/incarnation"
expect_controller_failure finish-maintenance
assert_eq 0 "$(event_count '^set:7692:true$')" 'sub2 incarnation change blocked restore'
test -s "$tmp/state/maintenance-ambiguous.json"

reset_fixture
run_controller prepare-maintenance
owned_hash="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
touch "$tmp/malformed_next_get_account"
expect_controller_failure finish-maintenance
assert_eq OWNED "$(marker_phase)" 'malformed primary GET kept owned phase'
assert_eq "$owned_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'malformed primary GET left owned marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 0 "$(event_count '^set:7692:true$')" 'malformed primary GET made no restore write'
run_controller finish-maintenance

reset_fixture
run_controller prepare-maintenance
owned_hash="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
touch "$tmp/fail_next_primary_snapshot"
expect_controller_failure finish-maintenance
assert_eq OWNED "$(marker_phase)" 'primary tuple query outage kept owned phase'
assert_eq "$owned_hash" "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
  'primary tuple query outage left marker byte-identical'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 0 "$(event_count '^set:7692:true$')" 'primary tuple query outage made no restore write'
run_controller finish-maintenance

reset_fixture
run_controller prepare-maintenance
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 "$backend" bump-primary-tuple 7692
expect_controller_failure finish-maintenance
assert_eq 0 "$(event_count '^set:7692:true$')" 'DB tuple change blocked restore'
assert_eq OWNED "$(marker_phase)" 'DB tuple conflict retained owned marker under poison sidecar'
test -s "$tmp/state/maintenance-ambiguous.json"
grep -Fq 'owned_primary_tuple_definitive_conflict' "$tmp/controller.log"

reset_fixture
run_controller prepare-maintenance
printf '2\n' >"$tmp/bump_xmin_on_snapshot_call"
expect_controller_failure finish-maintenance
assert_eq 0 "$(event_count '^set:7692:true$')" 'second ownership tuple fence change blocked restore'
assert_eq OWNED "$(marker_phase)" 'second tuple fence conflict retained owned marker'
test -s "$tmp/state/maintenance-ambiguous.json"
grep -Fq 'owned_primary_tuple_definitive_conflict' "$tmp/controller.log"

# If the first scheduler confirmation changes the authoritative DB tuple after
# it was fenced, the post-mismatch DB re-read makes the ambiguity sticky.
reset_fixture
printf '2\n' >"$tmp/bump_generation_on_full_account_call"
expect_controller_failure prepare-maintenance
assert_eq '2|SEAL_ACKED' "$(<"$tmp/full_account_injection_phase")" \
  'first scheduler confirmation injected during seal acknowledged'
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" \
  'first scheduler confirmation DB tuple change became ambiguous'
test -s "$tmp/state/maintenance-ambiguous.json"
primary_posts_before="$(event_count '^set:7692:false$')"
expect_controller_failure prepare-maintenance
assert_eq "$primary_posts_before" "$(event_count '^set:7692:false$')" \
  'sticky first scheduler confirmation ambiguity made zero extra primary POSTs'

# The same fence applies to a DB tuple change injected only during the second
# scheduler confirmation, after the first confirmation had succeeded.
reset_fixture
printf '3\n' >"$tmp/bump_generation_on_full_account_call"
expect_controller_failure prepare-maintenance
assert_eq '3|SEAL_ACKED' "$(<"$tmp/full_account_injection_phase")" \
  'second scheduler confirmation injected during seal acknowledged'
assert_eq PAUSE_AMBIGUOUS "$(marker_phase)" \
  'second scheduler confirmation DB tuple change became ambiguous'
test -s "$tmp/state/maintenance-ambiguous.json"
primary_posts_before="$(event_count '^set:7692:false$')"
expect_controller_failure prepare-maintenance
assert_eq "$primary_posts_before" "$(event_count '^set:7692:false$')" \
  'sticky second scheduler confirmation ambiguity made zero extra primary POSTs'

# A cache-only generation mismatch with the exact seal DB tuple still intact is
# propagation uncertainty, not proof of a competing database write. It remains
# retryable at SEAL_ACKED and can complete after the projection converges.
reset_fixture
printf '2\n' >"$tmp/bump_cache_generation_on_full_account_call"
expect_controller_failure prepare-maintenance
assert_eq '2|SEAL_ACKED' "$(<"$tmp/full_account_injection_phase")" \
  'cache-only mismatch injected during seal acknowledged'
assert_eq SEAL_ACKED "$(marker_phase)" 'cache-only generation mismatch kept seal acknowledged'
test ! -e "$tmp/state/maintenance-ambiguous.json"
rm -f "$tmp/bump_cache_generation_on_full_account_call" \
  "$tmp/full_account_call_count" "$tmp/cache_generation_override_7692"
run_controller prepare-maintenance
assert_eq OWNED "$(marker_phase)" 'cache projection convergence reached owned on retry'
run_controller finish-maintenance

# Restore transport/non-200 evidence is sticky for ordinary finish. The explicit
# resolver may adopt the unique applied 2xx receipt only after repeated live proof.
reset_fixture
run_controller prepare-maintenance
printf '3\n' >"$tmp/apply_then_fail_on_receipted_call"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" 'restore transport result became sticky ambiguity'
test -s "$tmp/state/maintenance-ambiguous.json"
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['restore_response_checkpoint'] == 'transport_or_non200'
assert p['restore_response_updated_at'] is None
PY
assert_eq 1 "$(event_count '^set:7692:true$')" 'restore transport result used one committed request'
run_controller resolve-restore-ambiguity
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['phase'] == 'RESTORE_ACKED'
assert p['restore_response_checkpoint'] == 'explicitly_resolved'
assert p['restore_response_updated_at'] is None
PY
run_controller finish-maintenance
assert_eq 1 "$(event_count '^set:7692:true$')" 'explicit transport resolution made no extra restore write'
test ! -e "$tmp/state/maintenance.json"

reset_fixture
run_controller prepare-maintenance
touch "$tmp/fail_next_restore_receipt_record"
expect_controller_failure finish-maintenance
assert_eq RESTORE_INTENT "$(marker_phase)" 'restore receipt read outage kept restore intent'
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['restore_response_checkpoint'] == 'validated'
assert p['restore_response_updated_at']
PY
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 1 "$(event_count '^set:7692:true$')" 'restore receipt outage issued one restore only'
run_controller finish-maintenance
assert_eq 1 "$(event_count '^set:7692:true$')" 'restore intent retry did not replay restore'
test ! -e "$tmp/state/maintenance.json"

# A crash after a valid restore body was parsed but before checkpoint fsync
# leaves pending intent. Ordinary finish poisons it without replay; only the
# explicit resolver may adopt the unique receipt after its repeated live proof.
reset_fixture
run_controller prepare-maintenance
TEST_RESPONSE_BARRIER_PREFIX="$tmp/response-barrier"
start_controller_background finish-maintenance
wait_for_marker "$tmp/response-barrier.restore.reached" "$CONTROLLER_PID" 8
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['phase'] == 'RESTORE_INTENT'
assert p['restore_response_checkpoint'] == 'pending'
assert p['restore_response_updated_at'] is None
PY
kill -KILL "$CONTROLLER_PID" 2>/dev/null || true
set +e
wait "$CONTROLLER_PID" 2>/dev/null
set -e
unset TEST_RESPONSE_BARRIER_PREFIX
restore_writes_before="$(event_count '^set:7692:true$')"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'restore response/checkpoint crash gap became sticky ambiguity'
assert_eq "$restore_writes_before" "$(event_count '^set:7692:true$')" \
  'restore response/checkpoint crash gap did not replay request'
test -s "$tmp/state/maintenance-ambiguous.json"
run_controller resolve-restore-ambiguity
python3 - "$tmp/state/maintenance.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
assert p['phase'] == 'RESTORE_ACKED'
assert p['restore_response_checkpoint'] == 'explicitly_resolved'
assert p['restore_response_updated_at'] is None
PY
run_controller finish-maintenance
assert_eq "$restore_writes_before" "$(event_count '^set:7692:true$')" \
  'explicit crash-gap resolution made zero account writes'
test ! -e "$tmp/state/maintenance.json"

# A malformed synchronous restore 2xx remains sticky and is never adopted by
# finish-maintenance. The explicit resolver may adopt it only from one durable
# 2xx receipt plus repeated live group/primary/fence proof, without replaying
# the restore write.
reset_fixture
run_controller prepare-maintenance
printf 'invalid-json\n' >"$tmp/bad_primary_response"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'malformed restore response remained sticky ambiguity'
test -s "$tmp/state/maintenance-ambiguous.json"
assert_eq t "$(member_schedulable 7692)" 'malformed restore had actually restored primary'
assert_eq 1 "$(event_count '^set:7692:true$')" 'malformed restore issued exactly once'
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'ordinary finish did not auto-adopt malformed 2xx'
assert_eq 1 "$(event_count '^set:7692:true$')" \
  'ordinary finish did not replay malformed restore'
run_controller resolve-restore-ambiguity
assert_eq RESTORE_ACKED "$(marker_phase)" \
  'explicit evidence resolver adopted unique restore receipt'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 1 "$(event_count '^set:7692:true$')" \
  'explicit evidence resolver made zero account writes'
run_controller finish-maintenance
test ! -e "$tmp/state/maintenance.json"

# Explicit reconciliation accepts the unique successful 2xx class, not only
# 200. The ordinary finish path must preserve that adopted evidence rather than
# re-poisoning a valid 204 receipt.
reset_fixture
run_controller prepare-maintenance
printf 'invalid-json\n' >"$tmp/bad_primary_response"
printf '204\n' >"$tmp/receipt_status_override"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'malformed restore 204 became sticky ambiguity'
run_controller resolve-restore-ambiguity
assert_eq RESTORE_ACKED "$(marker_phase)" \
  'explicit resolver adopted unique restore 204'
test ! -e "$tmp/state/maintenance-ambiguous.json"
assert_eq 1 "$(event_count '^set:7692:true$')" \
  '204 resolver made zero account writes'
run_controller finish-maintenance
test ! -e "$tmp/state/maintenance.json"
assert_eq 1 "$(event_count '^set:7692:true$')" \
  'finish retained adopted restore 204 without replay'

# A poison sidecar's phase/reason/timestamp are validated evidence. A
# same-run sidecar relabeled as a pause ambiguity can never be deleted by the
# restore-only explicit resolver.
reset_fixture
run_controller prepare-maintenance
printf 'invalid-json\n' >"$tmp/bad_primary_response"
expect_controller_failure finish-maintenance
python3 - "$tmp/state/maintenance-ambiguous.json" <<'PY'
import json,os,sys,tempfile
path=sys.argv[1]
p=json.load(open(path,encoding='utf-8'))
p['phase']='PAUSE_INTENT'
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path),prefix='ambiguity-tamper.')
with os.fdopen(fd,'w',encoding='utf-8') as f:
    json.dump(p,f,sort_keys=True)
    f.write('\n')
os.replace(tmp,path)
PY
restore_writes_before="$(event_count '^set:7692:true$')"
expect_controller_failure resolve-restore-ambiguity
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'mismatched sidecar phase left restore marker unresolved'
test -s "$tmp/state/maintenance-ambiguous.json"
assert_eq "$restore_writes_before" "$(event_count '^set:7692:true$')" \
  'mismatched sidecar phase resolver made zero account writes'

# Duplicate 2xx receipts can never be reconciled by the explicit command.
reset_fixture
run_controller prepare-maintenance
printf 'invalid-json\n' >"$tmp/bad_primary_response"
touch "$tmp/duplicate_next_receipt"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'duplicate malformed restore became sticky ambiguity'
expect_controller_failure resolve-restore-ambiguity
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'duplicate restore receipt remained unresolved'
test -s "$tmp/state/maintenance-ambiguous.json"
assert_eq 1 "$(event_count '^set:7692:true$')" \
  'duplicate receipt resolution made no extra account write'

# A group replacement immediately after the owned restore write is a confirmed
# post-write identity conflict. Keep the primary restored, poison the run, and
# never issue a second restore against the replacement group.
reset_fixture
run_controller prepare-maintenance
touch "$tmp/flip_group_after_primary_restore"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" 'restore-time group replacement became ambiguous'
assert_eq t "$(member_schedulable 7692)" 'restore-time group replacement kept primary restored'
assert_eq 1 "$(event_count '^set:7692:true$')" 'restore-time group replacement used one restore write'
test -s "$tmp/state/maintenance-ambiguous.json"
expect_controller_failure resolve-restore-ambiguity
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'group replacement could not be explicitly reconciled'
assert_eq 1 "$(event_count '^set:7692:true$')" \
  'group replacement resolver made zero account writes'

# A maintenance-opened standby can later become shared with another active
# group. Restore the owned primary, but retain the RESTORED marker/manual state;
# schedulable is global, so the controller must not close that shared account or
# call the lifecycle normal until membership is reconciled.
reset_fixture
run_controller prepare-maintenance
sed -i 's/^7693|\(.*\)|1$/7693|\1|2/' "$tmp/members"
expect_controller_failure finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'shared maintenance standby did not block owned primary restore'
assert_eq t "$(member_schedulable 7693)" 'shared maintenance standby was not closed globally'
assert_eq RESTORED "$(marker_phase)" 'shared maintenance standby retained restored marker'
assert_eq maintenance "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mode"])' "$tmp/state/state.json")" \
  'shared maintenance standby retained manual maintenance state'
assert_eq 1 "$(event_count '^set:7692:true$')" 'shared maintenance standby used one restore'
expect_controller_failure reconcile
assert_eq RESTORED "$(marker_phase)" 'timer did not clear restored marker while standby stayed shared'
assert_eq t "$(member_schedulable 7693)" 'timer did not globally close shared standby'
sed -i 's/^7693|\(.*\)|2$/7693|\1|1/' "$tmp/members"
run_controller finish-maintenance
test ! -e "$tmp/state/maintenance.json"
assert_eq 1 "$(event_count '^set:7692:true$')" 'membership repair did not replay primary restore'

# If an external actor pauses again after RESTORE_ACKED, finish never repeats the
# restore and marks the ownership outcome ambiguous.
reset_fixture
run_controller prepare-maintenance
touch "$tmp/bucket_error_after_primary_restore"
start_controller_background finish-maintenance
wait_for_phase "$tmp/state/maintenance.json" RESTORE_ACKED "$CONTROLLER_PID" 8
kill -KILL "$CONTROLLER_PID" 2>/dev/null || true
set +e
wait "$CONTROLLER_PID" 2>/dev/null
set -e
rm -f "$tmp/bucket_error_after_primary_restore" "$tmp/bucket_error_7692"
touch "$tmp/allow_external_primary_write"
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 "$backend" set-schedulable 7692 false >/dev/null
rm -f "$tmp/allow_external_primary_write"
restore_writes_before="$(event_count '^set:7692:true$')"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" 'external re-pause became restore ambiguous'
assert_eq "$restore_writes_before" "$(event_count '^set:7692:true$')" 'external re-pause caused no duplicate restore'
test -s "$tmp/state/maintenance-ambiguous.json"
expect_controller_failure resolve-restore-ambiguity
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'unschedulable primary blocked explicit restore reconciliation'
assert_eq "$restore_writes_before" "$(event_count '^set:7692:true$')" \
  'failed explicit reconciliation made zero account writes'

# If the only standby becomes inactive during maintenance, a healthy OWNED
# primary is still restored. The controller never changes status or re-enables
# that inactive account.
reset_fixture
run_controller prepare-maintenance
events_before="$(wc -l <"$tmp/events")"
sed -i 's/7693|\([^|]*\)|active|t|t|t/7693|\1|inactive|f|t|f/' "$tmp/members"
run_controller finish-maintenance
assert_eq t "$(member_schedulable 7692)" 'owned primary restored without active standby'
assert_eq inactive "$(awk -F '|' '$1==7693 {print $3}' "$tmp/members")" 'inactive standby status preserved'
assert_eq f "$(member_schedulable 7693)" 'inactive standby remained unschedulable'
assert_eq "$((events_before + 1))" "$(wc -l <"$tmp/events")" 'finish wrote only primary restore'

# Existing external pause can also finish primary-only after an external actor
# restores it; the controller observes but never writes the primary.
reset_fixture
sed -i 's/7692|\([^|]*\)|active|t|t|t/7692|\1|active|f|t|t/' "$tmp/members"
run_controller prepare-maintenance
sed -i 's/7693|\([^|]*\)|active|t|t|t/7693|\1|inactive|f|t|f/' "$tmp/members"
FAKE_DIR="$tmp" FAKE_BRIDGE_ID=7692 "$backend" set-schedulable 7692 true >/dev/null
run_controller finish-maintenance
assert_eq 0 "$(<"$tmp/receipted_call_count")" 'external primary-only finish made no owned request'
test ! -e "$tmp/state/maintenance.json"

# Routine logging configuration may change after ownership; warn or sampling
# prevents restoration and leaves the standby/marker protection intact.
for logging_state in 'warn|false' 'info|true'; do
  reset_fixture
  run_controller prepare-maintenance
  printf '%s\n' "$logging_state" >"$tmp/runtime_logging"
  expect_controller_failure finish-maintenance
  assert_eq 0 "$(event_count '^set:7692:true$')" "logging change $logging_state blocked restore"
  test -e "$tmp/state/maintenance.json"
  test -s "$tmp/state/maintenance-ambiguous.json"
done

# The 20-second recurring snapshot budget and 90-second explicit maintenance
# budget remain separate. The fixture shortens both while preserving ordering.
reset_fixture
printf '%s\n' "$(( $(date +%s) + 2 ))" >"$tmp/snapshot_not_ready_until"
TEST_SNAPSHOT_TIMEOUT_SECONDS=1
TEST_MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS=4
printf 'ok|10|0|0|3|7|0|0|0|0|0|degraded\n' >"$tmp/health"
expect_controller_failure reconcile
run_controller prepare-maintenance
run_controller finish-maintenance
unset TEST_SNAPSHOT_TIMEOUT_SECONDS TEST_MAINTENANCE_SNAPSHOT_TIMEOUT_SECONDS

# IDs are dynamic: only the configured primary is special and all active
# standbys are discovered from the current group inventory.
reset_fixture
sed -i 's/^7692|/9001|/; s/^7693|/9002|/; s/^7845|/9003|/' "$tmp/members"
mv "$tmp/meta_generation_7692" "$tmp/meta_generation_9001"
mv "$tmp/meta_generation_7693" "$tmp/meta_generation_9002"
mv "$tmp/meta_generation_7845" "$tmp/meta_generation_9003"
TEST_BRIDGE_ACCOUNT_ID=9001
run_controller prepare-maintenance
run_controller finish-maintenance
unset TEST_BRIDGE_ACCOUNT_ID
grep -q '^set:9002:true' "$tmp/events"
assert_eq 2 "$(grep -c '^set:9001:false' "$tmp/events")" 'dynamic primary received pause and seal'
assert_eq 1 "$(grep -c '^set:9001:true' "$tmp/events")" 'dynamic primary restored once'
if grep -Eq '^set:(7692|9003):' "$tmp/events"; then
  printf 'FAIL: dynamic run wrote stale or inactive account\n' >&2
  exit 1
fi

# A current ambiguity sidecar carries the same immutable identity and run id.
# Even by itself it rejects a rotated config before any account write.
reset_fixture
touch "$tmp/omit_next_receipt_clean"
expect_controller_failure prepare-maintenance
python3 - "$tmp/state/maintenance.json" "$tmp/state/maintenance-ambiguous.json" <<'PY'
import json,re,sys
marker=json.load(open(sys.argv[1],encoding='utf-8'))
sidecar=json.load(open(sys.argv[2],encoding='utf-8'))
assert sidecar['schema_version'] == 3
assert sidecar['group_member_ids'] == [7692,7693,7845,7850]
assert sidecar['backup_account_ids'] == [7693]
assert re.fullmatch(r'[a-f0-9]{64}',sidecar['identity_digest'])
for key in ('run_id','primary_account_id','group_id','group_member_ids',
            'backup_account_ids','identity_digest'):
    assert sidecar[key] == marker[key], (key,sidecar[key],marker[key])
PY
sidecar_run="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$tmp/state/maintenance-ambiguous.json")"
rm -f "$tmp/state/maintenance.json"
sed -i 's/7693|\([^|]*\)|active|t|t|t/7693|\1|active|f|t|t/' "$tmp/members"
run_controller reconcile
assert_eq t "$(member_schedulable 7693)" 'bound sidecar-only reconcile reopened standby'
grep -Fq "c2m-${sidecar_run}-b-7693" "$tmp/access_logs"
assert_eq maintenance "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mode"])' "$tmp/state/state.json")" \
  'bound sidecar-only reconcile retained maintenance mode'

# A standalone sidecar is not authority to write against a changed backup
# collection, even when the full group-member ID collection is unchanged.
reset_fixture
touch "$tmp/omit_next_receipt_clean"
expect_controller_failure prepare-maintenance
rm -f "$tmp/state/maintenance.json"
sed -i \
  's/7693|\([^|]*\)|active|t|t|t/7693|\1|active|f|t|t/; s/7845|\([^|]*\)|inactive|f|t|f/7845|\1|active|f|t|f/' \
  "$tmp/members"
rotation_events_before="$(wc -l <"$tmp/events")"
expect_controller_failure reconcile
assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" \
  'sidecar backup-identity drift made zero account writes'
assert_eq f "$(member_schedulable 7693)" 'identity drift did not reopen sealed backup'
assert_eq f "$(member_schedulable 7845)" 'identity drift did not open newly active backup'

reset_fixture
cat >>"$tmp/members" <<EOF
7694|$(encode_name third-sidecar-standby)|active|f|t|t|1
EOF
printf '2026-07-14T00:00:00.000091Z\n' >"$tmp/meta_generation_7694"
touch "$tmp/omit_next_receipt_clean"
expect_controller_failure prepare-maintenance
test -s "$tmp/state/maintenance-ambiguous.json"
rm -f "$tmp/state/maintenance.json"
rotation_events_before="$(wc -l <"$tmp/events")"
TEST_BRIDGE_ACCOUNT_ID=7693
for rotated_command in prepare-maintenance finish-maintenance reconcile status; do
  expect_controller_failure "$rotated_command"
  assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" \
    "sidecar config rotation $rotated_command made zero account writes"
done
unset TEST_BRIDGE_ACCOUNT_ID

# A marker/sidecar run-id conflict also fails closed without falling through to
# generic backup opening.
reset_fixture
touch "$tmp/omit_next_receipt_clean"
expect_controller_failure prepare-maintenance
python3 - "$tmp/state/maintenance-ambiguous.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1],encoding='utf-8'))
p['run_id']='22222222-2222-2222-2222-222222222222'
open(sys.argv[1],'w',encoding='utf-8').write(json.dumps(p,sort_keys=True)+'\n')
PY
rotation_events_before="$(wc -l <"$tmp/events")"
expect_controller_failure reconcile
assert_eq "$rotation_events_before" "$(wc -l <"$tmp/events")" 'conflicting sidecar run id made zero account writes'

# Both artifacts must agree on the sealed backup collection and digest. Each
# conflict stays read-only across every maintenance entrypoint.
for identity_conflict in backup_collection digest; do
  reset_fixture
  touch "$tmp/omit_next_receipt_clean"
  expect_controller_failure prepare-maintenance
  python3 - "$tmp/state/maintenance-ambiguous.json" "$identity_conflict" <<'PY'
import json,sys
path,kind=sys.argv[1:]
p=json.load(open(path,encoding='utf-8'))
if kind == 'backup_collection':
    p['backup_account_ids']=[7845]
elif kind == 'digest':
    p['identity_digest']='0'*64
else:
    raise SystemExit(kind)
open(path,'w',encoding='utf-8').write(json.dumps(p,sort_keys=True)+'\n')
PY
  identity_events_before="$(wc -l <"$tmp/events")"
  for identity_command in prepare-maintenance finish-maintenance reconcile status \
      resolve-restore-ambiguity; do
    expect_controller_failure "$identity_command"
    assert_eq "$identity_events_before" "$(wc -l <"$tmp/events")" \
      "marker/sidecar $identity_conflict conflict $identity_command made zero account writes"
  done
  test -e "$tmp/state/maintenance.json"
  test -e "$tmp/state/maintenance-ambiguous.json"
done

# The explicit resolver validates both artifacts before considering restore
# evidence. Build one real RESTORE_AMBIGUOUS pair, then prove every legacy or
# unknown schema on either artifact is a read-only rejection that preserves both
# files byte-for-byte.
reset_fixture
run_controller prepare-maintenance
printf 'invalid-json\n' >"$tmp/bad_primary_response"
expect_controller_failure finish-maintenance
assert_eq RESTORE_AMBIGUOUS "$(marker_phase)" \
  'resolver schema matrix built a restore-ambiguous marker'
test -s "$tmp/state/maintenance-ambiguous.json"
cp "$tmp/state/maintenance.json" "$tmp/resolver-schema-marker.baseline"
cp "$tmp/state/maintenance-ambiguous.json" "$tmp/resolver-schema-sidecar.baseline"

for schema_version in 1 2 3 4 5 6 99; do
  reset_fixture
  cp "$tmp/resolver-schema-marker.baseline" "$tmp/state/maintenance.json"
  cp "$tmp/resolver-schema-sidecar.baseline" "$tmp/state/maintenance-ambiguous.json"
  python3 - "$tmp/state/maintenance.json" "$schema_version" <<'PY'
import json,sys
path,version=sys.argv[1],int(sys.argv[2])
p=json.load(open(path,encoding='utf-8'))
p['schema_version']=version
open(path,'w',encoding='utf-8').write(json.dumps(p,sort_keys=True)+'\n')
PY
  marker_hash_before="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
  sidecar_hash_before="$(sha256sum "$tmp/state/maintenance-ambiguous.json" | awk '{print $1}')"
  resolver_events_before="$(wc -l <"$tmp/events")"
  expect_controller_failure resolve-restore-ambiguity
  assert_eq "$resolver_events_before" "$(wc -l <"$tmp/events")" \
    "resolver marker schema $schema_version made zero account writes"
  assert_eq "$marker_hash_before" \
    "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
    "resolver marker schema $schema_version preserved marker bytes"
  assert_eq "$sidecar_hash_before" \
    "$(sha256sum "$tmp/state/maintenance-ambiguous.json" | awk '{print $1}')" \
    "resolver marker schema $schema_version preserved sidecar bytes"
done

for schema_version in 1 2 99; do
  reset_fixture
  cp "$tmp/resolver-schema-marker.baseline" "$tmp/state/maintenance.json"
  cp "$tmp/resolver-schema-sidecar.baseline" "$tmp/state/maintenance-ambiguous.json"
  python3 - "$tmp/state/maintenance-ambiguous.json" "$schema_version" <<'PY'
import json,sys
path,version=sys.argv[1],int(sys.argv[2])
p=json.load(open(path,encoding='utf-8'))
p['schema_version']=version
open(path,'w',encoding='utf-8').write(json.dumps(p,sort_keys=True)+'\n')
PY
  marker_hash_before="$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')"
  sidecar_hash_before="$(sha256sum "$tmp/state/maintenance-ambiguous.json" | awk '{print $1}')"
  resolver_events_before="$(wc -l <"$tmp/events")"
  expect_controller_failure resolve-restore-ambiguity
  assert_eq "$resolver_events_before" "$(wc -l <"$tmp/events")" \
    "resolver sidecar schema $schema_version made zero account writes"
  assert_eq "$marker_hash_before" \
    "$(sha256sum "$tmp/state/maintenance.json" | awk '{print $1}')" \
    "resolver sidecar schema $schema_version preserved marker bytes"
  assert_eq "$sidecar_hash_before" \
    "$(sha256sum "$tmp/state/maintenance-ambiguous.json" | awk '{print $1}')" \
    "resolver sidecar schema $schema_version preserved sidecar bytes"
done

# Every pre-v7/unknown marker and every pre-v3/unknown sidecar is rejected by
# every maintenance entrypoint. None is upgraded, rewritten, or used to guess a
# standby; the original artifact remains for operator action.
for schema_version in 1 2 3 4 5 6 99; do
  reset_fixture
  python3 - "$tmp/state/maintenance.json" "$schema_version" <<'PY'
import json,sys
path,version=sys.argv[1],int(sys.argv[2])
payload={
  'schema_version':version,
  'run_id':'11111111-1111-1111-1111-111111111111',
  'phase':'OWNED',
  'primary_disabled_by_maintenance':True,
}
open(path,'w',encoding='utf-8').write(json.dumps(payload,sort_keys=True)+'\n')
PY
  legacy_events_before="$(wc -l <"$tmp/events")"
  for legacy_command in prepare-maintenance finish-maintenance reconcile status; do
    expect_controller_failure "$legacy_command"
    assert_eq "$legacy_events_before" "$(wc -l <"$tmp/events")" \
      "marker schema $schema_version $legacy_command made zero account writes"
  done
  assert_eq t "$(member_schedulable 7692)" "marker schema $schema_version preserved primary"
  assert_eq f "$(member_schedulable 7693)" "marker schema $schema_version did not guess standby"
  test -e "$tmp/state/maintenance.json"
done

for schema_version in 1 2 99; do
  reset_fixture
  python3 - "$tmp/state/maintenance-ambiguous.json" "$schema_version" <<'PY'
import json,sys
path,version=sys.argv[1],int(sys.argv[2])
payload={
  'schema_version':version,
  'run_id':'11111111-1111-1111-1111-111111111111',
  'phase':'PAUSE_INTENT',
  'reason':'test',
  'created_at':'2026-07-14T00:00:00.000000Z',
}
open(path,'w',encoding='utf-8').write(json.dumps(payload,sort_keys=True)+'\n')
PY
  legacy_events_before="$(wc -l <"$tmp/events")"
  for legacy_command in prepare-maintenance finish-maintenance reconcile status; do
    expect_controller_failure "$legacy_command"
    assert_eq "$legacy_events_before" "$(wc -l <"$tmp/events")" \
      "sidecar schema $schema_version $legacy_command made zero account writes"
  done
  assert_eq t "$(member_schedulable 7692)" "sidecar schema $schema_version preserved primary"
  assert_eq f "$(member_schedulable 7693)" "sidecar schema $schema_version did not guess standby"
  test -e "$tmp/state/maintenance-ambiguous.json"
done

# A pre-pause snapshot failure never reaches the primary mutation.
reset_fixture
touch "$tmp/snapshot_fail"
expect_controller_failure prepare-maintenance
assert_eq t "$(member_schedulable 7692)" 'snapshot failure left primary schedulable'
assert_primary_not_written

# Ambiguous active-group discovery performs zero writes.
reset_fixture
printf '%s\n' '12|codex-pro|active' '99|codex-pro|active' >"$tmp/group"
expect_controller_failure reconcile
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
