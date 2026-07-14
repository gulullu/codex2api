#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  printf 'usage: %s -- command [args...]\n' "$0" >&2
  exit 64
fi
if [[ "$1" == "--" ]]; then
  shift
fi
if (( $# == 0 )); then
  printf 'maintenance command is required\n' >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${FAILOVER_CONTROLLER_BIN:-}" ]]; then
  controller="$FAILOVER_CONTROLLER_BIN"
elif [[ -x /usr/local/libexec/codex2api-sub2-codex-pro-failover ]]; then
  controller=/usr/local/libexec/codex2api-sub2-codex-pro-failover
else
  controller="$script_dir/sub2-codex-pro-failover.sh"
fi

readonly failover_config_file="${FAILOVER_CONFIG_FILE:-/etc/default/codex2api-sub2-codex-pro-failover}"

load_bridge_account_id_once() {
  local value="${BRIDGE_ACCOUNT_ID:-}"
  if [[ -z "$value" ]]; then
    [[ -r "$failover_config_file" ]] || {
      printf 'BRIDGE_ACCOUNT_ID is required and config is unreadable: %s\n' "$failover_config_file" >&2
      exit 64
    }
    local line matches=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      if [[ "$line" == BRIDGE_ACCOUNT_ID=* ]]; then
        matches=$((matches + 1))
        value="${line#BRIDGE_ACCOUNT_ID=}"
      fi
    done <"$failover_config_file"
    (( matches == 1 )) || {
      printf 'BRIDGE_ACCOUNT_ID config must contain exactly one assignment\n' >&2
      exit 64
    }
  fi
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    printf 'BRIDGE_ACCOUNT_ID must be a positive integer\n' >&2
    exit 64
  }
  local maximum=9223372036854775807
  if (( ${#value} > ${#maximum} )) ||
     { (( ${#value} == ${#maximum} )) && [[ "$value" > "$maximum" ]]; }; then
    printf 'BRIDGE_ACCOUNT_ID is outside PostgreSQL bigint range\n' >&2
    exit 64
  fi
  export BRIDGE_ACCOUNT_ID="$value"
}

if [[ -z "${CREDENTIALS_DIRECTORY:-}" && -z "${SUB2_ADMIN_KEY_FILE:-}" && -r /root/.sub2api_admin.key ]]; then
  export SUB2_ADMIN_KEY_FILE=/root/.sub2api_admin.key
fi

lifecycle_runtime="${RUNTIME_DIRECTORY:-${FAILOVER_RUNTIME_DIR:-/run/codex2api-sub2-codex-pro-failover}}"
install -d -m 0700 "$lifecycle_runtime"
lifecycle_lock="${MAINTENANCE_LIFECYCLE_LOCK_FILE:-$lifecycle_runtime/maintenance-lifecycle.lock}"
exec 8>"$lifecycle_lock"
if ! flock --nonblock 8; then
  printf 'another codex2api maintenance lifecycle is already running\n' >&2
  exit 75
fi

# Freeze one validated primary identity for prepare, the wrapped command, and
# finish. A config-file edit during a long rebuild applies only to a later
# lifecycle; it cannot split ownership across two account ids.
load_bridge_account_id_once

"$controller" prepare-maintenance

set +e
"$@"
command_rc=$?
set -e
if (( command_rc != 0 )); then
  printf 'maintenance command failed (rc=%s); backups and maintenance marker were intentionally left in place\n' "$command_rc" >&2
  exit "$command_rc"
fi

if ! "$controller" finish-maintenance; then
  printf 'maintenance finished but recovery validation failed; backups were intentionally left in place\n' >&2
  exit 1
fi
