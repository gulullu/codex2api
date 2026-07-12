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
