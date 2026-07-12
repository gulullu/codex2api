# codex2api Relay health watchdog

This directory contains an external, read-only safety check for the production
codex2api Relay guardian. It is deliberately separate from the in-process
request breaker and the one-minute Guardian scan.

The systemd timer starts 90 seconds after boot and then runs every two minutes.
The service applies a hard 45-second process timeout. A ten-second randomized
delay avoids synchronized checks after fleet-wide events, with 15-second timer
accuracy. The script also takes a non-blocking flock lock, so a delayed run
cannot overlap the next invocation.

The unit uses Requisite=docker.service plus ordering, so it fails when Docker
is inactive without starting Docker. AssertPathExists checks the existing
Docker socket path without connecting to or socket-activating it. systemd
creates a private writable runtime directory for the lock at
/run/codex2api-relay-health-watchdog/watchdog.lock, including when
ProtectSystem=strict is active.

## What it checks

- GET http://127.0.0.1:8090/health with a five-second HTTP timeout.
- Runtime state, current restart state, restart count, and Docker health for
  codex2api, its PostgreSQL and Redis containers, sub2api, and sub2api
  PostgreSQL.
- Direct PostgreSQL reachability with pg_isready.
- Direct Redis reachability without credentials. PONG and an authenticated
  Redis NOAUTH response both prove that the server is reachable.
- The optional unauthenticated health summary:
  - guardian: enabled, mode, status, heartbeat_at, scan_interval_seconds
  - relay: configured, enabled, schedulable, quarantined, probation
- The number of schedulable Responses API accounts in the configured Relay
  group. OAuth accounts in the same group are ignored. The account locked flag
  only protects accounts from automatic cleanup in codex2api, so it does not
  remove an otherwise schedulable Relay account from this count.
- sub2api bridge account 7692 status, schedulable flag, and deletion state.

Older builds that do not expose guardian or relay in /health remain observable.
The script logs guardian as skipped and derives a static Relay candidate count
with a local read-only PostgreSQL SELECT. It excludes active database cooldowns,
but it cannot see transient Redis quarantine, probation, or other live runtime
state. A nonzero database fallback is therefore reported as
degraded/live_state_unknown, never as healthy. The health summary remains the
preferred source.

Every stdout line is one JSON object. The script never enables or disables an
account, restarts a service, writes the database, reads an admin secret, or
reads a Redis/PostgreSQL password. Health logging records only the sanitized
host, port, and path; URL userinfo and query parameters are never emitted.
Bootstrap, invalid configuration, and lock-open failures also emit a final
summary before exiting.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | All mandatory checks passed, or an overlapping invocation was skipped. |
| 1 | Observation is degraded, for example a stale Guardian heartbeat or an unavailable optional fallback. |
| 2 | A critical service, pool, or bridge check failed. |
| 3 | The watchdog itself cannot start because a required command or lock file is unavailable. |
| 124 | GNU timeout stopped the check after 45 seconds; systemd records the timeout even if the killed script cannot emit its final summary. |

The final JSON line has check=summary and includes all counters plus the exit
code. Missing optional health fields do not by themselves make the unit fail.

## Dependencies

- Linux with systemd
- bash 4 or newer
- docker CLI with permission to use /var/run/docker.sock
- curl, python3, flock, timeout
- the production container names used by /root/codex2api

All names and the health URL can be overridden through service Environment
entries. Do not add ADMIN_SECRET, database passwords, Redis passwords, API
keys, or other credentials.

## Self-check before installation

From the repository root:

    bash -n ops/relay-health-watchdog/relay-health-watchdog.sh
    bash -n ops/relay-health-watchdog/tests/selftest.sh
    bash -n ops/relay-health-watchdog/tests/systemd-selftest.sh
    bash ops/relay-health-watchdog/tests/selftest.sh

If shellcheck is installed:

    shellcheck ops/relay-health-watchdog/relay-health-watchdog.sh
    shellcheck ops/relay-health-watchdog/tests/selftest.sh

The self-check uses mock curl and docker commands. It does not contact or
modify production.

The root-only opt-in adds uniquely named transient dummy systemd units and a
dummy AF_UNIX socket in a private temporary directory. It proves
Requisite/AssertPathExists do not
activate either dummy, and that timeout plus KillMode=control-group removes a
hung descendant and releases flock:

    sudo RUN_SYSTEMD_ISOLATION_TEST=1 \
      bash ops/relay-health-watchdog/tests/selftest.sh

It never references or stops the real Docker, codex2api, or sub2api units.

## Install

Run these commands from the repository checkout. Save the existing deployment
first so an upgrade can be rolled back exactly:

    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="/var/backups/codex2api-relay-health-watchdog/$stamp"
    sudo install -d -m 0700 "$backup"
    for path in \
      /usr/local/libexec/codex2api-relay-health-watchdog \
      /usr/local/share/doc/codex2api-relay-health-watchdog/README.md \
      /etc/systemd/system/codex2api-relay-health-watchdog.service \
      /etc/systemd/system/codex2api-relay-health-watchdog.timer; do
      if sudo test -e "$path"; then
        sudo cp -a --parents "$path" "$backup"
      fi
    done
    printf 'backup=%s\n' "$backup"

    sudo install -Dm0755 \
      ops/relay-health-watchdog/relay-health-watchdog.sh \
      /usr/local/libexec/codex2api-relay-health-watchdog
    sudo install -Dm0644 \
      ops/relay-health-watchdog/README.md \
      /usr/local/share/doc/codex2api-relay-health-watchdog/README.md
    sudo install -Dm0644 \
      ops/relay-health-watchdog/systemd/codex2api-relay-health-watchdog.service \
      /etc/systemd/system/codex2api-relay-health-watchdog.service
    sudo install -Dm0644 \
      ops/relay-health-watchdog/systemd/codex2api-relay-health-watchdog.timer \
      /etc/systemd/system/codex2api-relay-health-watchdog.timer
    sudo systemctl daemon-reload
    sudo systemctl enable --now codex2api-relay-health-watchdog.timer

Confirm the schedule and run one read-only check:

    systemctl list-timers codex2api-relay-health-watchdog.timer
    sudo systemctl start codex2api-relay-health-watchdog.service
    journalctl -u codex2api-relay-health-watchdog.service -n 30 --no-pager

Installing or upgrading this watchdog does not require a codex2api or sub2api
restart.

## Uninstall

    sudo systemctl disable --now codex2api-relay-health-watchdog.timer
    sudo rm -f \
      /etc/systemd/system/codex2api-relay-health-watchdog.timer \
      /etc/systemd/system/codex2api-relay-health-watchdog.service \
      /usr/local/libexec/codex2api-relay-health-watchdog
    sudo rm -rf /usr/local/share/doc/codex2api-relay-health-watchdog
    sudo systemctl daemon-reload
    sudo systemctl reset-failed codex2api-relay-health-watchdog.service

Uninstalling only removes this observer. It does not alter Guardian state,
account state, the databases, or either application service.

## Roll back an upgrade

Stop only the timer, restore the files from the backup path printed during the
installation, and re-enable the timer:

    backup=/var/backups/codex2api-relay-health-watchdog/YYYYMMDDTHHMMSSZ
    sudo systemctl disable --now codex2api-relay-health-watchdog.timer
    sudo cp -a "$backup/usr/local/libexec/codex2api-relay-health-watchdog" \
      /usr/local/libexec/codex2api-relay-health-watchdog
    sudo cp -a "$backup/usr/local/share/doc/codex2api-relay-health-watchdog/README.md" \
      /usr/local/share/doc/codex2api-relay-health-watchdog/README.md
    sudo cp -a "$backup/etc/systemd/system/codex2api-relay-health-watchdog.service" \
      /etc/systemd/system/codex2api-relay-health-watchdog.service
    sudo cp -a "$backup/etc/systemd/system/codex2api-relay-health-watchdog.timer" \
      /etc/systemd/system/codex2api-relay-health-watchdog.timer
    sudo systemctl daemon-reload
    sudo systemctl enable --now codex2api-relay-health-watchdog.timer

If a backed-up file does not exist, use the uninstall procedure instead of
inventing a replacement. Rollback never restarts codex2api or sub2api.
