# sub2 codex-pro failover controller

This controller keeps the user's `codex2api-pro` bridge as the normal path while
opening only healthy standby accounts when the bridge path cannot safely carry
all traffic.

## Safety boundaries

- The active group is discovered on every run by the exact name `codex-pro`.
  There must be exactly one non-deleted active match. Otherwise the run performs
  no writes.
- Standbys are group members other than account `7692` whose account status is
  `active` and whose row is not deleted. `inactive`, `error`, and deleted rows
  are never changed.
- Standby failover changes only the sub2api `schedulable` flag through the admin
  API. It never changes account status, deletion state, credentials, cooldowns,
  or rate-limit state.
- Normal timer reconciliation never changes account `7692`. sub2api remains the
  owner of ordinary bridge health decisions.
- A standby is considered ready only after the database and scheduler outbox
  agree, its Redis scheduler metadata is active and unblocked, and every ready
  group OpenAI scheduler bucket contains at least one eligible standby.
- `guardian.status=degraded` alone is informational. It does not open standbys.

## Automatic state machine

The 30-second timer opens active standbys immediately when any of these is true:

- account `7692` is not active, deleted, or not schedulable;
- the codex2api health endpoint is unreachable or reports a non-`ok` service;
- codex2api reports no available internal account; or
- `health.relay.schedulable` is zero or missing.

When a standby is already open without a saved proof watermark, the first run
records that watermark and deliberately does not count as a healthy recovery
sample. It closes active standbys only after three consecutive later runs see
account `7692` active, schedulable, free of current database and Redis scheduling blocks,
present in every ready group OpenAI scheduler bucket, service status `ok`, at
least one internal account, and at least one schedulable Relay account. It also
requires at least two successful `7692` requests after the failover began, later
than the most recent `7692` error, with no new `7692` upstream 5xx in the last
60 seconds. This prevents an invisible in-process runtime breaker from causing
the controller to close the last known-good standby. Standby names and
membership are always read live.
After pausing the final standby it immediately repeats the complete recovery
check. If health changed in that narrow window, it reopens the active standbys
and returns non-zero.

State is stored in `state.json`:

```json
{
  "schema_version": 1,
  "mode": "normal|failover|maintenance|recovery_pending",
  "healthy_streak": 0,
  "last_reason": "...",
  "proof_after": "RFC3339 or null",
  "updated_at": "RFC3339"
}
```

## Planned maintenance

Use the explicit maintenance commands for a codex2api rebuild. They are the only
commands allowed to change account `7692`:

```bash
sub2-codex-pro-failover prepare-maintenance
# rebuild or recreate codex2api
sub2-codex-pro-failover finish-maintenance
```

`prepare-maintenance` writes a maintenance marker, opens all active standbys,
proves scheduler snapshot readiness, pauses `7692`, proves its removal from the
scheduler snapshots, and waits for two zero-concurrency samples. If any step
fails, it leaves standbys open and does not proceed to a service rebuild.
Only pending `account_changed` outbox events block snapshot confirmation;
continuous `account_last_used` traffic is intentionally ignored.

`finish-maintenance` requires codex2api service health before restoring `7692`
when this maintenance run paused it. It proves that `7692` has re-entered every
ready scheduler bucket. If Relay capacity is still zero, standbys stay open.
Otherwise normal reconciliation performs the three-sample recovery confirmation
before pausing standbys.
If the only standby becomes inactive or deleted during maintenance, finish still
restores a healthy maintenance-owned `7692`; it never changes that standby.

Maintenance commands wait a bounded 30 seconds for the shared controller lock
and fail non-zero on contention. Timer reconciliation and status commands may
instead skip harmlessly when another run owns the lock.
`safe-maintenance` also holds a separate lifecycle lock across prepare, the
wrapped rebuild command, and finish, so a second manual release cannot overlap.

The wrapper performs the same sequence around one command:

```bash
safe-maintenance -- docker compose up -d --no-deps --force-recreate codex2api
```

If the wrapped command or recovery validation fails, the marker and standbys are
intentionally left in place. This controller never calls the legacy
`/root/reset-bridge-7692.sh` helper.

The admin key is supplied to the systemd service with `LoadCredential`; it is not
stored in environment variables or emitted in logs.
Its temporary curl header file is mode `0600`, removed by normal and signal/exit
cleanup, and stale crash leftovers are removed only after the controller has
acquired its exclusive lock.
