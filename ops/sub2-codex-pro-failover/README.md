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
- If account `7692` loses its group association, the exact `codex-pro` group is
  still authoritative for standby discovery: reconciliation opens its active,
  non-deleted standbys without attempting a `7692` write. Planned maintenance
  stops after that protection is ready because it cannot safely own a missing
  primary.
- A standby is considered ready only after the database and scheduler outbox
  agree, its Redis scheduler metadata is active and unblocked, and every ready
  group OpenAI scheduler bucket contains at least one eligible standby.
- Redis scheduler reads are three-state: present, absent, or error. A Redis
  command error can never be treated as an absent account or silently remove a
  bucket from the proof set.
- Opening is best-effort across every active, non-deleted standby discovered in
  one live inventory snapshot, with runtime-ready accounts attempted first. The
  initial snapshot defines the dynamic work set, and membership/status/deletion
  state is re-read before each batch so an operator-paused, removed or newly
  inactive account is skipped before submission.
  Schedulability writes run in bounded batches of four, each local admin request
  has a five-second timeout, and the full submission phase has a 120-second
  deadline inside the 175-second service budget. A slow or failed early account
  therefore cannot serialize and hide a later healthy standby. The batch reuses
  one read-only credential header, gives every child a separate response file,
  reaps all children, avoids per-account convergence waits, and then applies the
  existing aggregate scheduler proof. Success still requires confirmed standby presence
  in every ready scheduler bucket; deadline-skipped or failed writes remain
  visible in the structured event. No batch path writes account status or the
  configured bridge account.
- `guardian.status=degraded` alone is informational. It does not open standbys.
- Relay capacity comes from `/health.relay.normal_schedulable`. Circuit
  `suspect`, legacy `half_open`, recovery `probation`, `open`, and last-resort
  entrances are not counted as stable front-door capacity.
- `/health.relay.effective_available_slots` is the live admission-capacity
  signal. One zero sample is tolerated; two consecutive 10-second zero samples
  open standbys. A health connection or parse failure opens standbys on the
  first sample because it may be a dead codex2api process.
- User-visible Relay exhaustion is read from codex2api PostgreSQL by first
  selecting the final row of every logical request across the whole site by
  `(created_at, id)` and only then filtering the current Relay group. Retry
  attempts, `guardian_attempt_only` rows, and probes never trigger sub2
  failover. A raw upstream 502 is not treated as
  `relay_route_unavailable`; it is evaluated only by the stricter terminal
  stream below, where one failure cannot trigger takeover.
- A second canonical terminal-failure stream catches mixed user-visible Relay
  incidents before every front has been locally removed. It accepts final
  `relay_route_unavailable`, upstream 502/503/504, real Relay-account 429s with
  the allowlisted account/window/model rate or capacity kinds, and rollback-era
  598 only when classified as transport/timeout. Local account-zero 429s,
  ordinary 500s, policy/CYB failures (including transition-era policy rows that
  carried a 5xx status), hidden retry attempts, and probes are excluded. One
  failure never opens a standby; two different logical requests in a sliding
  15-second cohort do.

## Automatic state machine

The 10-second timer opens active standbys immediately when any of these is true:

- account `7692` is not active, deleted, or not schedulable;
- the codex2api health endpoint reports a non-`ok` service;
- the codex2api health endpoint cannot be read or parsed;
- codex2api reports no available internal account; or
- `health.relay.normal_schedulable` is zero; or
- `health.relay.effective_available_slots` is zero for two consecutive runs; or
- two consecutive canonical-outcome telemetry reads fail; or
- at least two distinct canonical final logical requests ended as the exact
  `relay_route_unavailable` kind in the last 15 seconds; or
- at least three exact `relay_route_unavailable` finals occurred in 120
  seconds, even when they are too sparse for the 15-second cohort; or
- at least two distinct canonical Relay terminal failures of the supported
  kinds occurred in the same sliding 15-second cohort. A 502 followed by
  `relay_route_unavailable` is intentionally one qualifying mixed cohort.

The controller evaluates the 15-second cohort ending at the newest final
failure, accepts only a newest event seen within 60 seconds, and persists its
`(created_at, id)` tuple as a watermark. The timestamp remains authoritative if
a database restore moves the numeric sequence backwards. This closes the
sampling gap between 10-second timer runs without repeatedly triggering on an
old incident.

Only canonical-outcome SQL failure is debounced for one timer run. Two
consecutive failures open standbys. Health endpoint failure opens immediately.
Unknown telemetry can never prove recovery or close an already-open standby.

When a standby is already open without a saved proof watermark, the controller
records that watermark. It keeps standby capacity open for at least 180 seconds
and closes active standbys only after three consecutive later runs see
account `7692` active, schedulable, free of current database and Redis scheduling blocks,
present in every ready group OpenAI scheduler bucket, service status `ok`, at
least two normal Relay entrances (or all enabled entrances when fewer than two
exist), positive effective slots throughout the healthy recovery interval, and
zero `suspect`, `recovery_only`, `circuit_open`, and `last_resort` entrances.
Recovery additionally requires a 120-second window with zero canonical
`relay_route_unavailable` finals and zero supported canonical Relay terminal
failures, at least 20 canonical non-probe Relay successes after the proof
watermark and latest terminal failure, and at least
two successful `7692` requests later than its most recent error with no new
`7692` upstream 5xx in the last 60 seconds. This prevents an invisible
in-process runtime breaker or a recovery-only slot from causing the controller
to close the last known-good standby. Standby names and membership are always
read live.
Before every standby pause and again after the final pause, it re-reads the
complete recovery proof: service and scheduler health, normal Relay count,
120-second clean window, Relay success quorum, and account `7692` proof. If any
part changes in that narrow window, it reopens the active standbys and returns
non-zero.

State is stored in `state.json`:

```json
{
  "schema_version": 3,
  "mode": "normal|failover|maintenance|recovery_pending",
  "healthy_streak": 0,
  "last_reason": "...",
  "proof_after": "RFC3339 or null",
  "takeover_started_at": "RFC3339 or null",
  "last_trigger_at": "RFC3339 or null",
  "healthy_since": "RFC3339 or null",
  "last_unavailable_id": 0,
  "last_unavailable_at": "RFC3339 or null",
  "last_availability_id": 0,
  "last_availability_at": "RFC3339 or null",
  "telemetry_error_streak": 0,
  "effective_zero_streak": 0,
  "updated_at": "RFC3339"
}
```

Schema versions 1 through 3 are read for rollback compatibility. A missing,
malformed, timestamp-invalid, or unknown-version state file is treated as lost
control-plane evidence: reconciliation first opens active, non-deleted standby
capacity, never writes account `7692` or any account status, and atomically
replaces the file with a schema-v3 `failover` record. If a maintenance marker
also exists, the rebuilt mode is `maintenance` instead.

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
The marker does not claim ownership before the account is both paused and
drained. After scheduler exclusion it records a pending PostgreSQL `xmin` only
when this controller actually submitted the pause write; finding an already
paused account never creates ownership. If scheduler exclusion for that
externally paused account is ambiguous, preparation stops with standbys open
rather than repeating the pause and adopting it. After drain it captures the then-current
`xmin` and starts the ownership fence there. This deliberately allows ordinary
in-flight `last_used_at` writes while requests drain, while a later retry can
still prove that the account remains active, runtime-ready and unschedulable
before promoting ownership.
Only pending `account_changed` outbox events block snapshot confirmation;
continuous `account_last_used` traffic is intentionally ignored.

`finish-maintenance` requires codex2api service health before restoring `7692`
when this maintenance run paused it. It proves that `7692` has re-entered every
ready scheduler bucket. If Relay capacity is still zero, standbys stay open.
Otherwise normal reconciliation performs the three-sample recovery confirmation
before pausing standbys.
If the only standby becomes inactive or deleted during maintenance, finish still
restores a healthy maintenance-owned `7692`; it never changes that standby.
Before restoration, `finish-maintenance` requires the owned `xmin` to be
unchanged, the account to remain active, non-deleted, runtime-ready, and still
unschedulable. It repeats that check after its fresh inventory read and
immediately before the admin write. Any observed sub2api, operator, or
background row mutation invalidates ownership: the controller performs no
`7692` write and keeps the marker and standbys open. The sub2api endpoint does
not expose an atomic compare-and-set, so a mutation inside the final network
call remains a bounded external race; the post-write scheduler proof still
fails closed and preserves standby capacity. A legacy owned marker without an
`xmin` is intentionally not restored automatically.

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
