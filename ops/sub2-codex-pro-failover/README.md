# sub2 codex-pro failover controller

This controller keeps the user's `codex2api-pro` bridge as the normal path while
opening only healthy standby accounts when the bridge path cannot safely carry
all traffic.

## Safety boundaries

- The active group is discovered on every run by the exact name `codex-pro`.
  There must be exactly one non-deleted active match. Otherwise the run performs
  no writes.
- Every standby managed by this controller must belong to exactly one active
  group: this `codex-pro` group. Planned maintenance additionally requires the
  configured primary to be an active, non-deleted, exclusive member of that
  same group. Standbys are non-primary members whose account status is `active`,
  whose row is not deleted, and whose active-group count is exactly one.
  `inactive`, `error`, deleted, and shared-group rows are never changed.
- Standby failover changes only the sub2api `schedulable` flag through the admin
  API. It never changes account status, deletion state, credentials, cooldowns,
  or rate-limit state.
- Normal timer reconciliation never changes the configured primary. sub2api
  remains the owner of ordinary bridge health decisions.
- If the configured primary loses its group association, the exact `codex-pro`
  group is still authoritative for standby discovery: reconciliation opens its
  active, non-deleted standbys without attempting a primary write. Planned
  maintenance stops after that protection is ready because it cannot safely own
  a missing primary.
- Planned maintenance re-discovers the active group and re-proves the primary's
  exclusive membership before every primary transition and before every
  standby-open batch. A group-id replacement or primary membership/status drift
  before the primary pause aborts with no primary write. The same confirmed
  drift after a primary write is durable sticky evidence and requires operator
  reconciliation.
- Because sub2api `schedulable` is global rather than group-scoped, a
  schedulable non-primary that later becomes shared is never closed by this
  controller. Reconciliation enters `recovery_pending` with a critical manual
  reason instead of declaring normal. Maintenance may restore an owned primary,
  but retains the bound `RESTORED` marker and `maintenance` state until the
  shared membership or schedulability is reconciled externally.
- A standby is considered ready only after the database and scheduler outbox
  agree, its Redis scheduler metadata is active and unblocked, and every ready
  group OpenAI scheduler bucket contains at least one eligible standby.
- Redis scheduler reads are three-state: present, absent, or error. A Redis
  command error can never be treated as an absent account or silently remove a
  bucket from the proof set.
- Opening is best-effort across every active, non-deleted, single-active-group
  standby discovered in
  one live inventory snapshot, with runtime-ready accounts attempted first. The
  initial snapshot defines the dynamic work set, and membership, active-group
  count, status, and deletion state are re-read before each batch so an
  operator-paused, removed, shared, or newly inactive account is skipped before
  submission.
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

- the configured primary is not active, is deleted, or is not schedulable;
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
the configured primary active, schedulable, free of current database and Redis scheduling blocks,
present in every ready group OpenAI scheduler bucket, service status `ok`, at
least two normal Relay entrances (or all enabled entrances when fewer than two
exist), positive effective slots throughout the healthy recovery interval, and
zero `suspect`, `recovery_only`, `circuit_open`, and `last_resort` entrances.
Recovery additionally requires a 120-second window with zero canonical
`relay_route_unavailable` finals and zero supported canonical Relay terminal
failures, at least 20 canonical non-probe Relay successes after the proof
watermark and latest terminal failure, and at least
two successful primary-account requests later than its most recent error with
no new primary-account upstream 5xx in the last 60 seconds. This prevents an invisible
in-process runtime breaker or a recovery-only slot from causing the controller
to close the last known-good standby. Standby names and membership are always
read live.
Before every standby pause and again after the final pause, it re-reads the
complete recovery proof: service and scheduler health, normal Relay count,
120-second clean window, Relay success quorum, and primary-account proof. If any
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

This operational guardian state intentionally remains schema 3; it is distinct
from the schema-v5 maintenance ownership marker described below.

Schema versions 1 through 3 are read for rollback compatibility. A missing,
malformed, timestamp-invalid, or unknown-version state file is treated as lost
control-plane evidence: reconciliation first opens active, non-deleted standby
capacity, never writes the configured primary or any account status, and atomically
replaces the file with a schema-v3 `failover` record. If a maintenance marker
also exists, the rebuilt mode is `maintenance` instead.

## Planned maintenance

Use the explicit maintenance commands for a codex2api rebuild. They are the only
commands allowed to change the configured primary:

```bash
sub2-codex-pro-failover prepare-maintenance
# rebuild or recreate codex2api
sub2-codex-pro-failover finish-maintenance
```

`prepare-maintenance` first opens and proves all active standbys. Only after
those writes have converged does it establish the maintenance evidence boundary:
it verifies sub2api runtime logging is `debug` or `info` with sampling disabled,
records the sub2 container incarnation and sink drop/failure counters, submits a
high-entropy read-only FIFO sentinel, waits for that sentinel's exact durable
`http.access` receipt, and uses its log id as the maintenance watermark. It then
writes the schema-v5 marker. This ordering keeps the controller's own initial
standby writes outside the ownership audit window.

The schema-v5 maintenance marker is a write-ahead state machine:

```text
PREPARING -> EXTERNAL_PAUSED
PREPARING -> PAUSE_INTENT -> PAUSE_ACKED
PAUSE_ACKED -> SEAL_INTENT -> SEAL_ACKED -> OWNED
OWNED -> RESTORE_INTENT -> RESTORE_ACKED -> RESTORED
pre-ownership failure -> PAUSE_AMBIGUOUS
restore failure -> RESTORE_AMBIGUOUS
```

The marker immutably binds its run id to the configured primary account id and
the discovered sub2api group id. The ambiguity sidecar carries the same identity
and run id. Every later prepare, finish, reconcile, or status process validates
all present artifacts against each other and against its current configuration
before any account write. A changed config, legacy unbound artifact, malformed
identity, or marker/sidecar conflict fails closed with an operator-required
event and zero account writes; it is never adopted as ownership or passed to
generic fail-open rebuild logic. Primary-account rotation is therefore allowed
only when no maintenance marker or ambiguity sidecar exists.

Every primary mutation has a fresh random request id no longer than 64 ASCII
characters. The controller proves that id is absent before use and writes the
corresponding `*_INTENT` atomically before submitting the request. A synchronous
HTTP 200 is structurally validated for account id, schedulable value, active
status and timezone-aware `updated_at`. The asynchronous logger must then
produce exactly one durable `http.access` row with the same request id, method,
path and status 200. Receipt evaluation has four outcomes: exact success;
bounded absence at the 90-second deadline; a structured definitive conflict
such as duplicate/non-200 evidence; or a temporarily unverifiable read. A
read-side database, runtime-control, or receipt-query failure retains the exact
INTENT byte-for-byte and a later invocation only rechecks that request id; it
does not replay the primary write. Deadline expiry and definitive conflict are
sticky because the already-issued write cannot be adopted safely.

The idempotent ownership seal is stricter: immediately after its validated 200
response, the controller atomically checkpoints that response's `updated_at`
generation while remaining in `SEAL_INTENT`, then waits for the durable receipt.
This makes a read-outage restart safe without resending the seal. If the response
generation was not durably checkpointed, a later receipt is insufficient—the
controller poisons the run rather than guessing the current database timestamp.

After the pause receipt, the controller proves scheduler exclusion and observes
two zero-concurrency samples, waits an additional 10 seconds for deferred
last-used persistence, and proves the drain again. It then sends the second
idempotent `schedulable=false` seal. Ownership is granted only when the seal
response timestamp agrees with the full Redis `sched:acc:<id>` control object
and with the database `updated_at`, and the database `(updated_at, xmin)`
tuple plus scheduler snapshot remain unchanged across two confirmations. Redis
`sched:meta:<id>` and bucket membership are convergence evidence only; their
metadata is not treated as a durable mutation generation.

Before each ownership transition and before restoration, a new read-only FIFO
sentinel is sent to the admin log-health endpoint. Once its exact receipt is
durable, all earlier enqueued access events are known to have crossed the single
sink worker. The controller scans from the bootstrap watermark through that
sentinel log id. Every mutating `/api/v1/admin/%` request is a foreign conflict
except:

- this run's exact pause, seal or restore POST to the configured primary
  `/accounts/<primary>/schedulable`; and
- this controller's exact standby-open POST to
  `/accounts/<other-id>/schedulable`, only when the request id is
  `c2m-<this-run-uuid>-b-<other-id>`, `other-id` is the same canonical positive
  PostgreSQL bigint in the path, and the target is not the configured primary.

Bulk import/update, log cleanup, runtime-logging changes, malformed account-id
paths and future unknown admin mutations therefore fail closed. A completed
HTTP 4xx admin request is a confirmed rejection and remains auditable but is not
classified as a completed mutation; 2xx writes and 5xx/missing-status outcomes
remain fenced. If that completed foreign event is durably ordered before the
controller has written `PAUSE_INTENT` or issued any primary mutation, the run
stops in `PREPARING`, keeps standby protection open, and creates no ownership
ambiguity sidecar because the controller has not touched the primary. Its
immutable watermark deliberately prevents that attempt from silently adopting
the foreign change; operator reconciliation is required before starting a new
maintenance lifecycle. Any such conflict after a primary intent is recorded as
sticky ambiguity. The logging level/sampling gate, container incarnation, sink
dropped counter and sink write failure counter are rechecked throughout.
Ordinary background access traffic may continue; correctness does not depend on
a globally empty log queue or a stable global written count. The controller
never changes sub2api logging configuration.

There is intentionally no automatic PREPARING rebase. Do not delete or rename
the marker merely to make the command pass. A manual rebase is allowed only when
the blocking event reports `primary_writes=0` and `phase=PREPARING`, and all of
the following checks succeed while the recurring timer is stopped:

```bash
systemctl stop codex2api-sub2-codex-pro-failover.timer
timeout 180s sh -c 'while systemctl is-active --quiet \
  codex2api-sub2-codex-pro-failover.service; do sleep 1; done'

SUB2_ADMIN_KEY_FILE=/root/.sub2api_admin.key \
  /usr/local/libexec/codex2api-sub2-codex-pro-failover status |
  jq -e 'select(.reason == "status_snapshot") |
    .details.primary_status == "active" and
    .details.primary_schedulable == true and
    .details.schedulable_backups >= 1'

state=/var/lib/codex2api-sub2-codex-pro-failover
test ! -e "$state/maintenance-ambiguous.json"
jq -e '.schema_version == 5 and .phase == "PREPARING" and
  .pause_request_id == null and .pause_log_id == null and
  .seal_request_id == null and .seal_log_id == null and
  .restore_request_id == null and .restore_log_id == null' \
  "$state/maintenance.json"
```

Successful `status` also proves that the configured primary still has the exact
active-group identity bound into the marker; status fails before printing its
snapshot if identity or exclusive membership differs. After separately
reviewing the foreign admin event, archive rather than delete the old marker,
then start a new lifecycle:

```bash
install -d -m 0700 "$state/archive"
run_id="$(jq -r '.run_id' "$state/maintenance.json")"
mv -- "$state/maintenance.json" "$state/archive/maintenance.$run_id.json"

# Start the new lifecycle through the wrapper, supplying the actual maintenance
# command after `--`; restore the timer after that lifecycle succeeds.
/usr/local/sbin/codex2api-safe-maintenance -- <maintenance-command>
systemctl start codex2api-sub2-codex-pro-failover.timer
```

If any check fails, leave both marker and standby protection intact, restart the
timer, and investigate manually. Never archive a marker with an ambiguity
sidecar or any pause, seal, restore, or owned evidence.

Standby readiness is re-proved immediately before the primary pause, during
each drain poll, before the ownership seal, during both post-seal ownership
confirmations, immediately before persisting `OWNED`, and immediately after it.
If standby capacity cannot be proven at any fence, the controller attempts to
reopen eligible standbys and aborts that invocation. Before a primary pause, the
primary remains untouched. After a pause, temporary group/API/database/Redis
read failures, scheduler non-convergence, and the 600-second drain deadline
retain `PAUSE_ACKED` (or the current acknowledged phase) for retry. Only a
confirmed group drift, external admin write, explicit primary-state/tuple
conflict, or unknown/invalid write outcome becomes sticky-ambiguous and can
never claim or silently restore ownership. The seal's database tuple fences run
before scheduler-cache generation checks, so a confirmed DB generation change
cannot be hidden behind a retryable cache-convergence error; a cache-only
mismatch with the exact DB tuple still intact remains retryable.

Any known ambiguous outcome is first recorded in an independently fsynced
`maintenance-ambiguous.json` poison sidecar and, where the current phase has a
main-marker ambiguity transition, then reflected in that marker. Even if the
main-marker replacement fails, later prepare/finish calls refuse to
recover the intent. Only a structurally valid schema-v5 marker or schema-v2
sidecar whose run, primary and group identities agree is actionable maintenance
evidence; reconciliation keeps eligible exclusive standbys open and never
clears a valid sidecar automatically. A malformed, unknown-version, legacy
unbound, identity-mismatched, or mutually conflicting artifact causes a
read-only operator-required abort with zero account writes. Such artifacts are
never upgraded into ownership or passed through generic lost-state recovery.

An account already paused before this run becomes `EXTERNAL_PAUSED`. The
controller never adopts or restores it. Finish retains the marker and standby
protection until an external actor restores the primary; it may then observe
full scheduler convergence and clear the marker without issuing a primary
write. For an `OWNED` run, finish restores the primary only after the exact
receipts, FIFO foreign-write fence, logging/sink/incarnation evidence, scheduler
state and recorded database tuple still agree. If the only standby became
inactive or deleted, a healthy owned primary is still restored and that standby
is never modified; the result is recorded as primary-only recovery.

Explicit prepare/finish operations use 90-second scheduler-snapshot and receipt
budgets. Normal timer reconciliation keeps its 20-second snapshot budget, and
the primary drain proof has a 600-second budget followed by a 10-second deferred
settle interval and a second 600-second proof. These maintenance budgets cover
observed in-flight requests, scheduler convergence, and async-log propagation
without slowing the 10-second recurring failover loop.

Scheduler convergence is deliberately asymmetric. Standby protection is not
accepted until every current ready bucket exposes at least one active account
whose PostgreSQL row and both Redis account projections (`sched:meta` and
`sched:acc`) are schedulable. Disabling an account is accepted after two
consecutive observations that
PostgreSQL and both Redis projections expose it as unschedulable. sub2 checks
those projections (and the current database row on fallback/acquire paths)
before dispatch, so an old ZSET member cannot admit new work. Consumed outbox
rows and bucket removal may trail this safety fence and are diagnostic cleanup
state only; they never cause a logically paused standby to be reopened. Existing
requests that entered before the pause may finish normally, while the primary
maintenance drain remains a separate explicit proof when zero in-flight work is
required.

The sub2api endpoint does not expose atomic compare-and-set. A third-party write
after the final FIFO sentinel/tuple check but before the primary API call is
therefore an irreducible bounded race without an upstream CAS. The two primary
writes themselves are also not one database/outbox/cache transaction. Crash,
timeout, malformed-response, logger-loss, runtime-restart and longer concurrent
admin-write windows fail closed as described above.
Maintenance commands wait a bounded 30 seconds for the shared controller lock
and fail non-zero on contention. Timer reconciliation and status commands may
instead skip harmlessly when another run owns the lock.
`safe-maintenance` also holds a separate lifecycle lock across prepare, the
wrapped rebuild command, and finish, so a second `safe-maintenance` lifecycle
cannot overlap. A direct `prepare-maintenance` or `finish-maintenance` process
holds only the bounded controller lock for its own invocation; operators must
not interleave direct lifecycle commands with a running wrapper.

The wrapper performs the same sequence around one command:

```bash
safe-maintenance -- docker compose up -d --no-deps --force-recreate codex2api
```

If the wrapped command or recovery validation fails, the marker and standbys are
intentionally left in place. This controller never calls a legacy bridge-reset
helper.

`BRIDGE_ACCOUNT_ID` is mandatory and has no compiled or account-name-derived
default. The systemd unit reads it from the required, non-secret environment
file `/etc/default/codex2api-sub2-codex-pro-failover`. Direct controller and
`safe-maintenance` invocations use the same file when the variable is not
already present in their environment. The controller parses only one exact
`BRIDGE_ACCOUNT_ID=<positive PostgreSQL bigint>` assignment; it never sources
or executes the file. Missing, duplicate, empty, malformed, or out-of-range
values fail with exit status 64 before any state or account write. An explicit
environment value takes precedence, which allows isolated tests and controlled
one-off recovery without editing the shared file.

After acquiring its lifecycle lock, `safe-maintenance` performs the same strict
parse once and exports the validated id to `prepare-maintenance`, the wrapped
command, and `finish-maintenance`. Editing the file during a rebuild therefore
cannot split one lifecycle across two primaries; the new value applies only to
a later process, where marker identity validation still prevents accidental
adoption after a crash.

The supplied `.env.example` intentionally leaves `BRIDGE_ACCOUNT_ID=` empty so
no deployment-specific account id is committed to the repository. Installation
must write the currently selected positive numeric id to the `/etc/default`
file before enabling the unit. Release automation must create that file
atomically only when absent, preserve an existing operator-selected value,
validate the id, and never infer it from a mutable account name. If the bridge
account is replaced, first verify that neither `maintenance.json` nor
`maintenance-ambiguous.json` exists, then update this one file deliberately
before restarting the timer or running maintenance. An existing marker or
sidecar is identity-bound and deliberately blocks account-id rotation until the
old maintenance lifecycle is reconciled.

The admin key is supplied to the systemd service with `LoadCredential`; it is not
stored in environment variables or emitted in logs.
Its temporary curl header file is mode `0600`, removed by normal and signal/exit
cleanup, and stale crash leftovers are removed only after the controller has
acquired its exclusive lock.
