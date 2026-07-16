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
  Standby schedulability writes run in bounded batches of four, each ordinary
  local admin request has a five-second timeout, and the full submission phase has a 120-second
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
from the schema-v7 maintenance ownership marker described below.

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
writes the schema-v7 marker. This ordering keeps the controller's own initial
standby writes outside the ownership audit window.

The schema-v7 maintenance marker is a write-ahead state machine:

```text
PREPARING -> EXTERNAL_PAUSED
PREPARING -> PAUSE_INTENT -> PAUSE_ACKED
PAUSE_ACKED -> SEAL_INTENT -> SEAL_ACKED -> OWNED
OWNED -> RESTORE_INTENT -> RESTORE_ACKED -> RESTORED
pre-ownership failure -> PAUSE_AMBIGUOUS
restore failure -> RESTORE_AMBIGUOUS
```

Schema v7 deliberately does not adopt any active schema-v1 through schema-v6
maintenance marker, and sidecar schema v3 does not adopt schema-v1 or schema-v2.
Before upgrading the controller, the release gate must prove that both
`maintenance.json` and `maintenance-ambiguous.json` are absent. If either is
present, finish or reconcile that lifecycle with the old controller first;
replacing it in place would fail closed and leave standby protection open.

The marker immutably binds its run id to the configured primary account id, the
discovered sub2api group id, the sorted complete set of member account IDs, and
the sorted active/non-deleted backup IDs seen at marker creation. The full member
set includes inactive/deleted members and prevents a later account DELETE from
escaping the fence after its membership row is cascade-deleted. A SHA-256 digest
covers those collections plus the runtime/log watermark baseline. Sidecar schema
v3 copies both collections and the same digest. When both artifacts exist they
must match exactly. When only the sidecar survives, the current primary, group,
full member IDs, and active backup IDs must exactly match its sealed identity
before even a standby-open write is allowed. Any drift, changed config, legacy
or malformed artifact, or marker/sidecar conflict fails closed with an
operator-required event and zero account writes; it is never adopted as
ownership or passed to generic fail-open rebuild logic. Primary-account rotation
is therefore allowed only when no maintenance marker or ambiguity sidecar exists.

Once a marker exists, every standby readiness check and every standby
schedulable write is restricted to the marker's sealed backup IDs intersected
with the still-active/non-deleted backup inventory. A sealed standby that later
becomes ineligible is skipped and is never reactivated or changed. Conversely,
an inactive member that becomes newly eligible was not part of the sealed
maintenance backup collection: prepare, finish, reconcile, and status all stop
with an operator-required zero-write event before touching the primary. The
controller never opens, closes, or adopts that unsealed account merely because
it is now eligible.

Every primary mutation has a fresh random request id no longer than 64 ASCII
characters. The controller proves that id is absent before use and atomically
writes the corresponding `*_INTENT` with response checkpoint `pending` before
submitting the request. After the call returns, a same-phase compare-and-swap
persists exactly one result: `validated` plus the canonical response `updated_at`,
`transport_or_non200`, or `invalid`. A synchronous HTTP 200 is validated for
account id, schedulable value, active status and timezone-aware `updated_at`.
Only a durably persisted `validated` checkpoint may continue automatically. A
crash that leaves `pending`, or any transport/non-200/malformed outcome, creates
the poison sidecar before any receipt lookup on the next invocation; a receipt
alone can never erase the missing response-body evidence.

After a validated checkpoint, the asynchronous logger must produce exactly one
durable `http.access` row with the same request id, method, path and status 200.
Receipt evaluation has four outcomes: exact success; bounded absence at the
90-second deadline; a structured definitive conflict such as duplicate/non-200
evidence; or a temporarily unverifiable read. A read-side database,
runtime-control, or receipt-query failure retains the exact validated INTENT and
a later invocation only rechecks that request id; it does not replay the primary
write. Deadline expiry and definitive conflict are sticky.

The idempotent ownership seal also atomically checkpoints its validated response
`updated_at` while remaining in `SEAL_INTENT`, before waiting for the durable
receipt. Pause convergence is bound to the pause response generation before the
drain, and ordinary restore convergence is bound to the restore response
generation. The explicit restore-ambiguity resolver records
`explicitly_resolved` with no fabricated response timestamp after its stronger
repeated receipt, FIFO-fence, membership and live-state proof. If the response
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

PostgreSQL `accounts.updated_at` is the authoritative mutation generation and
has microsecond precision. sub2 may serialize that same value through Go/Redis
RFC3339 with zero through nine fractional digits and either `Z` or a numeric
timezone offset. Runtime comparisons therefore normalize valid values to UTC
with exactly six fractional digits. Seven-to-nine digit fractions are
intentionally truncated to the database's microsecond boundary; they do not
create nanosecond ownership identity. Missing timezones, malformed values, and
out-of-range timestamps fail closed. Persisted maintenance markers and poison
sidecars remain stricter canonical UTC-microsecond `.<six digits>Z` artifacts.

Before each ownership transition and before restoration, a new read-only FIFO
sentinel is sent to the admin log-health endpoint. Once its exact receipt is
durable, all earlier enqueued access events are known to have crossed the single
sink worker. The controller scans from the bootstrap watermark through that
sentinel log id. Every mutating `/api/v1/admin/%` request is a foreign conflict
except:

- a pause, seal, or restore POST to the configured primary only when its exact
  durable tuple--log id, persisted marker request id, method, primary account
  path, and HTTP 200 status--matches that operation's receipt recorded in the
  marker;
- while explicitly resolving restore ambiguity, the one unique 2xx restore
  candidate is allowed only as a call-scoped exact tuple containing its candidate
  log id, marker request id, method, and primary path in both foreign-write
  fences; it is not persisted or adopted until the final marker compare-and-swap;
- the exact read-only `POST /api/v1/admin/accounts/today-stats/batch`.

There is deliberately no post-watermark standby-write exemption based on a
`c2m-<run>-b-<account>` request-id pattern: a request-id-shaped string is not a
durable ownership receipt. Initial normal standby opens occur before the
watermark and therefore remain outside the audit window. A marker-time safety
reopen may preserve service, but any such post-watermark standby write poisons
ownership and later restoration fails closed because schema v7 has no exact
standby receipt manifest.

Every account-item `PUT`, `PATCH`, or `DELETE` remains fail-closed. A
current-state query cannot prove that an account was not added to and removed
from the group inside the maintenance window, so terminal state is never used
as a substitute for mutation history.

Bulk import/update, log cleanup, runtime-logging changes, malformed account-id
paths, primary/member account changes, group changes, and future unknown admin
mutations therefore fail closed. Failure to discover the unique active group or
to read its live membership also fails closed; it can never turn an account
write into an exemption. A completed
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
jq -e '.schema_version == 7 and .phase == "PREPARING" and
  .pause_request_id == null and .pause_log_id == null and
  .pause_response_checkpoint == "none" and
  .pause_response_updated_at == null and
  .seal_request_id == null and .seal_log_id == null and
  .restore_request_id == null and .restore_log_id == null and
  .restore_response_checkpoint == "none" and
  .restore_response_updated_at == null' \
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
recover the intent. Only a structurally valid schema-v7 marker or schema-v3
sidecar is actionable maintenance evidence. When both exist, their run, primary,
group, full member IDs, backup IDs, digest and lifecycle phases must agree. A
standalone sidecar additionally requires the current full member and active
backup sets to equal its sealed collections before reconciliation can open a
standby. Reconciliation never clears a valid sidecar automatically. A malformed,
unknown-version, legacy, identity-mismatched, drifted, or mutually conflicting
artifact causes a read-only operator-required abort with zero account writes.
Such artifacts are never upgraded into ownership or passed through generic
lost-state recovery.

One narrowly defined seal timeout has an explicit evidence-backed recovery
path; it is never used automatically by `prepare-maintenance`:

```bash
sub2-codex-pro-failover resolve-seal-ambiguity
sub2-codex-pro-failover prepare-maintenance
```

The command accepts only a schema-v7 marker in `PAUSE_AMBIGUOUS` plus the
identity-matched schema-v3 sidecar whose original phase is `SEAL_INTENT` and
whose reason is exactly
`ownership_seal_response_not_durable_backups_left_open`. It issues no account
write and never opens a standby. The resolver requires the already recorded
pause receipt, one exact HTTP 200 seal access receipt, one exact
`audit_logs` row whose action, route, account id and request body prove
`schedulable=false`, and exactly one occurrence of both maintenance request
ids. The adopted PostgreSQL generation must be strictly later than the pause
generation, no later than the audit row, and close enough to the audit row to
fit that row's measured request latency plus a one-second clock/commit
tolerance. The access completion must be no earlier than the audit row.

The primary must remain active, unschedulable and at zero concurrency. Its
PostgreSQL `updated_at/xmin`, Redis full-account generation, scheduler snapshot,
sealed group/member identity, ready standby proof, sub2 incarnation,
unsampled info/debug logging and sink counters must agree across two FIFO
foreign-write fences. Seal and audit records are reread after each fence and
must return the identical structured evidence tuple. Any duplicate, missing,
non-200, malformed, chronologically impossible, foreign-write, membership,
tuple, cache, runtime, logging or sink evidence leaves the marker and sidecar
unchanged.

This proof covers the supported sub2 admin API path and any database tuple
change that occurs while the resolver is running. Admin API writes are ordered
behind the FIFO sentinels and therefore appear as foreign access records unless
they are the one exact pause or seal receipt. The current audit/access schemas
do not contain the response `updated_at` or PostgreSQL `xmin`, so a privileged
actor who bypasses the API and directly changes the account row before the
resolver starts, emits no access/audit record, and leaves `updated_at` inside
the original seal latency window is not distinguishable from the seal write.
Direct database edits are therefore unsupported while a maintenance marker or
ambiguity sidecar exists; operators must not run this resolver after such an
out-of-band edit. The success event records this evidence scope explicitly.

Only the final marker compare-and-swap records `seal_log_id` and
`seal_response_updated_at` and advances to `SEAL_ACKED`; the sidecar is removed
after a final on-disk identity reread. If the process stops between those two
durable operations, the only accepted retry shape is the exact
`SEAL_ACKED` marker plus the original `SEAL_INTENT` sidecar and reason. The
resolver repeats the complete read-only proof, then removes the sidecar. No
other phase/reason pair is adopted.

`RESTORE_AMBIGUOUS` has one explicit evidence-backed recovery path; it is never
used automatically by `finish-maintenance`:

```bash
sub2-codex-pro-failover resolve-restore-ambiguity
sub2-codex-pro-failover finish-maintenance
```

The resolver issues no account write. It requires the identity-bound marker and
restore-phase poison sidecar (including a valid reason and timestamp), exact
unique pause/seal receipts, exactly one durable 2xx receipt
for the already-issued restore request, a live active and schedulable primary,
an unchanged full group-member control snapshot, and two clean FIFO foreign
mutation fences. Primary/member, bulk, group, malformed, or unknown writes still
block it. The candidate's exact log id is passed only to those two fence calls,
and uniqueness is proved again around them; it is never pre-adopted into the
marker. A second row with the same request id, a different log id, a 5xx or
missing status, or an intervening reverse/ABA write is therefore foreign even
when the final visible schedulable value looks correct. On success, and only in
the final marker compare-and-swap, the controller records `RESTORE_ACKED` with
`restore_response_checkpoint=explicitly_resolved`, leaves the response
generation empty, and then removes only the ambiguity sidecar. The ordinary
finish path rechecks health and all evidence before it can clear the maintenance
marker. Duplicate/non-2xx receipts, an unschedulable primary, group drift, a
non-restore sidecar phase, or any unverifiable evidence leave both artifacts
intact. After adoption, ordinary finish continues to
validate that same unique 2xx restore receipt; pause, seal, and all automatic
receipt paths remain strict HTTP 200.

An account already paused before this run becomes `EXTERNAL_PAUSED`. The
controller never adopts or restores it. Finish retains the marker and standby
protection until an external actor restores the primary; it may then observe
full scheduler convergence and clear the marker without issuing a primary
write. For an `OWNED` run, finish restores the primary only after the exact
receipts, FIFO foreign-write fence, logging/sink/incarnation evidence, scheduler
state and recorded database tuple still agree. A standby that becomes inactive
but remains in the same group is never reactivated or modified; a healthy owned
primary may still be restored as primary-only recovery. Removing or deleting a
sealed member changes the group identity and now fails closed for operator
reconciliation, even if account deletion already cascaded its membership row. A
previously inactive member that becomes an active backup during the sealed run
is likewise never opened or closed: its absence from the sealed backup
collection forces the zero-write operator path before primary restoration.

Explicit prepare/finish operations use 90-second scheduler-snapshot and receipt
budgets. Normal timer reconciliation keeps its 20-second snapshot budget, and
the primary drain proof has a 600-second budget followed by a 10-second deferred
settle interval and a second 600-second proof. These maintenance budgets cover
observed in-flight requests, scheduler convergence, and async-log propagation
without slowing the 10-second recurring failover loop.

Ordinary sub2 admin calls retain the five-second
`SUB2_ADMIN_REQUEST_TIMEOUT_SECONDS` default. Only maintenance-owned primary
pause/seal/restore calls use the separate
`PRIMARY_ADMIN_REQUEST_TIMEOUT_SECONDS` default of 20 seconds. This absorbs
observed primary admin latency without slowing standby batches or timer
reconciliation.

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

Each parallel standby-open child now reloads the live inventory and revalidates
active, non-deleted, single-group and sealed eligibility immediately before its
POST. This closes the parent-snapshot-to-child-submit window, but eligibility
can still change in the final microseconds between that last read and the write.
Absolute mutual exclusion requires a sub2 service-side compare-and-set or lease
that binds the POST to the validated eligibility generation; this controller
hardening does not add that server primitive.

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

`safe-maintenance -h` and `safe-maintenance --help` are pure help paths. Missing
commands and unknown wrapper options exit 64 before creating runtime state,
taking a lifecycle lock, reading primary configuration, or calling prepare.

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
