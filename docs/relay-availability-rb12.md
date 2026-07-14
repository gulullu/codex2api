# Relay availability protection (rb12)

## Problem statement

A Relay account represents a front door, not necessarily one upstream account.
The previous circuit breaker removed the whole front door after one
502/504/Cloudflare gateway response. Recovery then allowed only one in-flight
probe and required three serial successes. A transient gateway response could
therefore remove a large healthy pool for minutes.

The sub2 failover controller compounded the problem. It trusted the legacy
`relay.schedulable` count, which treated an idle half-open circuit as normal
capacity, and it did not inspect final `relay_route_unavailable` logical
requests. During the 2026-07-13 incident this kept standby accounts paused while
694 final logical requests failed.

## Safety goals

1. One isolated gateway or transport error never removes a healthy Relay front door.
2. A genuinely dead front door is isolated after bounded, independent evidence.
3. A request never retries the same failed front door and never replays after
   downstream output has started.
4. Recovery traffic is bounded but cannot be blocked by one long request.
5. The last usable Relay path remains available at a small last-resort limit
   until sub2 standby capacity is confirmed.
6. sub2 failover reacts to final logical route exhaustion rather than retry
   attempts, probes, or nominal half-open capacity.
7. Automatic failover changes only `schedulable` on active, non-deleted standby
   accounts. It never changes account status and never changes account 7692.
8. Unknown telemetry or corrupt controller state may open or keep standby
   capacity, but may never close it.
9. Membership, credential, endpoint and Relay-group changes start a new health
   epoch; late results and persisted state from the old epoch cannot leak in.
10. Runtime records remain readable by the pre-rb12 rollback image.

## Front-door circuit states

### closed

Normal scheduling. Successful and breaker-owned terminal outcomes are retained
in a bounded rolling evidence window.

### suspect

The first strong gateway or upstream transport failure enters suspect. Strong
transport evidence includes DNS/TLS/connect failures, upstream request timeout,
and an upstream stream ending without a terminal event. It explicitly excludes
client cancellation, downstream write failure, the soft first-token guard and
WebSocket message-too-big fallback. WebSocket close 1008 (`policy violation`)
is classified separately as `websocket_policy`: it still schedules the existing
asynchronous auth verification, but it is not retried across accounts, does not
penalize general account health, and cannot enter or open the Relay breaker.
Close 1006 and 1011 remain strong upstream transport evidence.

The failed logical request
hard-excludes this front door and may retry another front door, while new
requests remain admitted at a small bounded concurrency. A success from a
request issued after suspect began clears the state.

A confirmed open requires independent post-suspect evidence, not merely old
concurrent requests completing out of order. This prevents a burst of stale
failures from removing an otherwise successful high-volume pool.

If one request succeeds first and closes suspect while other requests from that
same bounded cohort later fail, those late failures start a fresh suspect
evidence cycle. They are not discarded, but their old evidence epoch cannot by
itself satisfy the post-suspect quorum.

Late 500/503 outcomes from that bounded cohort are also retained in the rolling
weak-failure window, and late successes are retained symmetrically as its
denominator. This makes the 50% decision independent of completion order.
Permits from the older unrestricted closed cohort are deliberately not replayed
into the next generation: only canonical, bounded, non-probe permits exactly one
generation old are accepted, so a large stale batch cannot flood fresh state.

### open

Confirmed failures temporarily fence the front door. The first open interval is
short. Repeated probation failure uses bounded exponential backoff.

### probation

After the open interval, a small number of concurrent recovery requests are
allowed. Multiple probes avoid one long streaming request occupying the only
recovery lease. Successful probes close the circuit; a breaker-owned failure
reopens it.

### last resort

If opening a front door would remove the last normal Relay capacity, the front
door stays selectable at a strict concurrency cap. This is a pool safety fence,
not a declaration that the upstream is healthy. Final route exhaustion still
causes sub2 standby takeover.

A breaker last-resort front is placed in the same low scheduling class as a
Guardian last-resort front. It is used only when no normal eligible front has
capacity; a recovered normal peer immediately takes precedence even when the
last-resort front has a higher official scheduler priority.

Last-resort ownership is scoped to the same request eligibility class used by
the scheduler (API-key policy, Relay traffic class and model eligibility). One
failed request can promote at most one front in its class. A front that is
manually paused, removed, or ineligible for the current key/model cannot block a
different class from retaining its own last usable path.

"Normal capacity" is model-, Relay-traffic-class- and API-key-specific. A peer must pass
the same model support, model mapping, model cooldown and routing filter, and it
must be allowed by the account API-key allowlist and the key group/plan policy,
and it must be in a stable Guardian state. Session-owner affinity is intentionally not
part of this pool test: a failed non-replayable continuation cannot switch owner
inside its current logical request, while isolating that repeatedly failing
owner still protects ordinary traffic. Guardian half-open, probation, temporary
bypass and Guardian last-resort entrances are recovery capacity, not proof that
another front door can be removed safely.

For an exact `previous_response_id` owner, transport failure is still recorded
but the current logical request never switches owners and never sticky-replays
the uncertain operation. The client receives the existing owner-unavailable
response and may resend full context explicitly.

The same no-replay rule applies when an owner-bound `encrypted_content` request
hits the optional soft first-token timeout. Since the owner may already be
executing, rb12 returns one canonical 504, retains the encrypted owner/pin, and
does not replay to the owner, switch accounts, or downgrade opaque context. A
request that combines `previous_response_id` and `encrypted_content` follows
this stricter rule. Ordinary requests without opaque owner state keep the
configured soft-timeout rotation behavior.

## Membership and configuration epochs

Leaving or joining the Relay group, changing the configured Relay group, or
changing a front base URL, API key, proxy, custom headers or client metadata
mode clears breaker and Guardian runtime state. Existing permits are revoked,
generation/revision fences advance, and a failed Redis delete is overwritten by
a closed tombstone. Display-name and model-list edits do not erase valid front
health evidence.

Persisted circuit records carry a SHA-256 identity fingerprint, never plaintext
credentials. A restart discards an open record whose fingerprint no longer
matches the loaded front. For safe rollback, rb12 writes in-memory `probation`
and durable last-resort as the legacy wire state `half_open`; rb12 restores the
new semantics while the pre-rb12 image can still recover instead of failing
closed on an unknown state.

The breaker permit, quorum and last-resort counters are process-local. Redis is
restart durability, not a distributed compare-and-swap coordinator. This is
correct for the current single codex2api runtime. Horizontal codex2api replicas
must not be enabled until those admission decisions have a shared coordinator
or traffic is partitioned so each Relay front has one breaker owner.

## Guardian mode and health capacity

- `off` ignores all Guardian execution state and scheduling hints.
- `monitor` may expose a `would_quarantine` shadow warning, but it never changes
  normal capacity, recovery capacity or effective slots.
- `enforce` is the only mode where quarantine, recovery and Guardian concurrency
  hints affect `/health.relay` capacity.

## sub2 takeover signals

The controller ranks all usage rows globally by `logical_request_id`, keeps the
last row, and only then filters the configured Relay group. Attempts marked
`guardian_attempt_only`, probes, and upstream failures later absorbed by a
successful retry do not trigger takeover.

Standby takeover is triggered when either stable Relay capacity is zero or a
short window contains multiple final `relay_route_unavailable` requests.
The newest final failure `(created_at,id)` tuple is persisted as a watermark so
an old burst cannot retrigger forever even when database sequence order differs
from commit order. Canonical final transport failures are written as HTTP 502
with `guardian_attempt_only=false`; hidden attempts remain attempt-only.

The controller also watches a unified user-visible Relay availability stream.
It first chooses the newest visible final globally for each non-empty logical
request ID and only then filters the current Relay group, OpenAI Responses
account type and non-probe routes. Two distinct finals within a sliding
15-second window trigger standby takeover when the newest event is no older
than 60 seconds. The stream contains `relay_route_unavailable`, 502/503/504,
verified upstream-account 429 rate-limit kinds, and rollback-compatible 598
transport/timeouts; ordinary 500, policy/content rejections, local account-zero
429, probes and hidden attempts are excluded. Exact route-unavailable retains
its separate three-in-120-seconds sparse trigger. Every supported terminal
failure, including a single event below the takeover threshold, advances its
own `(created_at,id)` watermark and restarts the 120-second recovery-clean
window.

The internal stream-break marker 598 is never a canonical client-visible or
final audit status. A real upstream request/stream transport failure is finalized
as 502; only the local soft first-token guard is finalized as 504. If a hidden
retry hard-excludes the last eligible front door, account selection exhaustion
preserves that last real 502/504/HTTP upstream failure as the canonical result;
`relay_route_unavailable` is reserved for requests that could not start any real
upstream attempt. This produces exactly one non-attempt-only logical result.

Before any downstream stream byte/frame, final transport failure is returned as
an explicit HTTP/WS error instead of an empty 200. After downstream output has
started, replay remains forbidden. In particular, an Anthropic-compatible
partial stream ends with an Anthropic `error` SSE event; it must never synthesize
`message_stop` or `end_turn` for a truncated upstream stream.

Semantic `response.failed` client rejections are not availability failures.
`cyber_policy` (including nested `codex_error_info` or message-only signals),
`content_policy`, `content_filter`, `safety` and `policy_violation` are finalized
as 400. Without an explicit upstream status, `payload_too_large`,
`request_too_large` and `message_too_large` are finalized as 413. These outcomes
are never transparently retried, never rotate the rejection across Relay front
doors, and do not contribute breaker evidence.

For malformed upstream responses that omit the structured error code, rb12 uses
an exact, deliberately narrow message allowlist for deterministic client errors:
missing required parameters, empty-string validation, context-window overflow,
unsupported parameters/values and a missing model. Broad fragments such as
`invalid` are not used because they could misclassify a recoverable upstream
fault and suppress safe failover.

Audit reporting has two explicit scopes. Request count, final status, model,
first-token latency and route source use only the newest visible business final.
An associated hidden retry contributes only to upstream-attempt, failover,
absorbed-5xx, safety-invariant and attempt-timeline metrics when it has a
positive attempt index and the same reporting window contains a visible final
with the same logical request ID. Standalone Guardian activity, empty legacy
IDs, and synthetic attempt-index-zero rows never become business traffic.

`/health.relay.effective_available_slots` is sampled independently from nominal
front count. One zero-slot sample is pending; two consecutive samples trigger
standby takeover. A health endpoint connection or parse failure triggers
immediate takeover, while SQL evidence failure keeps its own debounce.

When takeover opens sub2 standbys, runtime-ready accounts are submitted first
and every active, non-deleted standby is attempted best-effort. One cooldown,
failed admin write or stale scheduler snapshot cannot prevent a later healthy
standby from opening. Takeover succeeds only after at least one standby is
confirmed in every ready scheduler bucket.

Missing, corrupt or incompatible controller state is availability-first: open
safe standby accounts and atomically rebuild state. This path never changes
7692 and never changes account status. Redis readiness evidence is tri-state;
an absent value is distinct from a Redis command or parse error.

Standby recovery requires all of the following:

- the minimum takeover hold has elapsed;
- a clean window contains no final route-unavailable outcome;
- enough normal Relay front doors are closed and schedulable;
- effective slots stay positive and `suspect`, `recovery_only`, `circuit_open`
  and `last_resort` are all zero;
- enough canonical non-probe Relay successes occurred after the proof watermark;
- account 7692 has successful post-watermark traffic and no recent 5xx;
- the existing scheduler snapshot checks pass for every standby transition.

## Verification matrix

- 1,000 successes plus one 502: suspect only, never open.
- dead front door: confirmed open from independent post-suspect failures.
- concurrent stale failures: cannot satisfy the post-suspect evidence fence.
- late failures after a fast suspect success: retained as fresh pre-suspect
  evidence, never silently discarded.
- late bounded 500/503 and successes: retained symmetrically; five failures only
  act when the actual rolling failure rate is at least 50%.
- probation: bounded concurrent permits, no serial-probe starvation.
- late probation 503: reopens with recovery backoff, never becomes ordinary weak
  evidence.
- last normal Relay front: retained at last-resort capacity, persisted, and
  restored with the same concurrency cap after restart.
- same-model cooldown or unsupported peer: cannot defeat last-resort; an
  unrelated model cooldown does not remove valid capacity.
- first sub2 standby write fails: a later healthy standby still opens.
- HTTP/Responses SSE/WebSocket: no replay after any downstream byte or frame.
- Relay sticky transport policy: rotate fronts; ordinary-account sticky policy
  remains unchanged.
- client cancel, downstream write failure, soft TTFT and WS message-too-big:
  zero breaker evidence.
- WS close 1008: auth verification only, no retry/account-health/breaker
  evidence; close 1006/1011 remain strong transport evidence.
- final request/SSE/WS transport failure: one canonical 502 (soft TTFT 504),
  never internal 598 or empty 200; pool exhaustion preserves the last real
  failure and never adds a second canonical row.
- encrypted owner soft TTFT: one upstream execution, no owner replay or account
  switch, hidden internal 598 plus one account-neutral canonical 504 retaining
  the encrypted owner route shape.
- truncated Anthropic output: explicit `error` SSE, no synthesized
  `message_stop`/`end_turn`, and no replay.
- policy/content/safety `response.failed`: canonical 400; payload/request/message
  too large without a status: canonical 413; neither retries nor affects the
  Relay breaker across Responses SSE, downstream WS or Anthropic translation.
- membership/config identity change: old permits and persisted records cannot
  revive; rename alone preserves state.
- old-image rollback: every durable rb12 state decodes as `open` or `half_open`.
- fully saturated healthy fronts: second zero-slot sample opens sub2 standby;
  one transient zero does not.
- canonical Relay availability burst: one final 502/503/504/verified 429 does
  not open standby; two distinct logical requests in 15 seconds do, including a
  mixed gateway failure plus route-unavailable. Hidden retries, probes,
  duplicate logical IDs, policy failures, local 429 and ordinary 500 do not.
- sub2 recovery: any supported terminal final restarts the 120-second clean
  period and the 20-success proof cohort, even when it was a lone failure below
  the takeover threshold.

## Rollout boundary

rb12 should first ship with Guardian still in `monitor`. The fast breaker and
sub2 failover form the availability protection for this release. Guardian
`enforce` is a separate, slower reliability policy and must be enabled only in
a later controlled change after shadow events are replayed. Combining both
changes would obscure attribution and make rollback less safe.

The configuration-transition availability blocker is now closed in source:
the new in-memory scope and epoch are published first, then all old Redis keys
share one bounded cleanup deadline. A timeout cannot scale with account count;
leftover records are rejected by the new epoch. Race tests cover a blocked
delete while requests observe the newly published scope.

Guardian restart semantics remain deliberately availability-first. A process
restart does **not** restore Guardian quarantine/probation state; the independent
fast breaker still restores its transport fence. The API exposes a cold-start
guard lasting one full Guardian recovery window (initial quarantine plus both
probation stages). During that guard, Guardian may use bounded last-resort
capacity but may not create a new long isolation.

Raw or retry-absorbed `3 in 5m` gateway observations are diagnostic suspect
evidence only. A long strong isolation requires two distinct
fast-breaker-confirmed strong cycles inside ten minutes. Replacement peer
capacity also requires a recent canonical, non-probe success; configured or
nominally healthy capacity alone is not sufficient.

These changes do not authorize switching production to `enforce`. Keep
Guardian in `monitor` until the new shadow outcomes have completed a controlled
soak and confirmed-breaker precision, cold-start behavior, and canonical peer
freshness have been reviewed from production evidence.
