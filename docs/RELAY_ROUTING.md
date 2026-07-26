# Relay group routing, continuation, and audit

This extension adds RelayBases policy without replacing codex2api's official
account scheduler. Custom code may decide that a request must remain inside one
Relay group and may attach a route reason. The official scheduler continues to
own account priority, health, cooldowns, model eligibility, capacity, affinity,
exclusions, retries, and same-group account switching.

The first-release rules are:

- CYB, probe, and OAuth-capacity overflow constrain only the target Relay group.
- No custom component selects or pins a concrete Relay account.
- A Relay continuation may switch accounts only after a complete local replay
  has removed `previous_response_id`.
- A raw `previous_response_id` is never sent to Relay. If replay is unavailable
  and the official scheduler actually selects Relay, the gateway returns 409
  before any Relay HTTP/WS attempt.
- Routing audit data belongs to the independent `/codex-audit` page and the
  dedicated `rb_route_requests` and `rb_route_attempts` tables.

## First-release request scope

The route hooks cover:

- `POST /v1/responses`
- `POST /v1/responses/compact`
- `POST /v1/chat/completions`

The native downstream Responses WebSocket handler and any custom upstream Relay
WebSocket adapter are outside the first release.

RelayStyle remains an account property. Membership in the target group does not
change an account's type or force a transport that the account cannot support.

## Configuration

```env
CODEX_CYB_RELAY_GROUP_ID=3
CODEX_CYB_RELAY_ENABLED=true
CODEX_CYB_RELAY_PIN_TTL_SECONDS=86400
```

`CODEX_CYB_RELAY_GROUP_ID` is required. Routing is enabled by default when the
group ID is positive. The group pin TTL defaults to 24 hours.

Production continuation replay uses the deployment's shared Redis service plus
a bounded in-process cache. Replay TTL, maximum entries, and maximum retained
bytes have finite values. The memory tier is never allowed to grow without a
hard entry and byte bound.

For ordinary OAuth overflow, configure OAuth accounts with a higher
`scheduler_priority` and accounts in the Relay group with a lower priority.
The route extension must not add its own scheduler, retry loop, account health
state, or concurrency counter.

## Route decision contract

The routing layer produces only a constraint and an audit reason:

```text
required_group_id    optional Relay group restriction
route_source         cyb_rule | probe | oauth_overflow |
                     relay_continuation | cyb_feedback
route_signals        deterministic matched rule/probe identifiers
```

It never returns an account ID.

| Request condition | Constraint | Account selection |
|---|---|---|
| Deterministic CYB hit | Target Relay group | Official scheduler |
| Probe hit | Target Relay group | Official scheduler |
| OAuth has no schedulable candidate and Relay is eligible | Target Relay group | Official scheduler |
| Replayed Relay continuation | Original Relay group | Official scheduler; same-group switching allowed |
| New ordinary request | Existing official filters | Official scheduler |

The group constraint is composed with all existing official authorization,
model, API-key, and group filters. It never broadens access.

If the selected account fails with a retryable result, the existing official
retry path excludes that account and selects another eligible account under the
same group constraint. A retry must not escape to another group or back to
OAuth. If the group is exhausted, the existing scheduler wait/error behavior is
returned and the audit case is marked `group_exhausted`.

`oauth_overflow` means that no higher-priority OAuth account was schedulable.
The cause may be capacity, cooldown, health, model eligibility, or an existing
official filter. Distinguishing those causes would require changing scheduler
internals and is outside this extension.

## Deterministic CYB and probe rules

`security/cybroute` remains a routing-only package. It:

- reuses the existing prompt envelope and deterministic rule engine;
- adds the RelayBases production rule set and exclusions;
- preserves provenance partition isolation;
- recognizes the production exact probes and bounded probe heuristics;
- keeps configured sensitive words and custom patterns;
- returns route facts only;
- never blocks on an external model, selects an account, or sends a request.

The original request and the account-independent Payload Rules preview are both
scanned. Payload Rules whose output depends on a selected account run later and
must not be used to inject text that the early CYB scan is expected to detect.

An ordinary OAuth request that returns `cyber_policy` may teach the bounded,
HMAC-keyed feedback cache. A matching future request is treated as a CYB route
and receives the same Relay group constraint. Feedback never selects an
account.

## Conversation group pin

The ingress proxy should remove any public client value and inject a stable
`X-Codex2API-Affinity-Key` derived from the final user and conversation:

```text
same user + same conversation     -> same value
different user or conversation   -> different value
```

The conversation pin stores only the Relay group ID and route source. It never
stores a Relay account ID. Redis is required for consistent pins in a
multi-instance deployment; bounded memory is suitable as a local cache, not as
the sole production source.

A pin constrains future requests to the same Relay group while leaving account
choice to the official scheduler. Pin failure must never cause a request to
escape the required group.

The conversation pin and the continuation replay store have different keys and
purposes:

- conversation pin: stable conversation scope -> Relay group;
- replay snapshot: API-key owner + stable conversation scope when available +
  response ID -> complete standalone history.

Neither cache is an account-owner registry.

## Continuation contract

### Complete local replay is primary

Replay lookup is namespaced by the official API-key owner identity, a hashed
stable affinity/session scope when one is available, and the opaque
`previous_response_id`. If no stable scope is supplied, compatibility falls
back to API-key owner + response ID. The physical cache key is SHA-256-derived,
so raw scope and response-ID values do not appear in Redis keys or logs.
The owner namespace may reuse the official response-cache owner derivation, but
the complete replay store is separate from the official partial tool cache.

The persisted snapshot must contain a complete, account-independent
conversation up to the referenced response and, when that response was served
inside the configured Relay group, that group ID as routing provenance. A
partial tool cache, selected output fragments, or an account-bound encrypted
item is not a complete replay. Redis provides the shared durable tier; a
bounded in-process cache provides a hot/local tier. Every entry has a finite
TTL.

Snapshots are produced only from a complete canonical chain:

- an initial standalone request supplies the first complete input;
- a replayed request inherits its verified parent snapshot and appends the
  current turn;
- the corresponding assistant/tool output is appended only after a successful
  terminal response;
- the new response ID is published as `complete` only after the snapshot has
  been atomically committed;
- an interrupted stream, incomplete tool pair, oversized snapshot, or failed
  persistence never creates a falsely complete entry.

The Redis record is the cross-instance authority. The bounded memory tier may
serve a verified hit and cache a Redis result, but it applies the same owner,
completeness, TTL, entry-count, and byte-count checks. A Redis write failure does
not fail the completed response: the verified local snapshot remains usable on
that instance, while another instance safely observes a replay miss.

For a continuation request:

1. Resolve the snapshot using the scoped owner + `previous_response_id`.
2. Verify that the snapshot is explicitly marked complete and structurally
   valid.
3. Merge the current turn without duplicating prior input.
4. Preserve the current model, or reject a conflicting replay model.
5. Delete `previous_response_id` and verify that it is absent.
6. If the snapshot carries current Relay-group provenance, apply that group
   constraint; an unknown response ID does not manufacture a Relay route.
7. Pass the standalone request to the official scheduler.

After step 5, any healthy account in that Relay group may be selected. This is
the normal and preferred continuation path because it does not depend on
vendor-local response state or a specific account.

### Replay miss behavior

A replay miss does not fail the request globally before account selection.
If the official scheduler selects an OAuth account, the existing official OAuth
continuation path remains unchanged. If it actually selects a Relay account,
the account is released and the gateway returns a typed 409 before constructing
or sending a Relay request.

The first release deliberately has no live WS fallback. Production capability
probes found no Relay account with a usable Responses WebSocket v2 continuation
path, so adding an unverified transport adapter would increase coupling without
providing a working fallback.

The following are forbidden:

- sending a raw `previous_response_id` through the Relay HTTP executor;
- sending it to another account in the same group;
- sending it through a custom Relay WS transport;
- treating a partial replay snapshot as complete;
- silently dropping the ID and continuing with only the latest message.

Initial requests without `previous_response_id` continue through the existing
OAuth or Relay executor. The 409 boundary applies only to an unreplayable
continuation at the point where Relay has actually been selected.

## Independent audit

Relay routing and continuation are presented at the independent admin route:

```text
/codex-audit
```

The page has its own admin API and data model. It does not add a tab to another
security page and does not read from or write to that page's tables.

Two dedicated tables are authoritative:

- `rb_route_requests`: one row per logical downstream request;
- `rb_route_attempts`: one row per physical upstream account attempt, linked by
  request ID and ordered by attempt index.

`rb_route_requests` records the endpoint/model, masked API-key metadata, bounded
case text, scan coverage, route source/reason/signals, target group, whether a
previous response ID was present, replay outcome, detector miss, route
violation, group exhaustion, final account/transport/status, and attempt count.
Before persistence, case text is bounded and common credentials plus
`previous_response_id`, `prompt_cache_key`, and encrypted provider state are
redacted. It does not store a raw API key or a raw response ID.

`rb_route_attempts` records the actual account snapshot, selection mode,
transport, WS use, status/error, and selected/completed timestamps. This
separation keeps one logical request from being multiplied by retries.

The page must expose at least:

- logical requests and physical attempts;
- CYB, probe, overflow, continuation, and feedback routes;
- retry count and same-group account switches;
- replay hits and source, misses, invalid/incomplete snapshots, and typed 409s;
- group exhaustion and group-escape violations;
- OAuth detector misses and Relay-side `cyber_policy`;
- Relay successes/failures and per-account attempt distribution;
- bounded audit-writer queue health, dropped events, and failed writes;
- session-isolation violations.

Audit writes use a bounded asynchronous queue. Audit failure is observable but
must not alter routing or request success. Replay storage is operational state,
not audit data, and must not be downgraded to best-effort audit writes. Audit
rows have a 30-day retention window and are removed in bounded transactions.
Report generation rejects windows above its request/attempt cardinality limits
before loading detail rows; operators must narrow the selected time range
instead of allowing an unbounded in-memory report.

## Per-account capability probe

A point-in-time probe has already been run account by account. Initial Relay
HTTP succeeded on the healthy accounts, but raw HTTP continuation required
Responses WebSocket v2 and no tested Relay account exposed a usable WS v2 path.
This remains a snapshot, not a release guarantee.

Before every production release, rerun the probe for every enabled account in
the target Relay group and record only internal account identifiers, capability
class, status, latency, and failure category. Release notes and this document
must not contain upstream hostnames, credentials, tokens, or API keys.

The release probe must cover:

- initial HTTP request;
- complete local replay with `previous_response_id` removed;
- same-group switch after replay by disabling the first selected account;
- explicit 409 after replay miss with zero Relay HTTP/WS attempt;
- an informational WS v2 capability probe, which does not enable a release
  transport by itself.

## Intrusion budget

The extension is accepted only while these boundaries hold:

- zero changes to official account ranking, scheduler priority, health,
  cooldown, CAS acquisition, concurrency release, or retry-exclusion logic;
- zero custom account-selection or joint-wait loops;
- group routing is implemented by composing the existing `auth.AccountFilter`;
- request routing is hooked once at the shared handler path, not copied into
  independent per-account executors;
- replay logic lives in a new, narrow provider/store package;
- the existing HTTP Relay executor remains independently usable;
- audit schema/query/writer code and the `/codex-audit` page are standalone;
- no audit dependency on existing prompt-filter UI, logs, tables, or migrations;
- no changes to translator behavior beyond invoking the existing translation
  path with the already replayed standalone body.

Protected areas are the official scheduler/store, retry helpers, account health
state, and concurrency accounting. Any proposed change there requires a new
design review.

Before merge, publish:

- the exact list of modified existing upstream files and functions;
- added and deleted line counts separated into routing, replay, audit, and
  admin UI;
- proof that scheduler/retry behavior is unchanged under a group filter;
- an upstream rebase rehearsal and its conflict list;
- contract-test results for every hook.

If the same policy must be inserted separately into HTTP, Compact, chat, and WS
retry loops, the intrusion budget has been exceeded; first extract or reuse one
shared hook.

## Release gates

Do not deploy until all gates pass on the exact release artifact:

1. Build the clean official baseline, then build the extension and run the
   official test suite plus routing/replay/audit tests.
2. Verify deterministic CYB and probe fixtures, production exclusions, payload
   scan coverage, and scan truncation accounting.
3. Verify CYB/probe requests produce zero OAuth attempts and zero group escapes.
4. Verify ordinary OAuth traffic stays on higher-priority OAuth while eligible,
   then reaches Relay when no OAuth candidate is schedulable.
5. Force a retryable failure on Relay A and verify the official scheduler picks
   Relay B in the same group without custom account selection.
6. Populate a complete replay for a response from Relay A, disable A, and
   verify the next turn removes `previous_response_id` before Relay B receives
   it.
7. Verify Redis replay across two application instances and verify bounded
   memory eviction by TTL, entry limit, and byte limit.
8. Verify replay owner isolation: another API-key owner cannot resolve or use
   the snapshot.
9. On replay miss, verify OAuth selection preserves the official OAuth path and
   actual Relay selection returns 409 with zero Relay HTTP, WS, or sibling-account
   attempts.
10. Verify a raw `previous_response_id` is never present in an HTTP attempt or a
    same-group switched attempt.
11. Run concurrent A/B marker tests under official isolated request mode and
    verify no response bytes, tool results, or IDs cross requests.
12. Re-run the per-account capability probe described above.
13. Verify `/codex-audit` totals reconcile one logical request to all attempts,
    including retries, same-group switches, replay paths, failures, and
    detector misses.
14. Verify audit queue saturation/database failure does not alter request
    routing, while dropped/failed writes remain visible.
15. Run SQLite and PostgreSQL migration, query, retention, and rollback
    rehearsals without touching unrelated tables.
16. Compare error rate, first-token latency, memory, Redis, and database load
    against the clean official baseline.

Hard release invariants are zero tolerance:

- CYB/probe route escaping the Relay group;
- same-group switch while raw `previous_response_id` is still present;
- raw continuation sent over HTTP;
- replay lookup crossing API-key owners;
- custom scheduler/CAS/retry behavior;
- confirmed cross-request content delivery.

## Rollback

Rollback must preserve continuation safety:

1. Stop rollout and new-instance promotion.
2. Keep complete local replay enabled through the normal Relay path.
3. For a continuation without complete replay, keep the Relay-side 409 enabled;
   never restore raw HTTP or sibling-account fallback as a rollback shortcut.
4. Route new traffic to the last known-good artifact. Do not simply remove the
   Relay group constraint while continuing to serve CYB/probe traffic.
5. Disable `/codex-audit` writes only if the writer/database path is the cause;
   routing and replay must remain independent.
6. Keep the audit tables and historical rows. Do not drop or rewrite schema
   during an emergency rollback.
7. Let replay and pin keys expire by TTL. Do not bulk-delete shared Redis keys
   during rollback.
8. After traffic is stable, reconcile in-flight logical requests and attempts,
   then record the failing route/replay/transport mode for the next release.

Roll back immediately on any group escape, raw continuation cross-account/HTTP
attempt, replay owner violation, confirmed session bleed, unbounded cache
growth, scheduler regression, or audit failure that affects request handling.
