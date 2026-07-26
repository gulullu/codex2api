# Relay group routing

This extension keeps RelayBases routing separate from codex2api's account
scheduler. It decides only whether a request must stay inside one account
group; the official selector still owns priority, capacity, cooldowns,
affinity, exclusions, retries, and same-group account switching.

## First-release scope

The route hooks cover the HTTP handlers for:

- `POST /v1/responses`
- `POST /v1/responses/compact`
- `POST /v1/chat/completions`

The first release intentionally does not hook `/v1/messages` or the native
downstream Responses WebSocket handler. RelayStyle accounts continue to use the
official HTTP executor selected by their account configuration; belonging to
the Relay group does not force an account type or transport.

## Configuration

```env
CODEX_CYB_RELAY_GROUP_ID=3
CODEX_CYB_RELAY_ENABLED=true
CODEX_CYB_RELAY_PIN_TTL_SECONDS=86400
```

`CODEX_CYB_RELAY_GROUP_ID` is required. `CODEX_CYB_RELAY_ENABLED` defaults to
enabled when the group ID is positive. The pin TTL defaults to 24 hours.

The route layer checks only `group_id`. Operators are responsible for the
accounts placed in that group. For ordinary OAuth overflow, configure official
OAuth accounts with a higher `scheduler_priority` and accounts in the Relay
group with a lower priority. Do not add a custom overflow selector.

## Shared-key conversation contract

The ingress proxy must remove any public client value and inject a stable
`X-Codex2API-Affinity-Key` derived from the final user and conversation:

```text
same user + same conversation     -> same value
different user or conversation   -> different value
```

When this trusted header exists, it is the only route-pin scope used for the
request. Otherwise, scope extraction reuses the official explicit identity
fields, including Session/Conversation headers, `prompt_cache_key`, and
`Idempotency-Key`. The implementation never stores a raw identity value, API
key, prompt, response body, response ID, or Relay account ID.

Missing identity is not an application-level error:

- CYB, probe, and ordinary OAuth-overflow requests still use the target Relay
  group, but no group pin is persisted when no stable scope exists.
- A request with `previous_response_id` but no usable pin is conservatively
  constrained to the target Relay group.
- Pin-cache read or decoding failures conservatively constrain the request to
  Relay. Pin writes are best effort and a write failure keeps the already
  selected Relay route. None of these failures creates a custom HTTP 503; each
  emits a warning/statistics event.
- Normal scheduler behavior may still return 503 when the required Relay group
  genuinely has no eligible account or capacity. The internal group-escape
  invariant also remains fail-closed if a selector ever violates the required
  group; that path is separately counted as a route violation.

Use Redis for production and for every multi-instance deployment. The in-memory
cache is suitable only for local development: pins disappear on restart and
are not shared between processes. Redis improves continuation consistency but
is not placed on the request-success path: cache unavailability must not turn
otherwise routable requests into 503 responses.

The pin value contains only the Relay group ID and the original route source.
It never binds a specific account, so official retry may switch to any other
eligible account in the same group. No session content, response content, or
account ownership state is introduced.

## Deterministic routing rules

`security/cybroute` is a routing-only package. It:

- reuses the official prompt envelope and rule engine;
- adds the five RelayBases production-only deterministic rules;
- keeps the production non-CYB exclusions and composite rules;
- preserves provenance partition isolation;
- recognizes the production 19 exact probes and two probe heuristics;
- keeps configured sensitive words and custom patterns;
- never blocks, selects an account, or calls an external semantic reviewer.

The original request and the account-independent Payload Rules preview are both
scanned. Payload Rules whose behavior depends on a selected account execute
later and are therefore outside this first-release preview; do not use such
rules to inject CYB-sensitive prompt text.

An ordinary official OAuth request that really returns `cyber_policy` teaches a
process-local, HMAC-protected 24-hour/1024-entry feedback cache. A matching
future body routes only that request to Relay. Feedback-only hits deliberately
do not create a conversation pin, preserving the existing production behavior.

## Statistics

The Prompt Filter page contains a **Routing** tab backed by:

```text
GET /api/admin/relay-route/stats?window_hours=24
```

It exposes logical Relay routes, selection attempts, deterministic CYB routes,
probe routes, OAuth overflow, Relay continuation, feedback routes, retries,
same-group switches, group exhaustion, detector misses, Relay-side
`cyber_policy`, conservative route-state fallbacks, and group escape
violations. The `state_fallbacks` total covers missing scope, continuation pin
misses, pin read/write failures, and invalid or stale pin values. Metrics reuse
`prompt_filter_logs`; no database schema or migration is added, and prompt text
is never written to route events.

## Release gates

Before production rollout:

1. Verify the ingress affinity overwrite with two users sharing one API key.
2. Run concurrent A/B marker tests with official isolated request mode.
3. Create a response through Relay A, make A unavailable, and verify Relay B in
   the same group can continue the same `previous_response_id`.
4. Create an OAuth response, trigger a CYB route on the next turn, and verify
   the Relay upstream accepts the old continuation state or the client's full
   replay.
5. Confirm OAuth priority is higher than Relay priority and observe a real
   capacity overflow.
6. Confirm Redis is shared by every application instance and that simulated
   cache read/write/corruption failures route conservatively without a custom
   503.

Do not deploy if steps 3 or 4 fail. Cross-account continuation depends on the
Relay upstream sharing response state; codex2api's selector cannot manufacture
that state.
