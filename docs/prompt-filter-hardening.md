# RelayBases local routing hardening

This document describes the RelayBases build of codex2api. It intentionally differs from the generic upstream Prompt Filter feature.

## Responsibility boundary

- sub2 owns moderation for every request.
- codex2api local rules inspect the complete routing payload and produce Relay route signals only.
- codex2api does not return a local content-policy rejection.
- codex2api does not call the legacy Omni, Moderations, sidecar, or semantic-review provider pool.
- codex2api never buffers, scans, or interrupts SSE / WebSocket model output.

The database and API retain upstream compatibility fields so migrations and rollback remain possible. RelayBases admin reads and saves normalize the active values to:

```json
{
  "prompt_filter_mode": "monitor",
  "prompt_filter_review_enabled": false,
  "prompt_filter_semantic_review_enabled": false,
  "prompt_filter_advanced_config": {
    "output": {
      "enabled": false
    }
  }
}
```

Old database rows cannot reactivate these paths. Runtime SSE and WebSocket forwarding also bypasses the upstream output scanner as a second line of defense.

## Routing semantics

`prompt_filter_strict_terminal_enabled`, strict rules, and configured terminal categories remain schema-compatible names. In RelayBases they mean high-confidence routing:

- an ordinary score at or above the route threshold goes to Relay;
- a strict score at or above the high-risk threshold goes to Relay;
- a strict direct hit or a configured category can bypass the ordinary threshold and go to Relay;
- none of these signals rejects the request inside codex2api.

Use strict rules only for narrow, low-false-positive evidence. Dual-use terms should use moderate weights and combined evidence.

Input normalization and bounded URL / HTML / Base64 decoding may be enabled because they only improve the current-request routing view. Cumulative user / IP / session risk may produce an auxiliary Relay signal, but it must not become a user-visible denial.

## Relay isolation

- A request selected for Relay must never fall back to OAuth.
- A non-match must not be pulled into Relay by content-derived or idempotency pinning.
- Only explicit Session, Conversation, prompt cache, continuation ownership, and the same active WebSocket connection may retain short-lived continuity.
- Route logs must record current-request signals, affinity kind, final route source, and actual upstream account type.

## Output invariants

SSE bytes and WebSocket messages are forwarded unchanged. This remains true even if an old database row contains `"output":{"enabled":true}`.

The upstream `security/promptfilter.OutputScanner` implementation remains in source for upstream compatibility and unit coverage, but the RelayBases HTTP and WebSocket runtime does not instantiate it.

## Rule intelligence

Public-source intelligence can create candidate routing rules. Keep automatic rule addition off unless unattended changes are explicitly accepted. Human review should check false positives against normal business prompts, system instructions, tools, and skills before enabling a rule.

## Request buffering

Nginx cannot safely inspect arbitrary JSON payloads with ordinary `map` rules. Buffer the complete request and let codex2api build the routing view before opening the upstream model request. The example remains in `deploy/nginx/codex2api-prompt-buffering.conf.example`.

Do not enable `proxy_cache` or request-body logging on model endpoints. Prompt bodies may contain secrets and user content.

## Release checks

Before release, verify:

1. admin GET and UPDATE normalize monitor, legacy review disabled, semantic review disabled, and output disabled;
2. a stored output-enabled value cannot interrupt SSE or WebSocket traffic;
3. local input rules still produce Relay route signals;
4. Relay unavailability does not fall back to OAuth;
5. normal non-matches continue through the expected OAuth scheduler;
6. frontend text consistently states routing-only behavior and sub2 moderation ownership.
