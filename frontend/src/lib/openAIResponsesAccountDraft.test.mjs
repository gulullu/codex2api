import assert from "node:assert/strict";
import test from "node:test";

import {
  accountBaseConcurrencyMax,
  buildOpenAIResponsesAccountDraft,
  copySafeCustomHeaders,
  copySafeProxyURL,
} from "./openAIResponsesAccountDraft.ts";

test("Responses account draft copies configuration without credentials or runtime state", () => {
  const draft = buildOpenAIResponsesAccountDraft({
    id: 12,
    name: "relay-a",
    email: "https://relay.example",
    plan_type: "api",
    status: "ready",
    openai_responses_api: true,
    base_url: "https://relay.example/v1",
    models: ["gpt-5", "gpt-5-mini"],
    model_mapping: '{"gpt-5":"gpt-5.2"}',
    codex_client_metadata_mode: "off",
    custom_headers: {
      Authorization: "Bearer secret",
      COOKIE: "session=secret",
      "X-Api-Key": "secret",
      "X-Tenant": "blue",
    },
    proxy_url: "http://proxy.example:8080",
    score_bias_override: 35,
    base_concurrency_override: 800,
    skip_warm_tier: true,
    allowed_api_key_ids: [3, 7],
    tags: ["relay"],
    group_ids: [9],
    auto_pause_5h_threshold: 0.8,
    auto_pause_7d_threshold: 0.9,
    auto_pause_5h_disabled: true,
    auto_pause_7d_disabled: false,
    ignore_usage_limit_status_override: true,
    dispatch_count_limit: 2500,
    scheduler_priority: -10,
    active_requests: 8,
    total_requests: 100,
    error_message: "runtime-only",
    created_at: "2026-07-26T00:00:00Z",
    updated_at: "2026-07-26T00:00:00Z",
  });

  assert.deepEqual(draft.account, {
    name: "relay-a",
    base_url: "https://relay.example/v1",
    api_key: "",
    models: ["gpt-5", "gpt-5-mini"],
    model_mapping: '{"gpt-5":"gpt-5.2"}',
    codex_client_metadata_mode: "off",
    proxy_url: "http://proxy.example:8080",
    custom_headers: { "X-Tenant": "blue" },
  });
  assert.deepEqual(draft.scheduler, {
    score_bias_override: 35,
    base_concurrency_override: 800,
    skip_warm_tier: true,
    allowed_api_key_ids: [3, 7],
    tags: ["relay"],
    group_ids: [9],
    auto_pause_5h_threshold: 0.8,
    auto_pause_7d_threshold: 0.9,
    auto_pause_5h_disabled: true,
    auto_pause_7d_disabled: false,
    ignore_usage_limit_status_override: true,
    dispatch_count_limit: 2500,
    scheduler_priority: -10,
  });
  assert.equal("active_requests" in draft.scheduler, false);
  assert.equal("status" in draft.account, false);
});

test("copySafeCustomHeaders removes credential-bearing headers case-insensitively", () => {
  assert.deepEqual(
    copySafeCustomHeaders({
      authorization: "secret",
      Cookie: "secret",
      "Proxy-Authorization": "secret",
      "Set-Cookie": "secret",
      "api-key": "secret",
      "X-Relay-Token": "secret",
      Accept: "application/json",
    }),
    { Accept: "application/json" },
  );
});

test("copySafeProxyURL never carries embedded proxy credentials", () => {
  assert.equal(copySafeProxyURL("http://proxy.example:8080"), "http://proxy.example:8080");
  assert.equal(copySafeProxyURL("http://user:password@proxy.example:8080"), "");
  assert.equal(copySafeProxyURL("not a URL"), "");
});

test("base concurrency maximum is 1000 only when every selected account uses Responses API", () => {
  const responses = {
    id: 1,
    name: "relay",
    email: "relay",
    plan_type: "api",
    status: "ready",
    openai_responses_api: true,
    proxy_url: "",
    created_at: "",
    updated_at: "",
  };
  const oauth = {
    ...responses,
    id: 2,
    openai_responses_api: false,
  };

  assert.equal(accountBaseConcurrencyMax([responses]), 1000);
  assert.equal(accountBaseConcurrencyMax([responses, { ...responses, id: 3 }]), 1000);
  assert.equal(accountBaseConcurrencyMax([responses, oauth]), 50);
  assert.equal(accountBaseConcurrencyMax([oauth]), 50);
  assert.equal(accountBaseConcurrencyMax([]), 50);
});
