import type {
  AccountRow,
  AddOpenAIResponsesAccountRequest,
  UpdateAccountSchedulerRequest,
} from "../types";

export const DEFAULT_ACCOUNT_BASE_CONCURRENCY_MAX = 50;
export const RESPONSES_ACCOUNT_BASE_CONCURRENCY_MAX = 1000;

const SENSITIVE_HEADER_NAMES = new Set([
  "api-key",
  "authorization",
  "cookie",
  "proxy-authorization",
  "set-cookie",
  "x-api-key",
]);

const SENSITIVE_HEADER_FRAGMENTS = [
  "authorization",
  "cookie",
  "credential",
  "api-key",
  "apikey",
  "secret",
  "token",
];

export interface OpenAIResponsesAccountDraft {
  account: AddOpenAIResponsesAccountRequest;
  scheduler: UpdateAccountSchedulerRequest;
}

export function accountBaseConcurrencyMax(accounts: AccountRow[]): number {
  return accounts.length > 0 &&
    accounts.every((account) => account.openai_responses_api === true)
    ? RESPONSES_ACCOUNT_BASE_CONCURRENCY_MAX
    : DEFAULT_ACCOUNT_BASE_CONCURRENCY_MAX;
}

export function copySafeCustomHeaders(
  headers: Record<string, string> | null | undefined,
): Record<string, string> | null {
  if (!headers) return null;
  const safeHeaders = Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => {
        const normalized = name.trim().toLowerCase();
        return !SENSITIVE_HEADER_NAMES.has(normalized) &&
          !SENSITIVE_HEADER_FRAGMENTS.some((fragment) =>
            normalized.includes(fragment)
          );
      },
    ),
  );
  return Object.keys(safeHeaders).length > 0 ? safeHeaders : null;
}

export function copySafeProxyURL(value: string | null | undefined): string {
  const raw = value?.trim() ?? "";
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    return parsed.username || parsed.password ? "" : raw;
  } catch {
    // Do not copy an unparseable value that could conceal embedded credentials.
    return "";
  }
}

export function buildOpenAIResponsesAccountDraft(
  source: AccountRow,
): OpenAIResponsesAccountDraft {
  return {
    account: {
      name: source.name,
      base_url: source.base_url || "https://api.openai.com",
      api_key: "",
      models: [...(source.models ?? [])],
      model_mapping: source.model_mapping ?? "",
      codex_client_metadata_mode:
        source.codex_client_metadata_mode ?? "auto",
      proxy_url: copySafeProxyURL(source.proxy_url),
      custom_headers: copySafeCustomHeaders(source.custom_headers),
    },
    scheduler: {
      score_bias_override: source.score_bias_override ?? null,
      base_concurrency_override: source.base_concurrency_override ?? null,
      skip_warm_tier: source.skip_warm_tier ?? false,
      allowed_api_key_ids: [...(source.allowed_api_key_ids ?? [])],
      tags: [...(source.tags ?? [])],
      group_ids: [...(source.group_ids ?? [])],
      auto_pause_5h_threshold: source.auto_pause_5h_threshold ?? null,
      auto_pause_7d_threshold: source.auto_pause_7d_threshold ?? null,
      auto_pause_5h_disabled: source.auto_pause_5h_disabled ?? false,
      auto_pause_7d_disabled: source.auto_pause_7d_disabled ?? false,
      ignore_usage_limit_status_override:
        source.ignore_usage_limit_status_override ?? null,
      dispatch_count_limit: source.dispatch_count_limit ?? null,
      scheduler_priority: source.scheduler_priority ?? null,
    },
  };
}
