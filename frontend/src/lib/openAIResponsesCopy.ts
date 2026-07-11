import type { AccountRow, AddOpenAIResponsesAccountRequest } from '../types'
import { filterCopiedCustomHeaders } from './sensitiveHeaders'

const DEFAULT_RESPONSES_BASE_CONCURRENCY = 10000

// Deliberately builds a create payload only from public account metadata.
// Credentials and runtime/error/usage fields are never read or copied.
export function buildOpenAIResponsesCopyDraft(
  account: AccountRow,
): AddOpenAIResponsesAccountRequest {
  if (!account.openai_responses_api) {
    throw new Error('Only responses_api accounts can be copied')
  }

  return {
    name: account.name?.trim()
      ? `${account.name.trim()}-copy`
      : 'openai-responses-copy',
    base_url: account.base_url?.trim() || 'https://api.openai.com',
    api_key: '',
    models: [...(account.models ?? [])],
    model_mapping: account.model_mapping ?? '',
    codex_client_metadata_mode:
      account.codex_client_metadata_mode ?? 'auto',
    proxy_url: account.proxy_url ?? '',
    custom_headers: filterCopiedCustomHeaders(account.custom_headers),
    score_bias_override: account.score_bias_override ?? null,
    base_concurrency_override:
      account.base_concurrency_override ?? DEFAULT_RESPONSES_BASE_CONCURRENCY,
    skip_warm_tier: account.skip_warm_tier ?? false,
    allowed_api_key_ids: [...(account.allowed_api_key_ids ?? [])],
    tags: [...(account.tags ?? [])],
    group_ids: [...(account.group_ids ?? [])],
    auto_pause_5h_threshold: account.auto_pause_5h_threshold ?? null,
    auto_pause_7d_threshold: account.auto_pause_7d_threshold ?? null,
    auto_pause_5h_disabled: account.auto_pause_5h_disabled ?? false,
    auto_pause_7d_disabled: account.auto_pause_7d_disabled ?? false,
    ignore_usage_limit_status_override:
      account.ignore_usage_limit_status_override ?? null,
    dispatch_count_limit: account.dispatch_count_limit ?? null,
    scheduler_priority: account.scheduler_priority ?? null,
  }
}
