import type { BatchUpdateAccountsRequest } from "../types";

export const OAUTH_BATCH_BASE_CONCURRENCY_MAX = 50;
export const RESPONSES_BATCH_BASE_CONCURRENCY_MAX = 10000;

export function resolveBatchBaseConcurrencyMax(
  ids: number[],
  accounts: Array<{ id: number; openai_responses_api?: boolean }>,
): number {
  if (ids.length === 0) return OAUTH_BATCH_BASE_CONCURRENCY_MAX;
  const byID = new Map(accounts.map((account) => [account.id, account]));
  return ids.every((id) => byID.get(id)?.openai_responses_api === true)
    ? RESPONSES_BATCH_BASE_CONCURRENCY_MAX
    : OAUTH_BATCH_BASE_CONCURRENCY_MAX;
}

export interface BuildBatchMetadataUpdateOptions {
  ids: number[];
  updateTags: boolean;
  tags: string[];
  updateGroups: boolean;
  groupIds: number[];
  updateScoreBias: boolean;
  scoreBias: number | null;
  updateBaseConcurrency: boolean;
  baseConcurrency: number | null;
  updateSchedulerPriority: boolean;
  schedulerPriority: number | null;
}

export function buildBatchMetadataUpdate({
  ids,
  updateTags,
  tags,
  updateGroups,
  groupIds,
  updateScoreBias,
  scoreBias,
  updateBaseConcurrency,
  baseConcurrency,
  updateSchedulerPriority,
  schedulerPriority,
}: BuildBatchMetadataUpdateOptions): BatchUpdateAccountsRequest {
  const payload: BatchUpdateAccountsRequest = { ids: [...ids] };
  if (updateTags) payload.tags = [...tags];
  if (updateGroups) payload.group_ids = [...groupIds];
  if (updateScoreBias) payload.score_bias_override = scoreBias;
  if (updateBaseConcurrency)
    payload.base_concurrency_override = baseConcurrency;
  if (updateSchedulerPriority) payload.scheduler_priority = schedulerPriority;
  return payload;
}
