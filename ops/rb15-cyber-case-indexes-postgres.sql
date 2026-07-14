-- rb15 canonical CYB case candidate index.
--
-- Run this file with psql BEFORE the rb15 application restart. CONCURRENTLY
-- cannot run inside a transaction block. The statement is idempotent and does
-- not change request or account data.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_cyber_scope_created_at
ON usage_logs (upstream_account_type, created_at DESC, id DESC)
INCLUDE (logical_request_id, route_class, route_group_id, guardian_attempt_only, attempt_index)
WHERE upstream_error_kind = 'cyber_policy';

-- Verification (the query should use idx_usage_logs_cyber_scope_created_at for
-- non-trivial windows once PostgreSQL statistics are current):
-- EXPLAIN (ANALYZE, BUFFERS)
-- SELECT id
-- FROM usage_logs
-- WHERE created_at >= now() - interval '3 hours'
--   AND created_at <= now()
--   AND upstream_error_kind = 'cyber_policy'
--   AND upstream_account_type = 'oauth'
-- ORDER BY created_at DESC, id DESC;
