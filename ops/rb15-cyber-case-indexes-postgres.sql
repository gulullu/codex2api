\set ON_ERROR_STOP on
SET lock_timeout = '5s';
SET statement_timeout = '20min';

-- rb15 canonical CYB case candidate index.
--
-- Run this file with psql BEFORE the rb15 application restart. CONCURRENTLY
-- cannot run inside a transaction block. The script is safely repeatable only
-- when an existing same-name index is valid, ready and has this exact shape.
-- A failed or differently defined same-name index is an operator-visible hard
-- stop; this script never drops or replaces production indexes automatically.
-- On failure, do not restart the application. Inspect pg_index first; an
-- invalid same-name residue must be reviewed and explicitly removed with
-- DROP INDEX CONCURRENTLY before this script is retried.

SELECT to_regclass('public.idx_usage_logs_cyber_scope_created_at') IS NULL
       AS rb15_index_absent
\gset

\if :rb15_index_absent
CREATE INDEX CONCURRENTLY idx_usage_logs_cyber_scope_created_at
ON public.usage_logs (upstream_account_type, created_at DESC, id DESC)
INCLUDE (logical_request_id, route_class, route_group_id, guardian_attempt_only, attempt_index)
WHERE upstream_error_kind = 'cyber_policy';
\else
WITH target AS (
    SELECT i.*, am.amname,
           ARRAY(
               SELECT pg_get_indexdef(i.indexrelid, n, true)
               FROM generate_series(1, i.indnatts) AS n
               ORDER BY n
           ) AS indexed_columns,
           lower(regexp_replace(
               pg_get_expr(i.indpred, i.indrelid),
               '[[:space:]()]', '', 'g'
           )) AS normalized_predicate
    FROM pg_index i
    JOIN pg_class index_relation ON index_relation.oid = i.indexrelid
    JOIN pg_namespace index_namespace ON index_namespace.oid = index_relation.relnamespace
    JOIN pg_am am ON am.oid = index_relation.relam
    WHERE index_namespace.nspname = 'public'
      AND index_relation.relname = 'idx_usage_logs_cyber_scope_created_at'
      AND i.indrelid = 'public.usage_logs'::regclass
)
SELECT COALESCE(bool_and(
           indisvalid
           AND indisready
           AND indislive
           AND NOT indisunique
           AND NOT indisprimary
           AND indexprs IS NULL
           AND indnkeyatts = 3
           AND indnatts = 8
           AND indoption::text = '0 3 3'
           AND amname = 'btree'
           AND indexed_columns = ARRAY[
               'upstream_account_type', 'created_at', 'id',
               'logical_request_id', 'route_class', 'route_group_id',
               'guardian_attempt_only', 'attempt_index'
           ]::text[]
           AND normalized_predicate IN (
               'upstream_error_kind::text=''cyber_policy''::text',
               'upstream_error_kind=''cyber_policy''',
               'upstream_error_kind=''cyber_policy''::text'
           )
       ), false) AND count(*) = 1 AS rb15_existing_index_verified
FROM target
\gset

\if :rb15_existing_index_verified
\echo 'rb15 cyber case index already exists and is verified'
\else
\echo 'ERROR: existing rb15 cyber case index is invalid, not ready, or has an unexpected definition'
SELECT 1 / 0 AS rb15_abort_existing_index_verification;
\endif
\endif

-- Always verify the postcondition. This catches an interrupted concurrent
-- build that left an invalid catalog entry and prevents a false-success rerun.
WITH target AS (
    SELECT i.*, am.amname,
           ARRAY(
               SELECT pg_get_indexdef(i.indexrelid, n, true)
               FROM generate_series(1, i.indnatts) AS n
               ORDER BY n
           ) AS indexed_columns,
           lower(regexp_replace(
               pg_get_expr(i.indpred, i.indrelid),
               '[[:space:]()]', '', 'g'
           )) AS normalized_predicate
    FROM pg_index i
    JOIN pg_class index_relation ON index_relation.oid = i.indexrelid
    JOIN pg_namespace index_namespace ON index_namespace.oid = index_relation.relnamespace
    JOIN pg_am am ON am.oid = index_relation.relam
    WHERE index_namespace.nspname = 'public'
      AND index_relation.relname = 'idx_usage_logs_cyber_scope_created_at'
      AND i.indrelid = 'public.usage_logs'::regclass
)
SELECT COALESCE(bool_and(
           indisvalid
           AND indisready
           AND indislive
           AND NOT indisunique
           AND NOT indisprimary
           AND indexprs IS NULL
           AND indnkeyatts = 3
           AND indnatts = 8
           AND indoption::text = '0 3 3'
           AND amname = 'btree'
           AND indexed_columns = ARRAY[
               'upstream_account_type', 'created_at', 'id',
               'logical_request_id', 'route_class', 'route_group_id',
               'guardian_attempt_only', 'attempt_index'
           ]::text[]
           AND normalized_predicate IN (
               'upstream_error_kind::text=''cyber_policy''::text',
               'upstream_error_kind=''cyber_policy''',
               'upstream_error_kind=''cyber_policy''::text'
           )
       ), false) AND count(*) = 1 AS rb15_index_verified
FROM target
\gset

\if :rb15_index_verified
\echo 'rb15 cyber case index verification passed'
\else
\echo 'ERROR: rb15 cyber case index postcondition verification failed'
SELECT 1 / 0 AS rb15_abort_index_postcondition;
\endif

-- Optional query-plan verification for a non-trivial window:
-- EXPLAIN (ANALYZE, BUFFERS)
-- SELECT id
-- FROM usage_logs
-- WHERE created_at >= now() - interval '3 hours'
--   AND created_at <= now()
--   AND upstream_error_kind = 'cyber_policy'
--   AND upstream_account_type = 'oauth'
-- ORDER BY created_at DESC, id DESC;
