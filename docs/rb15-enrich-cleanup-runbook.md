# rb15 legacy enrichment cleanup runbook

This runbook removes only the attribution prefixes written by the retired,
untracked `scripts/enrich_misses.py` timer. It does not infer ownership, change
routing, restart codex2api, or enable/disable any account.

The command is intentionally fail-closed:

- dry-run is the default;
- candidates come only from an explicitly named frozen backup table;
- a write requires the exact row count and candidate SHA-256 printed by dry-run;
- each backup value must match its stored MD5;
- each live value must be either the exact backup value or the exact cleaned suffix;
- each update has an MD5 compare-and-set condition and verifies the returned suffix hash;
- prompt text is never printed. Reports contain only counts and hashes;
- rollback restores exact backup values by ID and never re-enables the legacy timer.

## Preconditions

1. Confirm `codex2api-miss-enrich.timer` is disabled and inactive, and its service
   is not running. Do not proceed while the writer can still mutate rows.
2. Confirm the frozen backup table exists and is immutable. For rb15 the table is:
   `public.ops_rb15_enrich_backup_20260715_031815`.
3. Do not run this command from an interactive shell that echoes environment
   variables. The command reads database settings from `RB15_DATABASE_URL`, or
   the normal `DATABASE_*` variables, and never logs the connection string.
4. Keep the backup table until the rb15 observation period is accepted. Dropping
   it removes the supported rollback source.

## Build and unit test

Run from the reviewed rb15 source tree:

```bash
go test ./cmd/rb15-enrich-cleanup
install -d -m 0700 /root/codex2api-ops
CGO_ENABLED=0 go build -trimpath \
  -o /root/codex2api-ops/rb15-enrich-cleanup \
  ./cmd/rb15-enrich-cleanup
chmod 0700 /root/codex2api-ops/rb15-enrich-cleanup
```

The examples below use an ephemeral container on the private network currently
attached to PostgreSQL. Resolve the network name at runtime instead of assuming
a Compose-generated name:

```bash
NETWORK="$(docker inspect codex2api-postgres \
  --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}' \
  | head -n 1)"
RUNTIME_DIR="$(docker inspect codex2api \
  --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}')"
ENV_FILE="$RUNTIME_DIR/.env"
test -n "$NETWORK"
test -f "$ENV_FILE"
```

Adjust only the source-tree path if the release worktree differs.

## Cleanup dry-run

```bash
docker run --rm \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -v /root/codex2api-ops/rb15-enrich-cleanup:/usr/local/bin/rb15-enrich-cleanup:ro \
  alpine:3.22 \
  /usr/local/bin/rb15-enrich-cleanup \
    --backup-table public.ops_rb15_enrich_backup_20260715_031815 \
    --batch-size 200 \
    --statement-timeout 5s \
    --lock-timeout 2s
```

Expected preflight state before the first cleanup is `pending_cleanup` for all
candidate rows. Record, without editing, these two fields from the JSON output:

- `candidate_snapshot.count`
- `candidate_snapshot.digest_sha256`

The report must say `write_ready: true`. Any `backup_*`,
`marker_signature_invalid`, `target_missing`, or
`live_content_drift` count is a hard stop. Investigate it; never widen the marker
parser or overwrite a drifted row to make the run pass.

## Execute cleanup

Replace the placeholders only with values copied from the immediately preceding
successful dry-run:

```bash
docker run --rm \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -v /root/codex2api-ops/rb15-enrich-cleanup:/usr/local/bin/rb15-enrich-cleanup:ro \
  alpine:3.22 \
  /usr/local/bin/rb15-enrich-cleanup \
    --backup-table public.ops_rb15_enrich_backup_20260715_031815 \
    --batch-size 200 \
    --statement-timeout 5s \
    --lock-timeout 2s \
    --execute \
    --expected-rows '<candidate_snapshot.count>' \
    --expected-candidate-digest '<candidate_snapshot.digest_sha256>'
```

A successful result has `completed: true`, postflight count entirely in
`already_clean`, identical preflight/postflight clean-suffix digests, and a
candidate snapshot identical to dry-run. The command is resumable: after a
signal, timeout, or compare-and-set conflict, resolve the cause, repeat dry-run,
and rerun with the same frozen snapshot. Already-clean rows are skipped.

## Rollback dry-run and execute

Rollback is a separate operation and is itself dry-run by default:

```bash
docker run --rm \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -v /root/codex2api-ops/rb15-enrich-cleanup:/usr/local/bin/rb15-enrich-cleanup:ro \
  alpine:3.22 \
  /usr/local/bin/rb15-enrich-cleanup \
    --backup-table public.ops_rb15_enrich_backup_20260715_031815 \
    --rollback
```

Proceed only if all rows are `pending_rollback` or `already_restored`. Then add
`--execute`, the exact expected row count, and the exact candidate digest:

```bash
docker run --rm \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -v /root/codex2api-ops/rb15-enrich-cleanup:/usr/local/bin/rb15-enrich-cleanup:ro \
  alpine:3.22 \
  /usr/local/bin/rb15-enrich-cleanup \
    --backup-table public.ops_rb15_enrich_backup_20260715_031815 \
    --rollback \
    --execute \
    --expected-rows '<candidate_snapshot.count>' \
    --expected-candidate-digest '<candidate_snapshot.digest_sha256>'
```

A successful rollback has all rows in `already_restored`.

Rollback restores database text only. It must not enable or start
`codex2api-miss-enrich.timer`; the obsolete writer remains disabled unless a
separate, explicitly reviewed decision says otherwise.

## Abort and incident rules

- A statement or lock timeout is an abort, not permission to raise timeouts
  blindly. Confirm database health first.
- A conditional-update conflict means a candidate changed after preflight. The
  current batch is rolled back; earlier committed batches are safe and
  idempotently recognized on the next run.
- Never paste prompt fields into a ticket or terminal. IDs, counts, category
  names, and the reported hashes are sufficient for investigation.
- Never drop the backup table or delete the retired script/unit during the same
  change window. Preserve both until acceptance and rollback expiry.
