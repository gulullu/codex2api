# rb15 legacy enrichment cleanup runbook

This one-off tool removes only the exact attribution prefixes written by the
retired `scripts/enrich_misses.py` job. It never infers ownership, prints prompt
text, changes routing/account state, restarts a service, or enables the timer.

The tool fails closed around four immutable facts: a sealed backup, a sealed
manifest, current PostgreSQL relation identity, and the exact candidate digest
reported by dry-run. Writes use exact text compare-and-set with strict `NULL`
semantics. Every transaction also has statement, lock, and total batch limits.

## Preconditions

1. `codex2api-miss-enrich.timer` is disabled/inactive and its service is not
   running. Do not proceed while the retired writer can run.
2. Work from the reviewed rb15 commit. Do not reuse the older unsealed backup;
   create a new backup+manifest pair with the tracked SQL below.
3. Keep the sealed pair and retired unit/script until the observation and
   rollback period is accepted.
4. Stop on any manifest, identity, parse-safety, drift, CAS, or timeout error.
   Never widen the parser or overwrite a row merely to make the run pass.

## Unit and disposable PostgreSQL E2E tests

```bash
go test ./cmd/rb15-enrich-cleanup

E2E_IMAGE='postgres@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa'
docker image inspect "$E2E_IMAGE" >/dev/null
docker rm -f rb15-enrich-e2e >/dev/null 2>&1 || true
trap 'docker rm -f rb15-enrich-e2e >/dev/null 2>&1 || true' EXIT
docker run -d --name rb15-enrich-e2e \
  --tmpfs /var/lib/postgresql:rw,nosuid,size=256m \
  -e POSTGRES_PASSWORD=rb15-e2e-only \
  -e POSTGRES_DB=rb15_e2e_test \
  -p 127.0.0.1:55432:5432 \
  "$E2E_IMAGE" >/dev/null
until docker exec rb15-enrich-e2e pg_isready -U postgres -d rb15_e2e_test >/dev/null 2>&1; do sleep 1; done
RB15_E2E_DATABASE_URL='postgres://postgres:rb15-e2e-only@127.0.0.1:55432/rb15_e2e_test?sslmode=disable' \
  go test -count=1 -run '^TestPostgresE2E$' ./cmd/rb15-enrich-cleanup
docker rm -f rb15-enrich-e2e >/dev/null
trap - EXIT
```

The E2E test itself refuses any database whose name does not start with
`rb15_e2e_`. It directly executes the tracked snapshot SQL and asserts a real
Unicode marker produces a non-empty, all-safe snapshot; it also covers dry-run
zero writes, multiple batches, execute, CAS conflict, resume, rollback drift,
and lock timeout.

## Build and locked-down runtime inputs

```bash
install -d -m 0700 /root/codex2api-ops
CGO_ENABLED=0 go build -trimpath \
  -o /root/codex2api-ops/rb15-enrich-cleanup \
  ./cmd/rb15-enrich-cleanup
chmod 0555 /root/codex2api-ops/rb15-enrich-cleanup

NETWORK="$(docker inspect codex2api-postgres \
  --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}' \
  | head -n 1)"
test -n "$NETWORK"

umask 077
DB_ENV="/root/codex2api-ops/rb15-db-env.$$"
trap 'rm -f "$DB_ENV"' EXIT
docker inspect codex2api --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | awk -F= '$1 ~ /^DATABASE_(HOST|NAME|PASSWORD|PORT|SSLMODE|USER)$/ {print}' \
  >"$DB_ENV"
for key in DATABASE_HOST DATABASE_NAME DATABASE_PASSWORD DATABASE_PORT DATABASE_SSLMODE DATABASE_USER; do
  test "$(grep -c "^${key}=" "$DB_ENV")" -eq 1
done
```

This deliberately extracts only six database variables into a root-only,
short-lived file. Never pass the application `.env`, inspect the file, or echo
its values.

The execution image is fixed by digest and must already exist locally:

```bash
RUN_IMAGE='alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce'
docker image inspect "$RUN_IMAGE" >/dev/null
```

Every tool invocation below must retain all of these Docker controls:

```text
--pull=never --read-only --cap-drop=ALL
--security-opt=no-new-privileges:true --pids-limit=64
--memory=64m --cpus=0.5 --user=65534:65534
--tmpfs /tmp:rw,noexec,nosuid,size=8m
```

## Create and seal the candidate snapshot

Choose fresh, timestamped, unqualified names. The tracked SQL creates both
tables in `public`, records the exact candidate predicate and safety fields,
records database/target/backup OIDs and relfilenodes, then installs always-on
reject-mutation triggers. It intentionally fails on zero candidates or reused
names.

```bash
BACKUP_NAME='ops_rb15_enrich_backup_YYYYMMDD_HHMMSS'
MANIFEST_NAME='ops_rb15_enrich_manifest_YYYYMMDD_HHMMSS'
test "$BACKUP_NAME" != "$MANIFEST_NAME"

docker exec -i codex2api-postgres sh -c '
  exec psql -X -v ON_ERROR_STOP=1 \
    -U "${POSTGRES_USER:-postgres}" \
    -d "${POSTGRES_DB:-${POSTGRES_USER:-postgres}}" \
    -v backup_table="$1" -v manifest_table="$2"
' sh "$BACKUP_NAME" "$MANIFEST_NAME" \
  < ops/rb15-enrich-cleanup/create-sealed-snapshot.sql
```

Do not edit, append to, truncate, recreate, or reuse either sealed relation.
The tool rejects a changed database OID, relation OID/relfilenode, count, source,
stored hash, parser flag, or prefix bound.

## Cleanup dry-run

```bash
rb15_run() {
  docker run --rm --pull=never \
    --network "$NETWORK" --env-file "$DB_ENV" \
    --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
    --pids-limit=64 --memory=64m --cpus=0.5 --user=65534:65534 \
    --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --mount type=bind,src=/root/codex2api-ops/rb15-enrich-cleanup,dst=/usr/local/bin/rb15-enrich-cleanup,readonly \
    "$RUN_IMAGE" /usr/local/bin/rb15-enrich-cleanup \
      --backup-table "public.$BACKUP_NAME" \
      --manifest-table "public.$MANIFEST_NAME" \
      --batch-size 100 --statement-timeout 5s --lock-timeout 2s \
      --batch-deadline 100s "$@"
}

umask 077
CLEANUP_EVIDENCE="/root/codex2api-ops/rb15-cleanup-dryrun-${BACKUP_NAME}.json"
CLEANUP_EVIDENCE_SHA="${CLEANUP_EVIDENCE}.sha256"
test ! -e "$CLEANUP_EVIDENCE"
test ! -e "$CLEANUP_EVIDENCE_SHA"
CLEANUP_TMP="$(mktemp /root/codex2api-ops/.rb15-cleanup-dryrun.XXXXXX)"
rb15_run >"$CLEANUP_TMP"
jq -e '.mode == "cleanup-dry-run" and .completed == true and .write_ready == true' \
  "$CLEANUP_TMP" >/dev/null
mv "$CLEANUP_TMP" "$CLEANUP_EVIDENCE"
chmod 0600 "$CLEANUP_EVIDENCE"
sha256sum "$CLEANUP_EVIDENCE" >"$CLEANUP_EVIDENCE_SHA"
chmod 0600 "$CLEANUP_EVIDENCE_SHA"

EXPECTED_ROWS="$(jq -er '.candidate_snapshot.count' "$CLEANUP_EVIDENCE")"
EXPECTED_DIGEST="$(jq -er '.candidate_snapshot.digest_sha256' "$CLEANUP_EVIDENCE")"
test "$EXPECTED_ROWS" -gt 0
test "${#EXPECTED_DIGEST}" -eq 64
```

The root-only JSON plus its SHA-256 sidecar are the external evidence for this
sealed candidate set. Do not edit or replace either file. Inspect counts with
`jq`; before the first cleanup every row should be `pending_cleanup`, while a
resume may also contain `already_clean`. Any other category is a hard stop.

## Execute cleanup

```bash
sha256sum -c "$CLEANUP_EVIDENCE_SHA"
test "$(jq -er '.backup_table' "$CLEANUP_EVIDENCE")" = "public.$BACKUP_NAME"
test "$(jq -er '.manifest_table' "$CLEANUP_EVIDENCE")" = "public.$MANIFEST_NAME"
test "$(jq -er '.candidate_snapshot.digest_sha256' "$CLEANUP_EVIDENCE")" = "$EXPECTED_DIGEST"
rb15_run \
  --execute \
  --expected-rows "$EXPECTED_ROWS" \
  --expected-candidate-digest "$EXPECTED_DIGEST"
```

Success means `completed: true`, postflight entirely `already_clean`, unchanged
candidate snapshot, and identical pre/post clean-suffix digests. A failed batch
rolls back; earlier committed batches are resumable after the cause is resolved
and a fresh dry-run succeeds against the same sealed pair.

## Rollback

The rollback dry-run must independently reproduce the exact same sealed
candidate count and digest before any restore:

```bash
sha256sum -c "$CLEANUP_EVIDENCE_SHA"
ROLLBACK_EVIDENCE="/root/codex2api-ops/rb15-rollback-dryrun-${BACKUP_NAME}.json"
ROLLBACK_EVIDENCE_SHA="${ROLLBACK_EVIDENCE}.sha256"
test ! -e "$ROLLBACK_EVIDENCE"
test ! -e "$ROLLBACK_EVIDENCE_SHA"
ROLLBACK_TMP="$(mktemp /root/codex2api-ops/.rb15-rollback-dryrun.XXXXXX)"
rb15_run --rollback >"$ROLLBACK_TMP"
jq -e '.mode == "rollback-dry-run" and .completed == true and .write_ready == true' \
  "$ROLLBACK_TMP" >/dev/null
test "$(jq -er '.candidate_snapshot.count' "$ROLLBACK_TMP")" = "$EXPECTED_ROWS"
test "$(jq -er '.candidate_snapshot.digest_sha256' "$ROLLBACK_TMP")" = "$EXPECTED_DIGEST"
mv "$ROLLBACK_TMP" "$ROLLBACK_EVIDENCE"
chmod 0600 "$ROLLBACK_EVIDENCE"
sha256sum "$ROLLBACK_EVIDENCE" >"$ROLLBACK_EVIDENCE_SHA"
chmod 0600 "$ROLLBACK_EVIDENCE_SHA"
sha256sum -c "$ROLLBACK_EVIDENCE_SHA"

rb15_run \
  --rollback --execute \
  --expected-rows "$EXPECTED_ROWS" \
  --expected-candidate-digest "$EXPECTED_DIGEST"
```

Proceed only when the rollback evidence contains exclusively
`pending_rollback` or `already_restored`. Success means postflight entirely
`already_restored`.

Rollback restores only exact backed-up text by ID. It must never enable or start
`codex2api-miss-enrich.timer`.

## Abort rules

- A timeout is an abort. Confirm database health before changing any limit.
- A CAS conflict means a live value changed after the batch read. Resolve the
  writer/drift, rerun dry-run, and resume; never force the row.
- Never paste prompts or the temporary DB environment into tickets or output.
  IDs, counts, categories, relation identity, and reported digests suffice.
- Remove the temporary DB env file when finished; keep the sealed relations
  through rollback expiry.
