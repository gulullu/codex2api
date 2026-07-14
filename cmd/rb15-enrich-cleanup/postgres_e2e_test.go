package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const (
	e2eBackupTable   = "public.rb15_e2e_backup"
	e2eManifestTable = "public.rb15_e2e_manifest"
)

// TestPostgresE2E is intentionally opt-in and destructive only inside a
// database whose name starts with rb15_e2e_. The runbook starts such a
// disposable PostgreSQL instance for this test.
func TestPostgresE2E(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("RB15_E2E_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set RB15_E2E_DATABASE_URL to a disposable PostgreSQL database")
	}
	t.Setenv("RB15_DATABASE_URL", dsn)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var databaseName string
	if err := db.QueryRow(`select current_database()`).Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(databaseName, "rb15_e2e_") {
		t.Fatalf("refusing destructive E2E against non-ephemeral database %q", databaseName)
	}
	defer dropE2ETables(t, db)
	testTrackedSnapshotSQL(t, db)
	dropE2ETables(t, db)

	originals := setupE2ESnapshot(t, db, 3)
	opts := e2eOptions(t)
	dry, err := run(context.Background(), opts)
	if err != nil {
		t.Fatalf("cleanup dry-run: %v", err)
	}
	assertLiveValues(t, db, originals)

	batchCalls := 0
	execute := opts
	execute.execute = true
	execute.expectedRows = dry.CandidateSnapshot.Count
	execute.expectedCandidateDigest = dry.CandidateSnapshot.Digest
	execute.testBeforeMutation = func(context.Context, []backupLiveRow) error {
		batchCalls++
		return nil
	}
	result, err := run(context.Background(), execute)
	if err != nil {
		t.Fatalf("multi-batch execute: %v", err)
	}
	if result.Mutated != 3 || batchCalls != 3 {
		t.Fatalf("multi-batch result mutated=%d calls=%d", result.Mutated, batchCalls)
	}
	assertCleanValues(t, db, 3)

	// CAS conflict after the first committed batch, followed by an idempotent
	// resume using the same sealed snapshot and dry-run digest.
	originals = setupE2ESnapshot(t, db, 3)
	dry, err = run(context.Background(), opts)
	if err != nil {
		t.Fatalf("CAS dry-run: %v", err)
	}
	execute = opts
	execute.execute = true
	execute.expectedRows = dry.CandidateSnapshot.Count
	execute.expectedCandidateDigest = dry.CandidateSnapshot.Digest
	hookCalls := 0
	execute.testBeforeMutation = func(ctx context.Context, batch []backupLiveRow) error {
		hookCalls++
		if hookCalls == 2 {
			_, err := db.ExecContext(ctx, `update public.prompt_filter_logs set full_text = 'concurrent drift' where id = $1`, batch[0].id)
			return err
		}
		return nil
	}
	partial, err := run(context.Background(), execute)
	if err == nil || !strings.Contains(err.Error(), "conditional update conflict") {
		t.Fatalf("expected CAS conflict, got result=%+v err=%v", partial, err)
	}
	if partial.Mutated != 1 {
		t.Fatalf("first committed batch was not reported: mutated=%d", partial.Mutated)
	}
	if _, err := db.Exec(`update public.prompt_filter_logs set full_text=$1, text_preview=$2 where id=2`, originals[2][0], originals[2][1]); err != nil {
		t.Fatal(err)
	}
	execute.testBeforeMutation = nil
	resumed, err := run(context.Background(), execute)
	if err != nil {
		t.Fatalf("resume after CAS conflict: %v", err)
	}
	if resumed.Mutated != 2 {
		t.Fatalf("resume mutated=%d, want 2", resumed.Mutated)
	}
	assertCleanValues(t, db, 3)

	// A post-cleanup edit must block rollback before any write.
	if _, err := db.Exec(`update public.prompt_filter_logs set text_preview='post cleanup drift' where id=3`); err != nil {
		t.Fatal(err)
	}
	rollback := opts
	rollback.operation = operationRollback
	rollbackDry, err := run(context.Background(), rollback)
	if err == nil || !strings.Contains(err.Error(), "live_content_drift") {
		t.Fatalf("rollback drift was not rejected: report=%+v err=%v", rollbackDry, err)
	}
	if _, err := db.Exec(`update public.prompt_filter_logs set text_preview='payload-3' where id=3`); err != nil {
		t.Fatal(err)
	}

	// Hold a row lock from a separate transaction. The mutation must stop at
	// lock_timeout rather than hang until the batch deadline.
	blocker, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.Exec(`update public.prompt_filter_logs set full_text=full_text where id=1`); err != nil {
		t.Fatal(err)
	}
	rollback.execute = true
	rollback.expectedRows = dry.CandidateSnapshot.Count
	rollback.expectedCandidateDigest = dry.CandidateSnapshot.Digest
	rollback.lockTimeout = 150 * time.Millisecond
	rollback.statementTimeout = 2 * time.Second
	rollback.batchDeadline = 3 * time.Second
	started := time.Now()
	_, err = run(context.Background(), rollback)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "lock timeout") {
		t.Fatalf("expected lock timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("lock timeout took too long: %v", elapsed)
	}
}

func testTrackedSnapshotSQL(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
create table public.prompt_filter_logs(
 id bigint primary key,
 created_at timestamptz,
 source text,
 logical_request_id text,
 full_text text,
 text_preview text
)`); err != nil {
		t.Fatal(err)
	}
	full, preview := legacyBlock("upstream_cyber_policy", "tracked-sql-payload", false)
	if _, err := db.Exec(`
insert into public.prompt_filter_logs(id, created_at, source, logical_request_id, full_text, text_preview)
values(1, now(), 'upstream_cyber_policy', 'tracked-sql-1', $1, $2)`, full, preview); err != nil {
		t.Fatal(err)
	}
	sessionFull, sessionPreview := legacyBlock("session_bleed", "session-bleed-payload", false)
	if _, err := db.Exec(`
insert into public.prompt_filter_logs(id, created_at, source, logical_request_id, full_text, text_preview)
values(2, now(), 'session_bleed', 'tracked-sql-2', $1, $2)`, sessionFull, sessionPreview); err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate tracked SQL from test source path")
	}
	sqlPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "ops", "rb15-enrich-cleanup", "create-sealed-snapshot.sql"))
	raw, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("read tracked snapshot SQL: %v", err)
	}
	render := func(backup, manifest string) string {
		rendered := string(raw)
		rendered = strings.Replace(rendered, "\\set ON_ERROR_STOP on", "", 1)
		rendered = strings.ReplaceAll(rendered, `public.:"backup_table"`, "public."+backup)
		rendered = strings.ReplaceAll(rendered, `public.:"manifest_table"`, "public."+manifest)
		rendered = strings.ReplaceAll(rendered, `:'backup_table'`, `'`+backup+`'`)
		rendered = strings.ReplaceAll(rendered, `:'manifest_table'`, `'`+manifest+`'`)
		return rendered
	}
	rendered := render("rb15_sql_backup", "rb15_sql_manifest")
	if strings.Contains(rendered, `public.:"`) ||
		strings.Contains(rendered, `:'backup_table'`) ||
		strings.Contains(rendered, `:'manifest_table'`) {
		t.Fatal("tracked SQL test renderer left an unresolved psql variable")
	}
	if _, err := db.Exec(rendered); err != nil {
		t.Fatalf("execute tracked snapshot SQL: %v", err)
	}
	var count int
	var allSafe bool
	if err := db.QueryRow(`
select count(*), bool_and(marker_pair and source_supported and full_parse_safe and preview_parse_safe and type_source_safe)
from public.rb15_sql_backup`).Scan(&count, &allSafe); err != nil {
		t.Fatal(err)
	}
	if count != 2 || !allSafe {
		t.Fatalf("tracked SQL candidate count=%d all_safe=%v", count, allSafe)
	}
	var manifestCount int
	if err := db.QueryRow(`select candidate_count from public.rb15_sql_manifest where manifest_key='rb15'`).Scan(&manifestCount); err != nil {
		t.Fatal(err)
	}
	if manifestCount != count {
		t.Fatalf("tracked SQL manifest count=%d, backup count=%d", manifestCount, count)
	}

	if _, err := db.Exec(`update public.prompt_filter_logs set source='unsupported_source' where id=2`); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(render("rb15_unsafe_backup", "rb15_unsafe_manifest"))
	if err == nil || !strings.Contains(err.Error(), "unsafe candidate set") {
		t.Fatalf("tracked SQL silently omitted unsafe marker pair: %v", err)
	}
	if _, rollbackErr := db.Exec(`rollback`); rollbackErr != nil {
		t.Fatalf("rollback failed tracked SQL transaction: %v", rollbackErr)
	}
	var unsafeBackupExists bool
	if err := db.QueryRow(`select to_regclass('public.rb15_unsafe_backup') is not null`).Scan(&unsafeBackupExists); err != nil {
		t.Fatal(err)
	}
	if unsafeBackupExists {
		t.Fatal("unsafe snapshot transaction did not roll back")
	}
}

func e2eOptions(t *testing.T) options {
	t.Helper()
	backupSQL, err := quoteQualifiedIdentifier(e2eBackupTable)
	if err != nil {
		t.Fatal(err)
	}
	manifestSQL, err := quoteQualifiedIdentifier(e2eManifestTable)
	if err != nil {
		t.Fatal(err)
	}
	return options{
		backupTable:      e2eBackupTable,
		backupTableSQL:   backupSQL,
		manifestTable:    e2eManifestTable,
		manifestTableSQL: manifestSQL,
		operation:        operationCleanup,
		batchSize:        1,
		statementTimeout: 2 * time.Second,
		lockTimeout:      500 * time.Millisecond,
		batchDeadline:    5 * time.Second,
	}
}

func setupE2ESnapshot(t *testing.T, db *sql.DB, count int) map[int64][2]string {
	t.Helper()
	dropE2ETables(t, db)
	ddl := `
create table public.prompt_filter_logs (
  id bigint primary key,
  full_text text,
  text_preview text
);
create table public.rb15_e2e_backup (
  id bigint primary key,
  source text,
  original_full_text text,
  original_text_preview text,
  original_full_md5 text,
  original_preview_md5 text,
  marker_pair boolean not null,
  source_supported boolean not null,
  full_parse_safe boolean not null,
  preview_parse_safe boolean not null,
  type_source_safe boolean not null,
  full_prefix_bytes integer not null,
  preview_prefix_bytes integer not null
);
create table public.rb15_e2e_manifest (
  manifest_key text primary key,
  parser_version text not null,
  predicate_version text not null,
  target_table text not null,
  backup_table text not null,
  candidate_count integer not null,
  sealed boolean not null,
  sealed_at timestamptz,
  database_oid bigint not null,
  target_relid bigint not null,
  target_relfilenode bigint not null,
  backup_relid bigint not null,
  backup_relfilenode bigint not null,
  manifest_relid bigint not null,
  manifest_relfilenode bigint not null
);`
	if _, err := db.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	originals := make(map[int64][2]string, count)
	for i := 1; i <= count; i++ {
		source := "local_filter"
		if i%2 == 0 {
			source = "upstream_cyber_policy"
		}
		full, preview := legacyBlock(source, fmt.Sprintf("payload-%d", i), i == count)
		originals[int64(i)] = [2]string{full, preview}
		if _, err := db.Exec(`insert into public.prompt_filter_logs(id, full_text, text_preview) values($1,$2,$3)`, i, full, preview); err != nil {
			t.Fatal(err)
		}
		stripped, err := stripLegacyEnrichment(source, full, preview)
		if err != nil {
			t.Fatal(err)
		}
		fullPrefix := len(full) - len(stripped.cleanFullText)
		previewPrefix := len(preview) - len(stripped.cleanTextPreview)
		if _, err := db.Exec(`
insert into public.rb15_e2e_backup(
 id, source, original_full_text, original_text_preview,
 original_full_md5, original_preview_md5, marker_pair,
 source_supported, full_parse_safe, preview_parse_safe, type_source_safe,
 full_prefix_bytes, preview_prefix_bytes)
values($1,$2,$3,$4,$5,$6,true,true,true,true,true,$7,$8)`,
			i, source, full, preview, md5String(full), md5String(preview), fullPrefix, previewPrefix); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`
insert into public.rb15_e2e_manifest(
 manifest_key, parser_version, predicate_version, target_table, backup_table,
 candidate_count, sealed, sealed_at, database_oid,
 target_relid, target_relfilenode, backup_relid, backup_relfilenode,
 manifest_relid, manifest_relfilenode)
select 'rb15', $1, $2, $3, $4, $5, true, now(), d.oid,
       t.oid, t.relfilenode, b.oid, b.relfilenode, m.oid, m.relfilenode
from pg_database d
join pg_class t on t.oid=to_regclass($3)
join pg_class b on b.oid=to_regclass($4)
join pg_class m on m.oid=to_regclass($6)
where d.datname=current_database()`,
		parserVersion, predicateVersion, targetTable, e2eBackupTable, count, e2eManifestTable,
	); err != nil {
		t.Fatal(err)
	}
	return originals
}

func dropE2ETables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
drop table if exists public.rb15_sql_manifest;
drop table if exists public.rb15_sql_backup;
drop table if exists public.rb15_unsafe_manifest;
drop table if exists public.rb15_unsafe_backup;
drop table if exists public.rb15_e2e_manifest;
drop table if exists public.rb15_e2e_backup;
drop table if exists public.prompt_filter_logs;
drop function if exists public.rb15_reject_snapshot_mutation();`); err != nil {
		t.Fatal(err)
	}
}

func assertLiveValues(t *testing.T, db *sql.DB, want map[int64][2]string) {
	t.Helper()
	for id, values := range want {
		var full, preview sql.NullString
		if err := db.QueryRow(`select full_text, text_preview from public.prompt_filter_logs where id=$1`, id).Scan(&full, &preview); err != nil {
			t.Fatal(err)
		}
		if !full.Valid || !preview.Valid || full.String != values[0] || preview.String != values[1] {
			t.Fatalf("id %d changed during dry-run", id)
		}
	}
}

func assertCleanValues(t *testing.T, db *sql.DB, count int) {
	t.Helper()
	for i := 1; i <= count; i++ {
		var full, preview sql.NullString
		if err := db.QueryRow(`select full_text, text_preview from public.prompt_filter_logs where id=$1`, i).Scan(&full, &preview); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("payload-%d", i)
		if !full.Valid || !preview.Valid || full.String != want || preview.String != want {
			t.Fatalf("id %d not clean: full=%q preview=%q", i, full.String, preview.String)
		}
	}
}
