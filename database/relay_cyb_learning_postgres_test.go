package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRelayCYBLegacyUserTextMigrationAgainstPostgres exercises the exact
// production upgrade shape: an existing table without sample_source or
// user_text_truncated. It uses a unique disposable schema and never touches
// public tables. Set CODEX2API_TEST_POSTGRES_DSN to enable it.
func TestRelayCYBLegacyUserTextMigrationAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("CODEX2API_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("未设置 CODEX2API_TEST_POSTGRES_DSN，跳过 PostgreSQL CYB 迁移用例")
	}

	ctx := context.Background()
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	schema := fmt.Sprintf("relay_cyb_legacy_test_%d", time.Now().UnixNano())
	if _, err := conn.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create disposable schema: %v", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop disposable schema: %v", err)
		}
	}()
	if _, err := conn.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		t.Fatalf("set disposable search_path: %v", err)
	}

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE rb_cyb_rules (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			pattern TEXT NOT NULL UNIQUE,
			rationale TEXT NOT NULL DEFAULT '',
			source_request_id TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			disabled_reason TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE rb_cyb_miss_samples (
			request_id TEXT PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			oauth_account_id BIGINT NOT NULL DEFAULT 0,
			oauth_account_name TEXT NOT NULL DEFAULT '',
			oauth_account_type TEXT NOT NULL DEFAULT '',
			redacted_request TEXT NOT NULL DEFAULT '',
			user_text TEXT NOT NULL DEFAULT '',
			request_truncated BOOLEAN NOT NULL DEFAULT FALSE,
			content_hash TEXT NOT NULL DEFAULT '',
			learning_status TEXT NOT NULL DEFAULT 'queued',
			learning_model TEXT NOT NULL DEFAULT '',
			learning_attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TIMESTAMPTZ NULL,
			learning_error TEXT NOT NULL DEFAULT '',
			rule_id BIGINT NOT NULL DEFAULT 0,
			learned_at TIMESTAMPTZ NULL
		)
	`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	var preVersionRuleID int64
	if err := conn.QueryRowContext(ctx, `
		INSERT INTO rb_cyb_rules (
			name, pattern, rationale, source_request_id, model, enabled
		) VALUES ($1, $2, $3, $4, $5, TRUE)
		RETURNING id
	`, "pre_version_postgres_rule", `(?i)pre.{0,20}version`, "baseline fixture",
		"pre-version-postgres-applied", "gpt-5.4").Scan(&preVersionRuleID); err != nil {
		t.Fatalf("insert pre-version rule: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash,
			learning_status, rule_id
		) VALUES ($1, $2, $2, $3, $4, $5, $6)
	`, "pre-version-postgres-applied", time.Now().UTC().Add(-time.Minute),
		"pre-version user evidence", "pre-version-postgres-applied-hash",
		RelayCYBLearningStatusApplied, preVersionRuleID); err != nil {
		t.Fatalf("insert pre-version applied sample: %v", err)
	}
	for index, status := range []string{
		RelayCYBLearningStatusQueued,
		RelayCYBLearningStatusRetry,
		RelayCYBLearningStatusProcessing,
	} {
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO rb_cyb_miss_samples (
				request_id, created_at, updated_at, user_text, content_hash, learning_status
			) VALUES ($1, $2, $2, $3, $4, $5)
		`,
			fmt.Sprintf("legacy-postgres-%d", index),
			time.Now().UTC().Add(time.Duration(index)*time.Second),
			"legacy head-only user text",
			fmt.Sprintf("legacy-postgres-hash-%d", index),
			status,
		); err != nil {
			t.Fatalf("insert legacy %s row: %v", status, err)
		}
	}

	db := &DB{conn: conn, driver: "postgres"}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("migrate legacy PostgreSQL CYB schema: %v", err)
	}

	var quarantined int
	if err := conn.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM rb_cyb_miss_samples
		WHERE sample_source = $1
		  AND user_text_truncated = TRUE
		  AND learning_status = $2
		  AND learning_error LIKE $3
	`,
		RelayCYBMissSourceOAuth,
		RelayCYBLearningStatusRejected,
		"%旧版头部提取%",
	).Scan(&quarantined); err != nil {
		t.Fatalf("count quarantined legacy rows: %v", err)
	}
	if quarantined != 3 {
		t.Fatalf("quarantined legacy rows = %d, want 3", quarantined)
	}
	var preVersionStatus string
	var preVersionExtractor int
	var preVersionRuleEnabled bool
	if err := conn.QueryRowContext(ctx, `
		SELECT sample.learning_status, sample.extractor_version, rule.enabled
		FROM rb_cyb_miss_samples sample
		JOIN rb_cyb_rules rule ON rule.id = sample.rule_id
		WHERE sample.request_id = $1
	`, "pre-version-postgres-applied").Scan(
		&preVersionStatus,
		&preVersionExtractor,
		&preVersionRuleEnabled,
	); err != nil {
		t.Fatalf("read pre-version applied sample: %v", err)
	}
	if preVersionStatus != RelayCYBLearningStatusApplied ||
		preVersionExtractor != -1 ||
		!preVersionRuleEnabled {
		t.Fatalf(
			"pre-version applied state = status %q extractor %d enabled %t",
			preVersionStatus,
			preVersionExtractor,
			preVersionRuleEnabled,
		)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash,
			learning_status, rule_id
		) VALUES ($1, $2, $2, $3, $4, $5, $6)
	`, "rollback-postgres-merged-existing", time.Now().UTC().Add(30*time.Second),
		"head-only rollback sample merged into an existing pattern",
		"rollback-postgres-merged-existing-hash",
		RelayCYBLearningStatusMerged, preVersionRuleID); err != nil {
		t.Fatalf("insert rollback merged sample: %v", err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("quarantine rollback merged sample: %v", err)
	}
	var mergedStatus string
	var mergedError string
	if err := conn.QueryRowContext(ctx, `
		SELECT learning_status, learning_error
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
	`, "rollback-postgres-merged-existing").Scan(&mergedStatus, &mergedError); err != nil {
		t.Fatalf("read rollback merged sample: %v", err)
	}
	if err := conn.QueryRowContext(ctx, `
		SELECT enabled
		FROM rb_cyb_rules
		WHERE id = $1
	`, preVersionRuleID).Scan(&preVersionRuleEnabled); err != nil {
		t.Fatalf("read pre-version rule after rollback merge: %v", err)
	}
	if mergedStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(mergedError, "既有规则保持不变") ||
		!preVersionRuleEnabled {
		t.Fatalf(
			"rollback merged state = status %q error %q existing_enabled %t",
			mergedStatus,
			mergedError,
			preVersionRuleEnabled,
		)
	}

	if _, err := conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, sample_source,
			user_text, extractor_version, user_text_truncated, content_hash, learning_status
		) VALUES ($1, $2, $2, $3, $4, $5, TRUE, $6, $7)
	`,
		"new-postgres-bounded",
		time.Now().UTC().Add(time.Minute),
		RelayCYBMissSourceRelay,
		"bounded head\n<<<USER_TEXT_MIDDLE_TRUNCATED>>>\nactual tail",
		relayCYBCurrentExtractorVersion,
		"new-postgres-bounded-hash",
		RelayCYBLearningStatusQueued,
	); err != nil {
		t.Fatalf("insert new bounded row: %v", err)
	}
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim new bounded row: %v", err)
	}
	if claimed == nil ||
		claimed.RequestID != "new-postgres-bounded" ||
		claimed.SampleSource != RelayCYBMissSourceRelay {
		t.Fatalf("claim after migration = %+v", claimed)
	}

	if _, err := conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash, learning_status
		) VALUES ($1, $2, $2, $3, $4, $5)
	`,
		"rollback-postgres-head-only",
		time.Now().UTC().Add(2*time.Minute),
		"head-only text written by a rolled-back binary",
		"rollback-postgres-head-only-hash",
		RelayCYBLearningStatusQueued,
	); err != nil {
		t.Fatalf("insert rollback-created legacy row: %v", err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("repeat migration after rollback-created row: %v", err)
	}
	var rollbackStatus string
	if err := conn.QueryRowContext(ctx, `
		SELECT learning_status
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
	`, "rollback-postgres-head-only").Scan(&rollbackStatus); err != nil {
		t.Fatalf("read rollback-created legacy row: %v", err)
	}
	if rollbackStatus != RelayCYBLearningStatusRejected {
		t.Fatalf("rollback-created legacy status = %q, want rejected", rollbackStatus)
	}

	var rollbackRuleID int64
	if err := conn.QueryRowContext(ctx, `
		INSERT INTO rb_cyb_rules (
			name, pattern, rationale, source_request_id, model, enabled
		) VALUES ($1, $2, $3, $4, $5, TRUE)
		RETURNING id
	`, "rollback_postgres_rule", `(?i)rollback.{0,20}head`, "rollback fixture",
		"rollback-postgres-applied", "gpt-5.4").Scan(&rollbackRuleID); err != nil {
		t.Fatalf("insert rollback-generated rule: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash,
			learning_status, rule_id
		) VALUES ($1, $2, $2, $3, $4, $5, $6)
	`, "rollback-postgres-applied", time.Now().UTC().Add(3*time.Minute),
		"head-only text learned by a rolled-back worker",
		"rollback-postgres-applied-hash",
		RelayCYBLearningStatusApplied, rollbackRuleID); err != nil {
		t.Fatalf("insert rollback-applied sample: %v", err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("repeat migration after rollback-applied row: %v", err)
	}
	var rollbackAppliedStatus string
	var rollbackRuleEnabled bool
	var rollbackDisabledReason string
	if err := conn.QueryRowContext(ctx, `
		SELECT sample.learning_status, rule.enabled, rule.disabled_reason
		FROM rb_cyb_miss_samples sample
		JOIN rb_cyb_rules rule ON rule.id = sample.rule_id
		WHERE sample.request_id = $1
	`, "rollback-postgres-applied").Scan(
		&rollbackAppliedStatus,
		&rollbackRuleEnabled,
		&rollbackDisabledReason,
	); err != nil {
		t.Fatalf("read rollback-applied state: %v", err)
	}
	if rollbackAppliedStatus != RelayCYBLearningStatusRejected ||
		rollbackRuleEnabled ||
		!strings.Contains(rollbackDisabledReason, "旧版头部提取") {
		t.Fatalf(
			"rollback-applied state = status %q enabled %t reason %q",
			rollbackAppliedStatus,
			rollbackRuleEnabled,
			rollbackDisabledReason,
		)
	}
}

func TestRelayCYBLegacyQuarantineWaitsForConcurrentPostgresWorker(t *testing.T) {
	dsn := os.Getenv("CODEX2API_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("未设置 CODEX2API_TEST_POSTGRES_DSN，跳过 PostgreSQL CYB 并发迁移用例")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	observer, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open observer postgres: %v", err)
	}
	observer.SetMaxOpenConns(1)
	observer.SetMaxIdleConns(1)
	defer observer.Close()
	if err := observer.PingContext(ctx); err != nil {
		t.Fatalf("ping observer postgres: %v", err)
	}

	schema := fmt.Sprintf("relay_cyb_race_test_%d", time.Now().UnixNano())
	if _, err := observer.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create disposable race schema: %v", err)
	}
	defer func() {
		if _, err := observer.ExecContext(
			context.Background(),
			`DROP SCHEMA `+schema+` CASCADE`,
		); err != nil {
			t.Errorf("drop disposable race schema: %v", err)
		}
	}()

	openSession := func(name string) *sql.DB {
		t.Helper()
		conn, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s postgres: %v", name, err)
		}
		conn.SetMaxOpenConns(1)
		conn.SetMaxIdleConns(1)
		if err := conn.PingContext(ctx); err != nil {
			conn.Close()
			t.Fatalf("ping %s postgres: %v", name, err)
		}
		if _, err := conn.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
			conn.Close()
			t.Fatalf("set %s search_path: %v", name, err)
		}
		return conn
	}

	migrationConn := openSession("migration")
	defer migrationConn.Close()
	workerConn := openSession("worker")
	defer workerConn.Close()

	db := &DB{conn: migrationConn, driver: "postgres"}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("initialize PostgreSQL CYB schema: %v", err)
	}

	const requestID = "rollback-postgres-concurrent-worker"
	if _, err := migrationConn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, extractor_version,
			content_hash, learning_status, learning_model, learning_attempts
		) VALUES ($1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $2, 0, $3, $4, $5, 1)
	`, requestID,
		"head-only text held by a rolled-back worker",
		"rollback-postgres-concurrent-worker-hash",
		RelayCYBLearningStatusProcessing,
		"gpt-5.4",
	); err != nil {
		t.Fatalf("insert concurrent legacy sample: %v", err)
	}

	workerTx, err := workerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin old worker transaction: %v", err)
	}
	workerFinished := false
	defer func() {
		if !workerFinished {
			_ = workerTx.Rollback()
		}
	}()
	if err := workerTx.QueryRowContext(ctx, `
		SELECT request_id
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
		FOR UPDATE
	`, requestID).Scan(new(string)); err != nil {
		t.Fatalf("old worker lock sample: %v", err)
	}
	var ruleID int64
	if err := workerTx.QueryRowContext(ctx, `
		INSERT INTO rb_cyb_rules (
			name, pattern, rationale, source_request_id, model, enabled
		) VALUES ($1, $2, $3, $4, $5, TRUE)
		RETURNING id
	`, "rollback_concurrent_rule", `(?i)rollback.{0,32}concurrent`,
		"concurrent rollback fixture", requestID, "gpt-5.4",
	).Scan(&ruleID); err != nil {
		t.Fatalf("old worker insert rule: %v", err)
	}
	if _, err := workerTx.ExecContext(ctx, `
		UPDATE rb_cyb_miss_samples
		SET learning_status = $1, rule_id = $2, learned_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE request_id = $3
	`, RelayCYBLearningStatusApplied, ruleID, requestID); err != nil {
		t.Fatalf("old worker apply rule: %v", err)
	}

	migrationApplicationName := fmt.Sprintf(
		"relay_cyb_quarantine_race_%d",
		time.Now().UnixNano(),
	)
	if _, err := migrationConn.ExecContext(
		ctx,
		`SELECT set_config('application_name', $1, false)`,
		migrationApplicationName,
	); err != nil {
		t.Fatalf("set migration application_name: %v", err)
	}
	migrationDone := make(chan error, 1)
	go func() {
		// Exercise the idempotent quarantine phase directly. Calling the full
		// schema migration here would let unrelated ALTER TABLE locks serialize
		// the sessions and hide this row-lock ordering regression.
		migrationDone <- db.rejectLegacyRelayCYBUserText(ctx)
	}()

	waitDeadline := time.NewTimer(5 * time.Second)
	defer waitDeadline.Stop()
	waitPoll := time.NewTicker(10 * time.Millisecond)
	defer waitPoll.Stop()
	migrationWaiting := false
	for !migrationWaiting {
		select {
		case err := <-migrationDone:
			_ = workerTx.Rollback()
			workerFinished = true
			t.Fatalf("migration completed before old worker released sample lock: %v", err)
		case <-waitPoll.C:
			if err := observer.QueryRowContext(ctx, `
				SELECT EXISTS (
					SELECT 1
					FROM pg_stat_activity
					WHERE application_name = $1
					  AND wait_event_type = 'Lock'
				)
			`, migrationApplicationName).Scan(&migrationWaiting); err != nil {
				_ = workerTx.Rollback()
				workerFinished = true
				t.Fatalf("observe migration lock wait: %v", err)
			}
		case <-waitDeadline.C:
			_ = workerTx.Rollback()
			workerFinished = true
			t.Fatal("migration did not block on the old worker sample lock")
		}
	}

	if err := workerTx.Commit(); err != nil {
		workerFinished = true
		t.Fatalf("commit old worker transaction: %v", err)
	}
	workerFinished = true
	select {
	case err := <-migrationDone:
		if err != nil {
			t.Fatalf("concurrent legacy quarantine: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("concurrent legacy quarantine did not finish: %v", ctx.Err())
	}

	var sampleStatus string
	var ruleEnabled bool
	var disabledReason string
	if err := migrationConn.QueryRowContext(ctx, `
		SELECT sample.learning_status, rule.enabled, rule.disabled_reason
		FROM rb_cyb_miss_samples sample
		JOIN rb_cyb_rules rule ON rule.id = sample.rule_id
		WHERE sample.request_id = $1
	`, requestID).Scan(&sampleStatus, &ruleEnabled, &disabledReason); err != nil {
		t.Fatalf("read concurrent quarantine result: %v", err)
	}
	if sampleStatus != RelayCYBLearningStatusRejected ||
		ruleEnabled ||
		!strings.Contains(disabledReason, "旧版头部提取") {
		t.Fatalf(
			"concurrent quarantine state = status %q enabled %t reason %q",
			sampleStatus,
			ruleEnabled,
			disabledReason,
		)
	}
}

func TestRelayCYBBackfillKeysetAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("CODEX2API_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("未设置 CODEX2API_TEST_POSTGRES_DSN，跳过 PostgreSQL CYB 回填游标用例")
	}

	ctx := context.Background()
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	schema := fmt.Sprintf("relay_cyb_keyset_test_%d", time.Now().UnixNano())
	if _, err := conn.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create disposable keyset schema: %v", err)
	}
	defer func() {
		if _, err := conn.ExecContext(
			context.Background(),
			`DROP SCHEMA `+schema+` CASCADE`,
		); err != nil {
			t.Errorf("drop disposable keyset schema: %v", err)
		}
	}()
	if _, err := conn.ExecContext(ctx, `SET search_path TO `+schema+`, public`); err != nil {
		t.Fatalf("set disposable keyset search_path: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE account_group_members (
			account_id BIGINT NOT NULL,
			group_id BIGINT NOT NULL,
			PRIMARY KEY (account_id, group_id)
		)
	`); err != nil {
		t.Fatalf("create keyset account memberships: %v", err)
	}

	db := &DB{conn: conn, driver: "postgres"}
	if err := db.migrateRelayAudit(ctx); err != nil {
		t.Fatalf("migrate relay audit schema: %v", err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("migrate relay learning schema: %v", err)
	}

	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, requestID := range []string{"postgres-keyset-a", "postgres-keyset-b"} {
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO rb_route_requests (
				request_id, created_at, updated_at, endpoint, full_text,
				route_source
			) VALUES ($1, $2, $2, '/v1/responses', $3, 'official_default')
		`, requestID, createdAt, `{"input":"historical PostgreSQL OAuth CYB sample"}`); err != nil {
			t.Fatalf("insert keyset request %s: %v", requestID, err)
		}
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO rb_route_attempts (
				request_id, attempt_index, account_id, account_type,
				status_code, error_kind, selected_at
			) VALUES ($1, 1, 51, 'oauth', 400, 'cyber_policy', $2)
		`, requestID, createdAt); err != nil {
			t.Fatalf("insert keyset attempt %s: %v", requestID, err)
		}
	}

	for _, sessionTimeZone := range []string{"America/Los_Angeles", "Asia/Shanghai"} {
		t.Run(sessionTimeZone, func(t *testing.T) {
			if _, err := conn.ExecContext(
				ctx,
				`SELECT set_config('TimeZone', $1, false)`,
				sessionTimeZone,
			); err != nil {
				t.Fatalf("set PostgreSQL session timezone: %v", err)
			}

			first, err := db.ListRelayCYBMissBackfillCandidatesAfter(
				ctx,
				0,
				createdAt.Add(time.Minute),
				time.Time{},
				"",
				1,
			)
			if err != nil {
				t.Fatalf("first PostgreSQL keyset page: %v", err)
			}
			if len(first) != 1 || first[0].RequestID != "postgres-keyset-a" {
				t.Fatalf("first PostgreSQL keyset page = %+v", first)
			}
			second, err := db.ListRelayCYBMissBackfillCandidatesAfter(
				ctx,
				0,
				createdAt.Add(time.Minute),
				first[0].CreatedAt,
				first[0].RequestID,
				1,
			)
			if err != nil {
				t.Fatalf("second PostgreSQL keyset page: %v", err)
			}
			if len(second) != 1 || second[0].RequestID != "postgres-keyset-b" {
				t.Fatalf("second PostgreSQL keyset page = %+v", second)
			}
		})
	}
}
