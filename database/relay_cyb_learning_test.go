package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteMigratesRelayCYBLearningSourceAndUserTextTruncation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay-cyb-legacy.db")
	db, err := New("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRelayCYBMissSample(context.Background(), &RelayCYBMissSampleInput{
		RequestID: "legacy-oauth-sample",
		UserText:  "legacy extracted text",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"sample_source", "extractor_version", "user_text_truncated"} {
		if _, err := legacy.Exec(`ALTER TABLE rb_cyb_miss_samples DROP COLUMN ` + column); err != nil {
			legacy.Close()
			t.Fatalf("drop legacy column %s: %v", column, err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("migrate legacy CYB table: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WriteRelayCYBMissSample(context.Background(), &RelayCYBMissSampleInput{
		RequestID:         "migrated-relay-sample",
		SampleSource:      RelayCYBMissSourceRelay,
		UserText:          "migrated user text",
		UserTextTruncated: true,
	}); err != nil {
		t.Fatal(err)
	}
	sample, err := db.GetRelayCYBMissSample(context.Background(), "migrated-relay-sample")
	if err != nil {
		t.Fatal(err)
	}
	if sample.SampleSource != RelayCYBMissSourceRelay || !sample.UserTextTruncated {
		t.Fatalf("migrated sample = %+v", sample)
	}
	legacySample, err := db.GetRelayCYBMissSample(context.Background(), "legacy-oauth-sample")
	if err != nil {
		t.Fatal(err)
	}
	if legacySample.SampleSource != RelayCYBMissSourceOAuth || !legacySample.UserTextTruncated {
		t.Fatalf("legacy sample provenance was not conservatively migrated: %+v", legacySample)
	}
	if legacySample.LearningStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(legacySample.LearningError, "旧版头部提取") {
		t.Fatalf("legacy sample was not quarantined from automatic learning: %+v", legacySample)
	}
	claimed, err := db.ClaimNextRelayCYBMissSample(context.Background(), "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.RequestID != "migrated-relay-sample" {
		t.Fatalf("new bounded sample should remain eligible after one-shot quarantine: %+v", claimed)
	}
}

func TestRelayCYBLegacyUserTextMigrationQuarantinesPendingStatesOnEveryStartup(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	statuses := []string{
		RelayCYBLearningStatusQueued,
		RelayCYBLearningStatusRetry,
		RelayCYBLearningStatusProcessing,
	}
	for index, status := range statuses {
		requestID := "legacy-pending-" + status
		if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
			RequestID:         requestID,
			CreatedAt:         time.Now().UTC().Add(time.Duration(index) * time.Second),
			UserText:          "legacy head-only user text",
			UserTextTruncated: true,
			ContentHash:       "legacy-hash-" + status,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.conn.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, extractor_version = 0
			WHERE request_id = $2
		`, status, requestID); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("run legacy user-text quarantine: %v", err)
	}
	for _, status := range statuses {
		sample, err := db.GetRelayCYBMissSample(ctx, "legacy-pending-"+status)
		if err != nil {
			t.Fatal(err)
		}
		if sample.LearningStatus != RelayCYBLearningStatusRejected ||
			!strings.Contains(sample.LearningError, "旧版头部提取") {
			t.Fatalf("legacy %s sample was not quarantined: %+v", status, sample)
		}
	}

	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:         "new-bounded-truncated",
		CreatedAt:         time.Now().UTC().Add(time.Minute),
		UserText:          "bounded head\n<<<USER_TEXT_MIDDLE_TRUNCATED>>>\nactual tail",
		UserTextTruncated: true,
		ContentHash:       "new-bounded-hash",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("repeat one-shot migration: %v", err)
	}
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.RequestID != "new-bounded-truncated" {
		t.Fatalf("new bounded sample was incorrectly rejected on repeat quarantine: %+v", claimed)
	}

	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash, learning_status
		) VALUES ($1, $2, $2, $3, $4, $5)
	`, "rollback-old-writer", time.Now().UTC().Add(2*time.Minute),
		"head-only text written by a rolled-back binary",
		"rollback-old-writer-hash", RelayCYBLearningStatusQueued); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("quarantine rollback-created legacy sample: %v", err)
	}
	rollbackSample, err := db.GetRelayCYBMissSample(ctx, "rollback-old-writer")
	if err != nil {
		t.Fatal(err)
	}
	if rollbackSample.LearningStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(rollbackSample.LearningError, "旧版头部提取") {
		t.Fatalf("rollback-created legacy sample was claimable: %+v", rollbackSample)
	}

	ruleResult, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_rules (
			name, pattern, rationale, source_request_id, model, enabled
		) VALUES ($1, $2, $3, $4, $5, TRUE)
	`, "rollback_generated_rule", `(?i)rollback.{0,20}head`, "rollback fixture",
		"rollback-old-worker-applied", "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	rollbackRuleID, err := ruleResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash,
			learning_status, rule_id
		) VALUES ($1, $2, $2, $3, $4, $5, $6)
	`, "rollback-old-worker-applied", time.Now().UTC().Add(3*time.Minute),
		"head-only text learned by a rolled-back worker",
		"rollback-old-worker-applied-hash",
		RelayCYBLearningStatusApplied, rollbackRuleID); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("quarantine rule applied by rollback worker: %v", err)
	}
	appliedSample, err := db.GetRelayCYBMissSample(ctx, "rollback-old-worker-applied")
	if err != nil {
		t.Fatal(err)
	}
	if appliedSample.LearningStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(appliedSample.LearningError, "自动停用") {
		t.Fatalf("rollback-applied sample was not quarantined: %+v", appliedSample)
	}
	rollbackRule, err := db.GetRelayCYBRule(ctx, rollbackRuleID)
	if err != nil {
		t.Fatal(err)
	}
	if rollbackRule.Enabled || !strings.Contains(rollbackRule.DisabledReason, "旧版头部提取") {
		t.Fatalf("rollback-generated rule was not disabled: %+v", rollbackRule)
	}
}

func TestRelayCYBExtractorBaselinePreservesPreVersionAppliedRule(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:   "pre-version-applied-sample",
		CreatedAt:   time.Now().UTC(),
		UserText:    "pre-version user evidence",
		ContentHash: "pre-version-applied-hash",
	}); err != nil {
		t.Fatal(err)
	}
	ruleResult, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_rules (
			name, pattern, rationale, source_request_id, model, enabled
		) VALUES ($1, $2, $3, $4, $5, TRUE)
	`, "pre_version_rule", `(?i)pre.{0,20}version`, "baseline fixture",
		"pre-version-applied-sample", "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := ruleResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		UPDATE rb_cyb_miss_samples
		SET extractor_version = 0, learning_status = $1, rule_id = $2
		WHERE request_id = $3
	`, RelayCYBLearningStatusApplied, ruleID, "pre-version-applied-sample"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		DELETE FROM data_migrations
		WHERE version = $1
	`, dataMigrationRelayCYBExtractorBaselineV1); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("re-run extractor baseline migration: %v", err)
	}

	sample, err := db.GetRelayCYBMissSample(ctx, "pre-version-applied-sample")
	if err != nil {
		t.Fatal(err)
	}
	if sample.LearningStatus != RelayCYBLearningStatusApplied {
		t.Fatalf("pre-version applied sample was reclassified: %+v", sample)
	}
	var extractorVersion int
	if err := db.conn.QueryRowContext(ctx, `
		SELECT extractor_version
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
	`, "pre-version-applied-sample").Scan(&extractorVersion); err != nil {
		t.Fatal(err)
	}
	if extractorVersion != -1 {
		t.Fatalf("pre-version extractor version = %d, want -1", extractorVersion)
	}
	rule, err := db.GetRelayCYBRule(ctx, ruleID)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Enabled || rule.DisabledReason != "" {
		t.Fatalf("pre-version applied rule should remain enabled: %+v", rule)
	}
	notifications, err := db.ListRelayCYBLearningNotifications(
		ctx,
		time.Now().UTC().Add(-time.Minute),
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	foundReview := false
	for _, notification := range notifications {
		if notification.EventType == "legacy_rule_review" && notification.Count == 1 {
			foundReview = true
			break
		}
	}
	if !foundReview {
		t.Fatalf("pre-version retained rule review notification missing: %+v", notifications)
	}

	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_cyb_miss_samples (
			request_id, created_at, updated_at, user_text, content_hash,
			learning_status, rule_id
		) VALUES ($1, $2, $2, $3, $4, $5, $6)
	`, "rollback-merged-existing-rule", time.Now().UTC().Add(time.Minute),
		"head-only rollback sample merged into an existing pattern",
		"rollback-merged-existing-rule-hash",
		RelayCYBLearningStatusMerged, ruleID); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("quarantine rollback sample merged into existing rule: %v", err)
	}
	mergedSample, err := db.GetRelayCYBMissSample(ctx, "rollback-merged-existing-rule")
	if err != nil {
		t.Fatal(err)
	}
	if mergedSample.LearningStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(mergedSample.LearningError, "既有规则保持不变") {
		t.Fatalf("rollback merged sample was not isolated accurately: %+v", mergedSample)
	}
	rule, err = db.GetRelayCYBRule(ctx, ruleID)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Enabled || rule.DisabledReason != "" {
		t.Fatalf("rollback merged sample disabled a pre-version rule: %+v", rule)
	}
}

func TestRelayCYBExtractorBaselineRejectsInFlightLegacyClaim(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:   "legacy-processing-across-baseline",
		CreatedAt:   time.Now().UTC(),
		UserText:    "legacy head-only processing evidence",
		ContentHash: "legacy-processing-across-baseline-hash",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		UPDATE rb_cyb_miss_samples
		SET extractor_version = 0,
		    learning_status = $1,
		    learning_model = $2,
		    learning_attempts = 1
		WHERE request_id = $3
	`, RelayCYBLearningStatusProcessing, "gpt-5.4",
		"legacy-processing-across-baseline"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		DELETE FROM data_migrations
		WHERE version = $1
	`, dataMigrationRelayCYBExtractorBaselineV1); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("migrate with in-flight legacy claim: %v", err)
	}

	sample, err := db.GetRelayCYBMissSample(ctx, "legacy-processing-across-baseline")
	if err != nil {
		t.Fatal(err)
	}
	if sample.LearningStatus != RelayCYBLearningStatusRejected {
		t.Fatalf("in-flight legacy sample was not rejected: %+v", sample)
	}
	var extractorVersion int
	if err := db.conn.QueryRowContext(ctx, `
		SELECT extractor_version
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
	`, "legacy-processing-across-baseline").Scan(&extractorVersion); err != nil {
		t.Fatal(err)
	}
	if extractorVersion != 0 {
		t.Fatalf("in-flight legacy extractor version = %d, want 0", extractorVersion)
	}
	if _, err := db.ApplyRelayCYBLearnedRule(
		ctx,
		"legacy-processing-across-baseline",
		1,
		"legacy_processing_rule",
		`(?i)legacy.{0,32}processing`,
		"must remain stale",
		"gpt-5.4",
	); !errors.Is(err, ErrRelayCYBLearningClaimStale) {
		t.Fatalf("legacy worker apply after baseline error = %v, want stale", err)
	}
}

func TestRelayCYBLegacyRelaySampleIsQuarantinedFromClaims(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:         "legacy-relay-truncated",
		CreatedAt:         time.Now().UTC(),
		SampleSource:      RelayCYBMissSourceRelay,
		UserText:          "legacy Relay head-only user text",
		UserTextTruncated: true,
		ContentHash:       "legacy-relay-truncated-hash",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		UPDATE rb_cyb_miss_samples
		SET extractor_version = 0
		WHERE request_id = $1
	`, "legacy-relay-truncated"); err != nil {
		t.Fatal(err)
	}
	if err := db.migrateRelayCYBLearning(ctx); err != nil {
		t.Fatalf("run legacy Relay quarantine: %v", err)
	}

	legacy, err := db.GetRelayCYBMissSample(ctx, "legacy-relay-truncated")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.SampleSource != RelayCYBMissSourceRelay ||
		legacy.LearningStatus != RelayCYBLearningStatusRejected ||
		!strings.Contains(legacy.LearningError, "旧版头部提取") {
		t.Fatalf("legacy Relay sample was not quarantined: %+v", legacy)
	}

	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:         "new-relay-bounded",
		CreatedAt:         time.Now().UTC().Add(time.Minute),
		SampleSource:      RelayCYBMissSourceRelay,
		UserText:          "bounded head\n<<<USER_TEXT_MIDDLE_TRUNCATED>>>\nactual tail",
		UserTextTruncated: true,
		ContentHash:       "new-relay-bounded-hash",
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.RequestID != "new-relay-bounded" {
		t.Fatalf("claim returned quarantined legacy Relay sample: %+v", claimed)
	}
	next, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	if next != nil {
		t.Fatalf("quarantined legacy Relay sample remained claimable: %+v", next)
	}
}

func TestRelayCYBMissSampleSummaryDetailAndLearningLifecycle(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.WriteRelayAuditRequest(ctx, &RelayAuditRequestInput{
		RequestID: "cyb-miss-1", CreatedAt: now, DetectorMiss: true,
		Endpoint: "/v1/responses", Model: "gpt-5.4",
		FullText: `{"input":"bounded audit prefix"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRelayAuditAttempt(ctx, &RelayAuditAttemptInput{
		RequestID: "cyb-miss-1", AttemptIndex: 1, AccountID: 51,
		AccountName: "oauth-example", AccountType: "oauth",
		StatusCode: 400, ErrorKind: "cyber_policy", SelectedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if ok := db.EnqueueRelayCYBMissSample(&RelayCYBMissSampleInput{
		RequestID: "cyb-miss-1", CreatedAt: now, AccountID: 51,
		AccountName: "oauth-example", AccountType: "oauth",
		RedactedRequest: `{"input":"dangerous request","access_token":"[REDACTED]"}`,
		UserText:        "dangerous request", ContentHash: "hash-1",
	}); !ok {
		t.Fatal("sample enqueue failed")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("sample writer did not drain")
	}

	page, err := db.ListRelayAuditCasesPage(ctx, RelayAuditCaseQuery{
		Kind: RelayAuditCaseOAuthCyber, Start: now.Add(-time.Minute), End: now.Add(time.Minute),
		Page: 1, PageSize: 20, SummaryOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].FullText != "" || len(page.Items[0].Attempts) != 0 {
		t.Fatalf("summary leaked detail: %+v", page.Items[0])
	}
	if page.Items[0].AttemptCount != 1 || page.Items[0].CYBLearning == nil {
		t.Fatalf("summary metadata=%+v", page.Items[0])
	}
	if page.Items[0].CYBLearning.AccountName != "oauth-example" ||
		page.Items[0].CYBLearning.Status != RelayCYBLearningStatusQueued {
		t.Fatalf("learning summary=%+v", page.Items[0].CYBLearning)
	}

	detail, err := db.GetRelayAuditCaseDetail(ctx, "cyb-miss-1")
	if err != nil {
		t.Fatal(err)
	}
	if detail.CYBMiss == nil || detail.CYBMiss.RedactedRequest == "" ||
		detail.CYBMiss.UserText != "dangerous request" {
		t.Fatalf("detail sample=%+v", detail.CYBMiss)
	}
	if len(detail.Case.Attempts) != 1 || detail.Case.FullText == "" {
		t.Fatalf("detail case=%+v", detail.Case)
	}

	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.RequestID != "cyb-miss-1" ||
		claimed.LearningStatus != RelayCYBLearningStatusProcessing ||
		claimed.LearningAttempts != 1 {
		t.Fatalf("claimed=%+v", claimed)
	}
	rule, err := db.ApplyRelayCYBLearnedRule(
		ctx,
		claimed.RequestID,
		claimed.LearningAttempts,
		"cyb_auto_example",
		`(?i)dangerous\s+request`,
		"test rationale",
		"gpt-5.4",
	)
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID <= 0 || !rule.Enabled {
		t.Fatalf("rule=%+v", rule)
	}
	enabled, err := db.ListEnabledRelayCYBRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || enabled[0].Pattern != rule.Pattern {
		t.Fatalf("enabled=%+v", enabled)
	}
	stats, err := db.GetRelayCYBLearningStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Applied != 1 || stats.Rules != 1 || stats.Queued != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.OAuthSamples != 1 || stats.RelaySamples != 0 {
		t.Fatalf("source stats=%+v", stats)
	}
}

func TestRelayCYBLearningSettingsRoundTrip(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	settings, err := db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Enabled || settings.Model != DefaultRelayCYBLearningModel {
		t.Fatalf("defaults=%+v", settings)
	}
	updated, err := db.UpdateRelayCYBLearningSettings(ctx, false, "gpt-5.4-mini")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.Model != "gpt-5.4-mini" {
		t.Fatalf("updated=%+v", updated)
	}
}

func TestRelayCYBClaimMergesDuplicateContentHash(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	writeRelayCYBTestSample(t, db, "merge-source", "same content", "same-hash", now)
	source, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim source: %v", err)
	}
	rule, err := db.ApplyRelayCYBLearnedRule(
		ctx,
		source.RequestID,
		source.LearningAttempts,
		"cyb_auto_merge_source",
		`(?i)same\s+content`,
		"test merge source",
		"gpt-5.4",
	)
	if err != nil {
		t.Fatalf("apply source: %v", err)
	}

	if err := db.WriteRelayCYBMissSample(ctx, &RelayCYBMissSampleInput{
		RequestID:       "merge-duplicate",
		CreatedAt:       now.Add(time.Second),
		SampleSource:    RelayCYBMissSourceRelay,
		RedactedRequest: `{"input":"redacted Relay test sample"}`,
		UserText:        "same content",
		ContentHash:     "same-hash",
	}); err != nil {
		t.Fatalf("write cross-source duplicate: %v", err)
	}
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim after duplicate: %v", err)
	}
	if claimed != nil {
		t.Fatalf("duplicate should merge without a model claim: %+v", claimed)
	}
	duplicate, err := db.GetRelayCYBMissSample(ctx, "merge-duplicate")
	if err != nil {
		t.Fatalf("get duplicate: %v", err)
	}
	if duplicate.LearningStatus != RelayCYBLearningStatusMerged ||
		duplicate.RuleID != rule.ID ||
		duplicate.LearningAttempts != 0 ||
		duplicate.SampleSource != RelayCYBMissSourceRelay {
		t.Fatalf("merged duplicate = %+v, want rule %d without model attempt", duplicate, rule.ID)
	}
	stats, err := db.GetRelayCYBLearningStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Applied != 1 || stats.Merged != 1 || stats.Rules != 1 ||
		stats.OAuthSamples != 1 || stats.RelaySamples != 1 {
		t.Fatalf("stats after merge = %+v", stats)
	}
}

func TestRelayCYBClaimDoesNotMergeIntoFuseDisabledRule(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	writeRelayCYBTestSample(t, db, "disabled-source", "same disabled content", "disabled-hash", now)
	source, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim source: %v", err)
	}
	rule, err := db.ApplyRelayCYBLearnedRule(
		ctx,
		source.RequestID,
		source.LearningAttempts,
		"cyb_auto_disabled_source",
		`(?i)same\s+disabled\s+content`,
		"test disabled source",
		"gpt-5.4",
	)
	if err != nil {
		t.Fatalf("apply source: %v", err)
	}
	disabled, err := db.DisableRelayCYBRule(ctx, rule.ID, "test fuse")
	if err != nil || !disabled {
		t.Fatalf("disable = %v, %v", disabled, err)
	}

	writeRelayCYBTestSample(t, db, "disabled-duplicate", "same disabled content", "disabled-hash", now.Add(time.Second))
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim duplicate: %v", err)
	}
	if claimed == nil || claimed.RequestID != "disabled-duplicate" {
		t.Fatalf("disabled rule swallowed a new learning case: %+v", claimed)
	}
}

func TestRelayCYBApplyExistingPatternMarksMergedWithoutDuplicateEvent(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const pattern = `(?i)shared\s+candidate`

	writeRelayCYBTestSample(t, db, "pattern-source", "shared candidate one", "hash-one", now)
	source, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim source: %v", err)
	}
	rule, err := db.ApplyRelayCYBLearnedRule(
		ctx, source.RequestID, source.LearningAttempts,
		"cyb_auto_shared", pattern, "source", "gpt-5.4",
	)
	if err != nil {
		t.Fatalf("apply source: %v", err)
	}

	writeRelayCYBTestSample(t, db, "pattern-duplicate", "shared candidate two", "hash-two", now.Add(time.Second))
	duplicate, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim duplicate: %v", err)
	}
	mergedRule, err := db.ApplyRelayCYBLearnedRule(
		ctx, duplicate.RequestID, duplicate.LearningAttempts,
		"cyb_auto_shared_again", pattern, "duplicate", "gpt-5.4",
	)
	if err != nil {
		t.Fatalf("apply duplicate: %v", err)
	}
	if mergedRule.ID != rule.ID {
		t.Fatalf("existing pattern returned rule %d, want %d", mergedRule.ID, rule.ID)
	}
	sample, err := db.GetRelayCYBMissSample(ctx, duplicate.RequestID)
	if err != nil {
		t.Fatalf("get duplicate: %v", err)
	}
	if sample.LearningStatus != RelayCYBLearningStatusMerged || sample.RuleID != rule.ID {
		t.Fatalf("duplicate sample = %+v", sample)
	}
	events, err := db.ListRelayCYBLearningNotifications(ctx, now.Add(-time.Minute), 20)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	appliedEvents := 0
	for _, event := range events {
		if event.EventType == "applied" {
			appliedEvents++
		}
	}
	if appliedEvents != 1 {
		t.Fatalf("applied events = %d, want 1: %+v", appliedEvents, events)
	}
}

func TestRelayCYBStaleTransitionsReturnClaimError(t *testing.T) {
	tests := []struct {
		name       string
		transition func(context.Context, *DB, string) error
	}{
		{
			name: "retry",
			transition: func(ctx context.Context, db *DB, requestID string) error {
				return db.MarkRelayCYBLearningRetry(ctx, requestID, 1, "retry", time.Now(), false)
			},
		},
		{
			name: "failed",
			transition: func(ctx context.Context, db *DB, requestID string) error {
				return db.MarkRelayCYBLearningRetry(ctx, requestID, 1, "failed", time.Now(), true)
			},
		},
		{
			name: "rejected",
			transition: func(ctx context.Context, db *DB, requestID string) error {
				return db.MarkRelayCYBLearningRejected(ctx, requestID, 1, "rejected")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newRelayAuditSQLite(t)
			ctx := context.Background()
			writeRelayCYBTestSample(t, db, "stale-"+test.name, "sample", "hash-"+test.name, time.Now().UTC())

			err := test.transition(ctx, db, "stale-"+test.name)
			if !errors.Is(err, ErrRelayCYBLearningClaimStale) {
				t.Fatalf("transition error = %v, want ErrRelayCYBLearningClaimStale", err)
			}
			sample, getErr := db.GetRelayCYBMissSample(ctx, "stale-"+test.name)
			if getErr != nil {
				t.Fatalf("get sample: %v", getErr)
			}
			if sample.LearningStatus != RelayCYBLearningStatusQueued {
				t.Fatalf("stale transition changed sample: %+v", sample)
			}
		})
	}
}

func TestRelayCYBLearningLeaseAttemptPreventsABACompletion(t *testing.T) {
	tests := []struct {
		name       string
		wantStatus string
		transition func(context.Context, *DB, string, int) error
	}{
		{
			name:       "retry",
			wantStatus: RelayCYBLearningStatusRetry,
			transition: func(ctx context.Context, db *DB, requestID string, attempt int) error {
				return db.MarkRelayCYBLearningRetry(
					ctx,
					requestID,
					attempt,
					"retry",
					time.Now().Add(time.Minute),
					false,
				)
			},
		},
		{
			name:       "rejected",
			wantStatus: RelayCYBLearningStatusRejected,
			transition: func(ctx context.Context, db *DB, requestID string, attempt int) error {
				return db.MarkRelayCYBLearningRejected(ctx, requestID, attempt, "rejected")
			},
		},
		{
			name:       "applied",
			wantStatus: RelayCYBLearningStatusApplied,
			transition: func(ctx context.Context, db *DB, requestID string, attempt int) error {
				_, err := db.ApplyRelayCYBLearnedRule(
					ctx,
					requestID,
					attempt,
					"cyb_auto_aba_"+testSafeName(requestID),
					`(?i)aba\s+sample`,
					"ABA lease test",
					"gpt-5.4",
				)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newRelayAuditSQLite(t)
			ctx := context.Background()
			requestID := "aba-" + test.name
			writeRelayCYBTestSample(
				t,
				db,
				requestID,
				"aba sample",
				"hash-"+test.name,
				time.Now().UTC(),
			)

			first, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
			if err != nil || first == nil {
				t.Fatalf("first claim = %+v, %v", first, err)
			}
			if _, err := db.conn.ExecContext(ctx, `
				UPDATE rb_cyb_miss_samples
				SET updated_at = $1
				WHERE request_id = $2
			`, db.timeArg(time.Now().UTC().Add(-11*time.Minute)), requestID); err != nil {
				t.Fatalf("age first lease: %v", err)
			}
			second, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
			if err != nil || second == nil {
				t.Fatalf("second claim = %+v, %v", second, err)
			}
			if second.RequestID != requestID ||
				second.LearningAttempts != first.LearningAttempts+1 {
				t.Fatalf("second claim = %+v, first = %+v", second, first)
			}

			if err := test.transition(ctx, db, requestID, first.LearningAttempts); !errors.Is(
				err,
				ErrRelayCYBLearningClaimStale,
			) {
				t.Fatalf("old lease transition error = %v, want ErrRelayCYBLearningClaimStale", err)
			}
			current, err := db.GetRelayCYBMissSample(ctx, requestID)
			if err != nil {
				t.Fatalf("get after stale completion: %v", err)
			}
			if current.LearningStatus != RelayCYBLearningStatusProcessing ||
				current.LearningAttempts != second.LearningAttempts {
				t.Fatalf("old lease changed current claim: %+v", current)
			}

			if err := test.transition(ctx, db, requestID, second.LearningAttempts); err != nil {
				t.Fatalf("current lease transition: %v", err)
			}
			current, err = db.GetRelayCYBMissSample(ctx, requestID)
			if err != nil {
				t.Fatalf("get final sample: %v", err)
			}
			if current.LearningStatus != test.wantStatus {
				t.Fatalf("final status = %q, want %q: %+v", current.LearningStatus, test.wantStatus, current)
			}
		})
	}
}

func TestRelayCYBApplyRejectsChangedLearningSettings(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		model   string
	}{
		{name: "disabled", enabled: false, model: "gpt-5.4"},
		{name: "model changed", enabled: true, model: "gpt-5.4-mini"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newRelayAuditSQLite(t)
			ctx := context.Background()
			requestID := "settings-" + test.name
			writeRelayCYBTestSample(t, db, requestID, "danger sample", "hash-"+test.name, time.Now().UTC())
			claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if claimed == nil {
				t.Fatal("expected processing claim")
			}
			if _, err := db.UpdateRelayCYBLearningSettings(ctx, test.enabled, test.model); err != nil {
				t.Fatalf("update settings: %v", err)
			}
			_, err = db.ApplyRelayCYBLearnedRule(
				ctx,
				requestID,
				claimed.LearningAttempts,
				"cyb_auto_settings_guard",
				`(?i)danger\s+sample`,
				"settings guard",
				"gpt-5.4",
			)
			if !errors.Is(err, ErrRelayCYBLearningClaimStale) {
				t.Fatalf("apply error = %v, want ErrRelayCYBLearningClaimStale", err)
			}
			sample, getErr := db.GetRelayCYBMissSample(ctx, requestID)
			if getErr != nil {
				t.Fatalf("get sample: %v", getErr)
			}
			if sample.LearningStatus != RelayCYBLearningStatusProcessing || sample.RuleID != 0 {
				t.Fatalf("settings race applied stale rule: %+v", sample)
			}
		})
	}
}

func TestRelayCYBTerminalTransitionAndEventAreAtomic(t *testing.T) {
	tests := []struct {
		name       string
		transition func(context.Context, *DB, string, int) error
	}{
		{
			name: "failed",
			transition: func(ctx context.Context, db *DB, requestID string, attempt int) error {
				return db.MarkRelayCYBLearningRetry(ctx, requestID, attempt, "failed", time.Now(), true)
			},
		},
		{
			name: "rejected",
			transition: func(ctx context.Context, db *DB, requestID string, attempt int) error {
				return db.MarkRelayCYBLearningRejected(ctx, requestID, attempt, "rejected")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newRelayAuditSQLite(t)
			ctx := context.Background()
			requestID := "atomic-" + test.name
			writeRelayCYBTestSample(t, db, requestID, "sample", "hash-"+test.name, time.Now().UTC())
			claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if _, err := db.conn.ExecContext(ctx, `DROP TABLE rb_cyb_learning_events`); err != nil {
				t.Fatalf("drop events table: %v", err)
			}

			if err := test.transition(ctx, db, requestID, claimed.LearningAttempts); err == nil {
				t.Fatal("transition succeeded without its notification event")
			}
			sample, err := db.GetRelayCYBMissSample(ctx, requestID)
			if err != nil {
				t.Fatalf("get sample: %v", err)
			}
			if sample.LearningStatus != RelayCYBLearningStatusProcessing {
				t.Fatalf("non-atomic event failure left terminal state: %+v", sample)
			}
		})
	}
}

func TestDisableRelayCYBRuleEmitsOneFuseEvent(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()
	writeRelayCYBTestSample(t, db, "fuse-source", "fuse sample", "fuse-hash", now)
	claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	rule, err := db.ApplyRelayCYBLearnedRule(
		ctx, claimed.RequestID, claimed.LearningAttempts,
		"cyb_auto_fuse", `(?i)fuse\s+sample`, "fuse", "gpt-5.4",
	)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	disabled, err := db.DisableRelayCYBRule(ctx, rule.ID, "test fuse")
	if err != nil || !disabled {
		t.Fatalf("first disable = %v, %v", disabled, err)
	}
	disabled, err = db.DisableRelayCYBRule(ctx, rule.ID, "duplicate fuse")
	if err != nil || disabled {
		t.Fatalf("second disable = %v, %v", disabled, err)
	}
	events, err := db.ListRelayCYBLearningNotifications(ctx, now.Add(-time.Minute), 20)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	fuseEvents := 0
	for _, event := range events {
		if event.EventType == "auto_disabled" && event.RuleID == rule.ID {
			fuseEvents++
		}
	}
	if fuseEvents != 1 {
		t.Fatalf("fuse events = %d, want 1: %+v", fuseEvents, events)
	}
}

func testSafeName(value string) string {
	return strings.NewReplacer("-", "_", " ", "_").Replace(value)
}

func writeRelayCYBTestSample(
	t *testing.T,
	db *DB,
	requestID string,
	userText string,
	contentHash string,
	createdAt time.Time,
) {
	t.Helper()
	if err := db.WriteRelayCYBMissSample(context.Background(), &RelayCYBMissSampleInput{
		RequestID:       requestID,
		CreatedAt:       createdAt,
		RedactedRequest: `{"input":"redacted test sample"}`,
		UserText:        userText,
		ContentHash:     contentHash,
	}); err != nil {
		t.Fatalf("WriteRelayCYBMissSample(%s): %v", requestID, err)
	}
}
