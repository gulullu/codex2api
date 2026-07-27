package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

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

	writeRelayCYBTestSample(t, db, "merge-duplicate", "same content", "same-hash", now.Add(time.Second))
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
		duplicate.LearningAttempts != 0 {
		t.Fatalf("merged duplicate = %+v, want rule %d without model attempt", duplicate, rule.ID)
	}
	stats, err := db.GetRelayCYBLearningStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Applied != 1 || stats.Merged != 1 || stats.Rules != 1 {
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
