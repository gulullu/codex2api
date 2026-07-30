package database

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRelayAuditSQLite(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "relay-audit.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close(): %v", err)
		}
	})
	return db
}

func TestRelayAuditReportKeepsOAuthCyberAttemptAfterFinalSuccess(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.WriteRelayAuditRequest(ctx, &RelayAuditRequestInput{
		RequestID: "request-1", CreatedAt: now, RouteSource: "oauth_overflow", RouteGroupID: 7,
		RouteSignals: `["feedback","feedback"]`, FullText: `{"input":"example"}`,
		HasPreviousResponseID: true, ReplayStatus: "hit", ReplaySource: "memory",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRelayAuditOutcome(ctx, &RelayAuditOutcomeInput{
		RequestID: "request-1", AttemptIndex: 1, AccountID: 1, AccountType: "oauth",
		StatusCode: 400, ErrorKind: "cyber_policy", CompletedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRelayAuditOutcome(ctx, &RelayAuditOutcomeInput{
		RequestID: "request-1", AttemptIndex: 2, AccountID: 2, AccountType: "responses_api",
		StatusCode: 200, CompletedAt: now.Add(time.Second), Final: true,
	}); err != nil {
		t.Fatal(err)
	}

	report, err := db.BuildRelayAuditReport(ctx, RelayAuditQuery{
		Start: now.Add(-time.Minute), End: now.Add(time.Minute), BucketMinutes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OAuthCyberMisses != 1 || report.Summary.RelaySuccesses != 1 ||
		report.Summary.ReplayHits != 1 || report.Summary.ReplayMisses != 0 {
		t.Fatalf("summary=%+v", report.Summary)
	}
	if len(report.RouteSignals) != 1 || report.RouteSignals[0].Requests != 1 {
		t.Fatalf("route signals=%+v", report.RouteSignals)
	}
	page, err := db.ListRelayAuditCasesPage(ctx, RelayAuditCaseQuery{
		Kind: RelayAuditCaseOAuthCyber, Start: now.Add(-time.Minute), End: now.Add(time.Minute),
		Page: 1, PageSize: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || len(page.Items[0].Attempts) != 2 {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].AttemptCount != 2 {
		t.Fatalf("attempt_count=%d want=2", page.Items[0].AttemptCount)
	}
}

func TestRelayAuditReportCountsNoAffinitySplitSeparately(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.WriteRelayAuditRequest(ctx, &RelayAuditRequestInput{
		RequestID:    "no-affinity",
		CreatedAt:    now,
		RouteSource:  "no_affinity_split",
		RouteGroupID: 7,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRelayAuditOutcome(ctx, &RelayAuditOutcomeInput{
		RequestID:    "no-affinity",
		AttemptIndex: 1,
		AccountID:    2,
		AccountType:  "responses_api",
		StatusCode:   200,
		CompletedAt:  now,
		Final:        true,
	}); err != nil {
		t.Fatal(err)
	}

	report, err := db.BuildRelayAuditReport(ctx, RelayAuditQuery{
		Start: now.Add(-time.Minute), End: now.Add(time.Minute), BucketMinutes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.LogicalRequests != 1 || report.Summary.RelayRequests != 1 ||
		report.Summary.NoAffinitySplit != 1 || report.Summary.OAuthOverflow != 0 ||
		report.Summary.CYBRule != 0 {
		t.Fatalf("summary=%+v", report.Summary)
	}
	if len(report.Timeline) != 1 || report.Timeline[0].NoAffinitySplit != 1 ||
		report.Timeline[0].OAuthOverflow != 0 {
		t.Fatalf("timeline=%+v", report.Timeline)
	}
	if len(report.RelayRoutes) != 1 ||
		report.RelayRoutes[0].RouteSource != "no_affinity_split" {
		t.Fatalf("relay routes=%+v", report.RelayRoutes)
	}
}

func TestRelayAuditReportCountsRelayNativeFallbackOutcomes(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	requests := []struct {
		id           string
		replayStatus string
		replaySource string
		groupID      int64
		statusCode   int
	}{
		{
			id:           "native-success",
			replayStatus: "cache_miss",
			replaySource: "relay_native",
			groupID:      7,
			statusCode:   200,
		},
		{
			id:           "native-failure",
			replayStatus: "incomplete",
			replaySource: "relay_native",
			groupID:      7,
			statusCode:   400,
		},
		{
			id:           "local-miss-oauth",
			replayStatus: "cache_miss",
			statusCode:   200,
		},
	}
	for index, request := range requests {
		createdAt := now.Add(time.Duration(index) * time.Second)
		if err := db.WriteRelayAuditRequest(ctx, &RelayAuditRequestInput{
			RequestID:             request.id,
			CreatedAt:             createdAt,
			RouteGroupID:          request.groupID,
			HasPreviousResponseID: true,
			ReplayStatus:          request.replayStatus,
			ReplaySource:          request.replaySource,
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.WriteRelayAuditOutcome(ctx, &RelayAuditOutcomeInput{
			RequestID:    request.id,
			AttemptIndex: 1,
			AccountID:    int64(index + 1),
			AccountType:  "responses_api",
			StatusCode:   request.statusCode,
			CompletedAt:  createdAt,
			Final:        true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	report, err := db.BuildRelayAuditReport(ctx, RelayAuditQuery{
		Start: now.Add(-time.Minute), End: now.Add(time.Minute), BucketMinutes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ReplayMisses != 3 ||
		report.Summary.RelayNativeFallbacks != 2 ||
		report.Summary.RelayNativeSuccesses != 1 ||
		report.Summary.RelayNativeFailures != 1 ||
		report.Summary.ReplayUnavailable != 0 {
		t.Fatalf("summary=%+v", report.Summary)
	}
}

func TestRelayAuditRetentionDeletesInBatchesAndRemovesOrphans(t *testing.T) {
	db := newRelayAuditSQLite(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-45 * 24 * time.Hour)
	recent := time.Now().UTC()
	for _, request := range []RelayAuditRequestInput{
		{RequestID: "old-1", CreatedAt: old},
		{RequestID: "old-2", CreatedAt: old.Add(time.Second)},
		{RequestID: "recent", CreatedAt: recent},
	} {
		if err := db.WriteRelayAuditRequest(ctx, &request); err != nil {
			t.Fatal(err)
		}
		if err := db.WriteRelayAuditAttempt(ctx, &RelayAuditAttemptInput{
			RequestID: request.RequestID, AttemptIndex: 1, SelectedAt: request.CreatedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_route_attempts (request_id, attempt_index, selected_at)
		VALUES ('orphan', 1, $1)
	`, db.timeArg(old)); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupRelayAuditBefore(ctx, recent.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var requestCount, attemptCount, orphanCount int
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_route_requests`).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_route_attempts`).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_route_attempts WHERE request_id = 'orphan'`).Scan(&orphanCount); err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 || attemptCount != 1 || orphanCount != 0 {
		t.Fatalf("requests=%d attempts=%d orphans=%d", requestCount, attemptCount, orphanCount)
	}
}

func TestRelayAuditNormalizesOffsetTimeAndBoundsQueuedBody(t *testing.T) {
	db := newRelayAuditSQLite(t)
	offset := time.FixedZone("UTC+8", 8*60*60)
	created := time.Date(2026, 7, 27, 12, 0, 0, 0, offset)
	large := `{"input":"` + strings.Repeat("界", RelayAuditFullTextMaxRunes+100) + `"}`
	if ok := db.EnqueueRelayAuditRequest(&RelayAuditRequestInput{
		RequestID: "bounded", CreatedAt: created, FullText: large,
	}); !ok {
		t.Fatal("enqueue failed")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("audit queue did not drain")
	}
	page, err := db.ListRelayAuditCasesPage(context.Background(), RelayAuditCaseQuery{
		Kind:  RelayAuditCaseRelayRoute,
		Start: created.UTC().Add(-time.Minute),
		End:   created.UTC().Add(time.Minute),
		Page:  1, PageSize: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The default relay-route predicate excludes this group-less row; inspect it
	// directly to verify the stored instant and bounded content.
	var createdRaw any
	var fullText string
	var truncated bool
	if err := db.conn.QueryRowContext(context.Background(), `
		SELECT created_at, full_text, scan_truncated
		FROM rb_route_requests WHERE request_id = 'bounded'
	`).Scan(&createdRaw, &fullText, &truncated); err != nil {
		t.Fatal(err)
	}
	stored, err := parseDBTimeValue(createdRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Equal(created.UTC()) {
		t.Fatalf("stored=%s want=%s", stored, created.UTC())
	}
	if !truncated || len([]rune(fullText)) != RelayAuditFullTextMaxRunes {
		t.Fatalf("truncated=%v runes=%d", truncated, len([]rune(fullText)))
	}
	if page.Total != 0 {
		t.Fatalf("unexpected relay page total=%d", page.Total)
	}
}
