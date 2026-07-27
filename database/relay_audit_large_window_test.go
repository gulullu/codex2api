package database

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestRelayAuditLargeWindowAggregatesAndKeepsCasesPaged(t *testing.T) {
	const requestCount = 25_001

	db := newRelayAuditSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-24 * time.Hour)
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	requestStatement, err := tx.PrepareContext(ctx, `
		INSERT INTO rb_route_requests (
			request_id, created_at, updated_at, full_text,
			route_source, route_signals, route_group_id, final_status_code
		) VALUES ($1, $2, $2, $3, $4, $5, $6, $7)
	`)
	if err != nil {
		t.Fatalf("prepare request insert: %v", err)
	}
	latestRequestID := ""
	for index := 0; index < requestCount; index++ {
		requestID := fmt.Sprintf("large-window-%05d", index)
		createdAt := start.Add(time.Duration(index%24)*time.Hour + 15*time.Minute)
		if index == requestCount-1 {
			latestRequestID = requestID
			createdAt = end.Add(-time.Minute)
		}
		if _, err := requestStatement.ExecContext(
			ctx,
			requestID,
			db.timeArg(createdAt),
			`{"input":"large window retained body"}`,
			"cyb_rule",
			`["large_window_rule"]`,
			7,
			200,
		); err != nil {
			_ = requestStatement.Close()
			t.Fatalf("insert request %d: %v", index, err)
		}
	}
	if err := requestStatement.Close(); err != nil {
		t.Fatalf("close request statement: %v", err)
	}

	attemptStatement, err := tx.PrepareContext(ctx, `
		INSERT INTO rb_route_attempts (
			request_id, attempt_index, selection_mode,
			account_id, account_name, account_type,
			status_code, selected_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
	`)
	if err != nil {
		t.Fatalf("prepare attempt insert: %v", err)
	}
	for _, attempt := range []struct {
		index         int
		selectionMode string
		status        int
	}{
		{index: 1, status: 503},
		{index: 2, selectionMode: "same_group_switch", status: 200},
	} {
		if _, err := attemptStatement.ExecContext(
			ctx,
			latestRequestID,
			attempt.index,
			attempt.selectionMode,
			51,
			"relay-test",
			"responses_api",
			attempt.status,
			db.timeArg(end.Add(-time.Minute)),
		); err != nil {
			_ = attemptStatement.Close()
			t.Fatalf("insert attempt %d: %v", attempt.index, err)
		}
	}
	if err := attemptStatement.Close(); err != nil {
		t.Fatalf("close attempt statement: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}
	committed = true

	report, err := db.BuildRelayAuditReport(ctx, RelayAuditQuery{
		Start:         start,
		End:           end,
		BucketMinutes: 60,
	})
	if err != nil {
		t.Fatalf("BuildRelayAuditReport for %d requests: %v", requestCount, err)
	}
	if report.Summary.LogicalRequests != requestCount {
		t.Fatalf(
			"logical_requests = %d, want %d",
			report.Summary.LogicalRequests,
			requestCount,
		)
	}
	if report.Summary.RouteAttempts != 2 ||
		report.Summary.Retries != 1 ||
		report.Summary.SameGroupSwitches != 1 {
		t.Fatalf("attempt summary = %+v", report.Summary)
	}
	if len(report.Timeline) != 24 {
		t.Fatalf("timeline buckets = %d, want 24", len(report.Timeline))
	}

	page, err := db.ListRelayAuditCasesPage(ctx, RelayAuditCaseQuery{
		Kind:        RelayAuditCaseRelayRoute,
		Start:       start,
		End:         end,
		Page:        1,
		PageSize:    20,
		SummaryOnly: true,
	})
	if err != nil {
		t.Fatalf("ListRelayAuditCasesPage: %v", err)
	}
	if page.Total != requestCount || len(page.Items) != 20 || page.PageSize != 20 {
		t.Fatalf(
			"paged cases total=%d items=%d page_size=%d",
			page.Total,
			len(page.Items),
			page.PageSize,
		)
	}
	foundLatest := false
	for _, item := range page.Items {
		if item.FullText != "" {
			t.Fatalf("summary page included full_text for %s", item.RequestID)
		}
		if len(item.Attempts) != 0 {
			t.Fatalf("summary page included attempts for %s: %+v", item.RequestID, item.Attempts)
		}
		if item.RequestID == latestRequestID {
			foundLatest = true
			if item.AttemptCount != 2 {
				t.Fatalf("latest attempt_count = %d, want 2", item.AttemptCount)
			}
		}
	}
	if !foundLatest {
		t.Fatalf("latest request %q was not present on the first page", latestRequestID)
	}
}
