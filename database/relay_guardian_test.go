package database

import (
	"context"
	"testing"
	"time"
)

func TestRelayGuardianUsagePersistsAttemptTerminalAcrossLongRetry(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	base := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	insert := `INSERT INTO usage_logs (created_at, account_id, logical_request_id, status_code,
		upstream_error_kind, route_class, route_group_id, upstream_account_type, guardian_attempt_only)
		VALUES ($1,$2,$3,$4,$5,'cyb_relay',7,'openai_responses',$6)`
	if _, err := db.conn.ExecContext(ctx, insert, db.timeArg(base), 50, "long-retry", 502, "server", true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, insert, db.timeArg(base.Add(3*time.Minute)), 53, "long-retry", 200, "", false); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListRelayGuardianUsage(ctx, 7, base.Add(-time.Second), base.Add(4*time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d, want 2", len(rows))
	}
	if !rows[0].GuardianAttemptOnly || rows[1].GuardianAttemptOnly {
		t.Fatalf("attempt/final markers lost: %+v", rows)
	}
}

func TestRelayGuardianReliabilityUsesOnlyFinalUserVisibleLogicalRequests(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	insert := func(at time.Time, accountID int64, logical string, status int, kind, routeSource string, attemptOnly bool) {
		t.Helper()
		_, err := db.conn.ExecContext(ctx, `INSERT INTO usage_logs (created_at,account_id,logical_request_id,status_code,
			upstream_error_kind,route_class,route_source,route_group_id,upstream_account_type,guardian_attempt_only)
			VALUES ($1,$2,$3,$4,$5,'cyb_relay',$6,7,'openai_responses',$7)`,
			db.timeArg(at), accountID, logical, status, kind, routeSource, attemptOnly)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(now.Add(-9*time.Minute), 50, "retry-success", 502, "server", "direct", true)
	insert(now.Add(-8*time.Minute), 51, "retry-success", 200, "", "direct", false)
	insert(now.Add(-7*time.Minute), 51, "visible-500", 500, "server", "direct", false)
	insert(now.Add(-6*time.Minute), 51, "probe", 500, "server", "probe", false)
	insert(now.Add(-5*time.Minute), 51, "policy", 500, "content_policy", "direct", false)
	insert(now.Add(-4*time.Minute), 51, "client-400", 400, "bad_request", "direct", false)
	insert(now.Add(-3*time.Minute), 51, "strong-502", 502, "server", "direct", false)
	insert(now.Add(-2*time.Minute), 51, "local-busy", 503, "websocket_busy_session", "direct", false)
	insert(now.Add(-time.Minute), 51, "local-capacity", 503, "websocket_local_capacity", "direct", false)
	insert(now.Add(-30*time.Second), 51, "continuation-unavailable", 503, "websocket_continuation_unavailable", "direct", false)
	insert(now.Add(-20*time.Second), 51, "usage-limit-kind", 503, "usage_limit", "direct", false)
	insert(now.Add(-10*time.Second), 51, "usage-limit-message", 503, "server", "direct", false)
	insert(now.Add(-5*time.Second), 51, "concurrency-limit-message", 503, "server", "direct", false)
	_, err = db.conn.ExecContext(ctx, `UPDATE usage_logs SET error_message='Concurrency usage limit exceeded' WHERE logical_request_id='usage-limit-message'`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.conn.ExecContext(ctx, `UPDATE usage_logs SET error_message='Concurrency limit exceeded for user' WHERE logical_request_id='concurrency-limit-message'`)
	if err != nil {
		t.Fatal(err)
	}
	insert(now.Add(-30*time.Minute), 51, "old-success", 200, "", "direct", false)
	insert(now.Add(-40*time.Minute), 51, "old-failure", 503, "server", "direct", false)

	rows, err := db.ListRelayGuardianReliability(ctx, 7, now.Add(-time.Hour), now.Add(-10*time.Minute), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	got := rows[0]
	if got.AccountID != 51 || got.Total10m != 2 || got.Failures10m != 1 || got.Total60m != 4 || got.Failures60m != 2 {
		t.Fatalf("unexpected reliability aggregate: %+v", got)
	}
	if got.LatestFailureRowID10m <= 0 || got.LatestFailureRowID60m <= got.LatestFailureRowID10m {
		t.Fatalf("unexpected latest failure ids: %+v", got)
	}
}

func TestRelayGuardianReliabilityRanksGloballyBeforeRelayScope(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	insert := func(at time.Time, accountID int64, logical string, status int, kind, routeClass string, groupID int64, accountType string) {
		t.Helper()
		_, insertErr := db.conn.ExecContext(ctx, `INSERT INTO usage_logs (created_at,account_id,logical_request_id,status_code,
			upstream_error_kind,route_class,route_source,route_group_id,upstream_account_type,guardian_attempt_only)
			VALUES ($1,$2,$3,$4,$5,$6,'direct',$7,$8,false)`,
			db.timeArg(at), accountID, logical, status, kind, routeClass, groupID, accountType)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}

	// Neither Relay attempt is the final logical outcome, so neither may count.
	insert(now.Add(-9*time.Minute), 51, "relay-500-oauth-success", 500, "server", "cyb_relay", 7, "openai_responses")
	insert(now.Add(-8*time.Minute), 0, "relay-500-oauth-success", 200, "", "oauth", 0, "oauth")
	insert(now.Add(-7*time.Minute), 51, "relay-503-oauth-success", 503, "server", "cyb_relay", 7, "openai_responses")
	insert(now.Add(-6*time.Minute), 0, "relay-503-oauth-success", 200, "", "oauth", 0, "oauth")
	// This chain terminates in Relay and must be charged to the final Relay account.
	insert(now.Add(-5*time.Minute), 0, "oauth-failure-relay-final", 500, "server", "oauth", 0, "oauth")
	insert(now.Add(-4*time.Minute), 53, "oauth-failure-relay-final", 500, "server", "cyb_relay", 7, "openai_responses")

	rows, err := db.ListRelayGuardianReliability(ctx, 7, now.Add(-time.Hour), now.Add(-10*time.Minute), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].AccountID != 53 || rows[0].Total10m != 1 || rows[0].Failures10m != 1 ||
		rows[0].Total60m != 1 || rows[0].Failures60m != 1 {
		t.Fatalf("cross-pool final ranking aggregate=%+v", rows)
	}
}

func TestRelayGuardianReliabilityExcludesUnmaturedRows(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	insert := func(at time.Time, logical string) {
		t.Helper()
		_, insertErr := db.conn.ExecContext(ctx, `INSERT INTO usage_logs (created_at,account_id,logical_request_id,status_code,
			upstream_error_kind,route_class,route_source,route_group_id,upstream_account_type,guardian_attempt_only)
			VALUES ($1,51,$2,500,'server','cyb_relay','direct',7,'openai_responses',false)`, db.timeArg(at), logical)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	insert(now.Add(-3*time.Minute), "mature-failure")
	insert(now.Add(-time.Minute), "unmatured-failure")
	insert(now.Add(-4*time.Minute), "mature-failure-recent-success")
	if _, err := db.conn.ExecContext(ctx, `INSERT INTO usage_logs (created_at,account_id,logical_request_id,status_code,
		upstream_error_kind,route_class,route_source,route_group_id,upstream_account_type,guardian_attempt_only)
		VALUES ($1,51,'mature-failure-recent-success',200,'','cyb_relay','direct',7,'openai_responses',false)`, db.timeArg(now.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}

	matureEnd := now.Add(-2 * time.Minute)
	rows, err := db.ListRelayGuardianReliability(ctx, 7, matureEnd.Add(-time.Hour), matureEnd.Add(-10*time.Minute), matureEnd, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Total10m != 1 || rows[0].Failures10m != 1 {
		t.Fatalf("maturity watermark aggregate=%+v", rows)
	}
}

func TestRelayGuardianModeRoundTrip(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpdateRelayGuardianMode(ctx, "monitor"); err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings == nil || settings.RelayGuardianMode != "monitor" {
		t.Fatalf("mode=%v", settings)
	}
}

func TestRelayGuardianEventsPaginationAndTimeFilter(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	for index, eventType := range []string{"quarantine", "probation", "recovered"} {
		_, err := db.conn.ExecContext(ctx, `INSERT INTO relay_guardian_events (created_at,account_id,event_type,generation) VALUES ($1,51,$2,$3)`, db.timeArg(base.Add(time.Duration(index)*time.Minute)), eventType, index+1)
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := db.ListRelayGuardianEvents(ctx, 1, 1, base.Add(30*time.Second), base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 1 || page.Items[0].EventType != "recovered" {
		t.Fatalf("page=%+v", page)
	}
	second, err := db.ListRelayGuardianEvents(ctx, 2, 1, base.Add(30*time.Second), base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].EventType != "probation" {
		t.Fatalf("second=%+v", second)
	}
}

func TestRelayGuardianEventsUseCurrentAccountNameAfterRename(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts (id,name,platform,type,credentials,status,enabled)
		VALUES (51,'old-relay','openai','responses_api','{}','active',true)`); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertRelayGuardianEvent(ctx, &RelayGuardianEvent{AccountID: 51, AccountName: "old-relay", EventType: "summary"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(ctx, `UPDATE accounts SET name='renamed-relay' WHERE id=51`); err != nil {
		t.Fatal(err)
	}
	page, err := db.ListRelayGuardianEvents(ctx, 1, 20, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].AccountName != "renamed-relay" {
		t.Fatalf("events did not follow current account name: %+v", page.Items)
	}
}

func TestRelayGuardianEventsUseSnapshotForBlankOrMissingAccountName(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, account := range []struct {
		id     int64
		name   string
		status string
		error  string
	}{
		{id: 51, name: "   ", status: "active"},
		{id: 52, name: "physical-current", status: "active"},
		{id: 53, name: "  soft-deleted-current  ", status: "deleted", error: "deleted"},
	} {
		if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts (id,name,platform,type,credentials,status,error_message,enabled)
			VALUES ($1,$2,'openai','responses_api','{}',$3,$4,true)`, account.id, account.name, account.status, account.error); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range []RelayGuardianEvent{
		{AccountID: 51, AccountName: "blank-name-snapshot", EventType: "summary"},
		{AccountID: 52, AccountName: "physical-delete-snapshot", EventType: "summary"},
		{AccountID: 53, AccountName: "soft-delete-snapshot", EventType: "summary"},
	} {
		if err := db.InsertRelayGuardianEvent(ctx, &event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.conn.ExecContext(ctx, `DELETE FROM accounts WHERE id=52`); err != nil {
		t.Fatal(err)
	}

	page, err := db.ListRelayGuardianEvents(ctx, 1, 20, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[int64]string, len(page.Items))
	for _, event := range page.Items {
		got[event.AccountID] = event.AccountName
	}
	if got[51] != "blank-name-snapshot" {
		t.Fatalf("blank current name = %q, want snapshot", got[51])
	}
	if got[52] != "physical-delete-snapshot" {
		t.Fatalf("missing account name = %q, want snapshot", got[52])
	}
	if got[53] != "soft-deleted-current" {
		t.Fatalf("soft-deleted current name = %q, want current trimmed name", got[53])
	}
}

func TestRelayGuardianEventUsesProvidedTimeAndRetentionDeletesOnlyOldRows(t *testing.T) {
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 2, 3, 4, 0, time.UTC)
	recent := old.Add(100 * 24 * time.Hour)
	if err := db.InsertRelayGuardianEvent(ctx, &RelayGuardianEvent{CreatedAt: old, EventType: "summary", Details: map[string]any{"window_id": "old"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertRelayGuardianEvent(ctx, &RelayGuardianEvent{CreatedAt: recent, EventType: "audit", Details: map[string]any{"window_id": "recent"}}); err != nil {
		t.Fatal(err)
	}
	page, err := db.ListRelayGuardianEvents(ctx, 1, 20, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || !page.Items[1].CreatedAt.Equal(old) {
		t.Fatalf("provided event time not preserved: %+v", page.Items)
	}
	deleted, err := db.DeleteRelayGuardianEventsBefore(ctx, old.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted=%d, want 1", deleted)
	}
	remaining, err := db.ListRelayGuardianEvents(ctx, 1, 20, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if remaining.Total != 1 || len(remaining.Items) != 1 || remaining.Items[0].EventType != "audit" {
		t.Fatalf("retention removed wrong rows: %+v", remaining)
	}
}
