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
