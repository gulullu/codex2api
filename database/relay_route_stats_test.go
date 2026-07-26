package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRelayRouteStatsWindow(t *testing.T) {
	window, err := ValidateRelayRouteStatsWindow(0)
	if err != nil || window != 24*time.Hour {
		t.Fatalf("default window = %s, err=%v", window, err)
	}
	if _, err := ValidateRelayRouteStatsWindow(24*90 + 1); err == nil {
		t.Fatal("oversized stats window was accepted")
	}
}

func TestGetRelayRouteStatsSQLite(t *testing.T) {
	db, err := New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Now()
	for _, input := range []*RelayAuditRequestInput{
		{RequestID: "cyb", CreatedAt: now, RouteSource: "cyb_rule", RouteGroupID: 7},
		{RequestID: "overflow", CreatedAt: now, RouteSource: "oauth_overflow", RouteGroupID: 7},
		{RequestID: "oauth-miss", CreatedAt: now, RouteSource: "official_default"},
	} {
		if err := db.WriteRelayAuditRequest(ctx, input); err != nil {
			t.Fatalf("WriteRelayAuditRequest(%s): %v", input.RequestID, err)
		}
	}
	for _, input := range []*RelayAuditOutcomeInput{
		{RequestID: "cyb", AttemptIndex: 1, AccountID: 10, AccountType: "responses_api", StatusCode: 503, ErrorKind: "server_error", CompletedAt: now},
		{RequestID: "cyb", AttemptIndex: 2, AccountID: 11, AccountType: "responses_api", StatusCode: 200, CompletedAt: now, Final: true},
		{RequestID: "overflow", AttemptIndex: 1, AccountID: 12, AccountType: "responses_api", StatusCode: 200, CompletedAt: now, Final: true},
		{RequestID: "oauth-miss", AttemptIndex: 1, AccountID: 13, AccountType: "oauth", StatusCode: 400, ErrorKind: "cyber_policy", CompletedAt: now, Final: true, DetectorMiss: true},
	} {
		if err := db.WriteRelayAuditOutcome(ctx, input); err != nil {
			t.Fatalf("WriteRelayAuditOutcome(%s): %v", input.RequestID, err)
		}
	}
	if err := db.WriteRelayAuditAttempt(ctx, &RelayAuditAttemptInput{
		RequestID: "cyb", AttemptIndex: 2, SelectionMode: "same_group_switch",
		AccountID: 11, AccountType: "responses_api", SelectedAt: now,
	}); err != nil {
		t.Fatalf("WriteRelayAuditAttempt(switch): %v", err)
	}
	if err := db.WriteRelayAuditState(ctx, &RelayAuditStateInput{
		RequestID: "oauth-miss", DetectorMiss: true, StateFallbackReason: "pin_read_error",
	}); err != nil {
		t.Fatalf("WriteRelayAuditState(): %v", err)
	}

	stats, err := db.GetRelayRouteStats(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("GetRelayRouteStats(): %v", err)
	}
	if stats.RouteAttempts != 4 || stats.LogicalRoutes != 2 {
		t.Fatalf("route totals = attempts:%d logical:%d", stats.RouteAttempts, stats.LogicalRoutes)
	}
	if stats.CYBRule != 1 || stats.OAuthOverflow != 1 || stats.SameGroupSwitches != 1 ||
		stats.DetectorMisses != 1 || stats.StateFallbacks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}
