package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayRouteSelectionSource(t *testing.T) {
	for _, source := range []string{
		"relay_route_cyb_rule",
		"relay_route_probe",
		"relay_route_oauth_overflow",
		"relay_route_relay_continuation",
		"relay_route_cyb_feedback",
		"relay_route_official_default",
	} {
		if !relayRouteSelectionSource(source) {
			t.Fatalf("%q should be a selection source", source)
		}
	}
	for _, source := range []string{
		"relay_route_detector_miss",
		"relay_route_group_exhausted",
		"relay_route_group_escape_violation",
		"relay_route_state_fallback",
	} {
		if relayRouteSelectionSource(source) {
			t.Fatalf("%q should not be a selection source", source)
		}
	}
}

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
	for _, input := range []*PromptFilterLogInput{
		{Source: "relay_route_cyb_rule", Mode: "initial"},
		{Source: "relay_route_cyb_rule", Mode: "same_group_switch"},
		{Source: "relay_route_oauth_overflow", Mode: "initial"},
		{Source: "relay_route_official_default", Mode: "initial"},
		{Source: "relay_route_detector_miss", Mode: "cyber_policy"},
		{Source: "relay_route_state_fallback", Mode: "pin_read_error"},
		{Source: "prompt_filter", Mode: "monitor"},
	} {
		if err := db.InsertPromptFilterLog(ctx, input); err != nil {
			t.Fatalf("InsertPromptFilterLog(%s): %v", input.Source, err)
		}
	}

	stats, err := db.GetRelayRouteStats(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("GetRelayRouteStats(): %v", err)
	}
	if stats.RouteAttempts != 4 || stats.LogicalRoutes != 3 {
		t.Fatalf("route totals = attempts:%d logical:%d", stats.RouteAttempts, stats.LogicalRoutes)
	}
	if stats.CYBRule != 1 || stats.OAuthOverflow != 1 || stats.SameGroupSwitches != 1 ||
		stats.DetectorMisses != 1 || stats.StateFallbacks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}
