package database

import (
	"context"
	"fmt"
	"time"
)

type RelayRouteStats struct {
	WindowHours        int   `json:"window_hours"`
	RouteAttempts      int64 `json:"route_attempts"`
	LogicalRoutes      int64 `json:"logical_routes"`
	CYBRule            int64 `json:"cyb_rule"`
	Probe              int64 `json:"probe"`
	NoAffinitySplit    int64 `json:"no_affinity_split"`
	OAuthOverflow      int64 `json:"oauth_overflow"`
	Continuation       int64 `json:"relay_continuation"`
	Feedback           int64 `json:"cyb_feedback"`
	Retries            int64 `json:"retries"`
	SameGroupSwitches  int64 `json:"same_group_switches"`
	GroupExhausted     int64 `json:"group_exhausted"`
	DetectorMisses     int64 `json:"detector_misses"`
	RelayCyberPolicies int64 `json:"relay_cyber_policies"`
	RouteViolations    int64 `json:"route_violations"`
	StateFallbacks     int64 `json:"state_fallbacks"`
}

func (db *DB) GetRelayRouteStats(ctx context.Context, window time.Duration) (RelayRouteStats, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	stats := RelayRouteStats{WindowHours: int(window.Round(time.Hour) / time.Hour)}
	end := time.Now()
	report, err := db.BuildRelayAuditReport(ctx, RelayAuditQuery{
		Start:         end.Add(-window),
		End:           end,
		BucketMinutes: 60,
	})
	if err != nil {
		return stats, err
	}
	if report == nil {
		return stats, nil
	}
	summary := report.Summary
	stats.RouteAttempts = summary.RouteAttempts
	stats.LogicalRoutes = summary.RelayRequests
	stats.CYBRule = summary.CYBRule
	stats.Probe = summary.Probe
	stats.NoAffinitySplit = summary.NoAffinitySplit
	stats.OAuthOverflow = summary.OAuthOverflow
	stats.Continuation = summary.Continuation
	stats.Feedback = summary.Feedback
	stats.Retries = summary.Retries
	stats.SameGroupSwitches = summary.SameGroupSwitches
	stats.GroupExhausted = summary.GroupExhausted
	stats.DetectorMisses = summary.DetectorMisses
	stats.RelayCyberPolicies = summary.RelayCyberPolicies
	stats.RouteViolations = summary.RouteViolations
	stats.StateFallbacks = summary.StateFallbacks
	return stats, nil
}

func ValidateRelayRouteStatsWindow(hours int) (time.Duration, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*90 {
		return 0, fmt.Errorf("window_hours must be between 1 and %d", 24*90)
	}
	return time.Duration(hours) * time.Hour, nil
}
