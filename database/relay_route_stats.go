package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type RelayRouteStats struct {
	WindowHours        int   `json:"window_hours"`
	RouteAttempts      int64 `json:"route_attempts"`
	LogicalRoutes      int64 `json:"logical_routes"`
	CYBRule            int64 `json:"cyb_rule"`
	Probe              int64 `json:"probe"`
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
	start, _ := db.timeRangeArgs(time.Now().Add(-window), time.Now())
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(source, ''), COALESCE(mode, ''), COUNT(*)
		FROM prompt_filter_logs
		WHERE created_at >= $1 AND source LIKE 'relay_route_%'
		GROUP BY source, mode
	`, start)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var source, mode string
		var count int64
		if err := rows.Scan(&source, &mode, &count); err != nil {
			return stats, err
		}
		switch source {
		case "relay_route_group_exhausted":
			stats.GroupExhausted += count
		case "relay_route_detector_miss":
			stats.DetectorMisses += count
		case "relay_route_relay_cyber_policy":
			stats.RelayCyberPolicies += count
		case "relay_route_group_escape_violation":
			stats.RouteViolations += count
		case "relay_route_state_fallback":
			stats.StateFallbacks += count
		}
		if relayRouteSelectionSource(source) {
			stats.RouteAttempts += count
			if mode == "initial" {
				stats.LogicalRoutes += count
				switch source {
				case "relay_route_cyb_rule":
					stats.CYBRule += count
				case "relay_route_probe":
					stats.Probe += count
				case "relay_route_oauth_overflow":
					stats.OAuthOverflow += count
				case "relay_route_relay_continuation":
					stats.Continuation += count
				case "relay_route_cyb_feedback":
					stats.Feedback += count
				}
			}
			if mode == "retry" {
				stats.Retries += count
			}
			if mode == "same_group_switch" {
				stats.SameGroupSwitches += count
			}
		}
	}
	return stats, rows.Err()
}

func relayRouteSelectionSource(source string) bool {
	switch strings.TrimSpace(source) {
	case "relay_route_cyb_rule",
		"relay_route_probe",
		"relay_route_oauth_overflow",
		"relay_route_relay_continuation",
		"relay_route_cyb_feedback",
		"relay_route_official_default":
		return true
	default:
		return false
	}
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
