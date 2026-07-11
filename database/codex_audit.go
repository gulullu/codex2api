package database

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type CodexAuditQuery struct {
	Start         time.Time
	End           time.Time
	BucketMinutes int
	Limit         int
}

type CodexAuditReport struct {
	WindowStart            time.Time                   `json:"window_start"`
	WindowEnd              time.Time                   `json:"window_end"`
	GeneratedAt            time.Time                   `json:"generated_at"`
	Verdict                string                      `json:"verdict"`
	Summary                CodexAuditSummary           `json:"summary"`
	PromptFilter           []CodexAuditPromptFilterRow `json:"prompt_filter"`
	Usage                  CodexAuditUsageSummary      `json:"usage"`
	Timeline               []CodexAuditTimelinePoint   `json:"timeline"`
	Models                 []CodexAuditModelRow        `json:"models"`
	RelayRoutes            []CodexAuditRelayRouteRow   `json:"relay_routes"`
	RouteSignals           []CodexAuditRouteSignalRow  `json:"route_signals"`
	RouteSamples           []*PromptFilterLog          `json:"route_samples"`
	OAuthCyberCases        []*PromptFilterLog          `json:"oauth_cyber_cases"`
	RelayCyberCases        []*PromptFilterLog          `json:"relay_cyber_cases"`
	SuspiciousSamples      []*PromptFilterLog          `json:"suspicious_samples"`
	ProbeObserved          []CodexAuditProbeRow        `json:"probe_observed"`
	ProbeShortCircuits     []CodexAuditProbeRow        `json:"probe_short_circuits"`
	ProbeHighFrequency     []CodexAuditProbeRow        `json:"probe_high_frequency"`
	PolicyErrors           []*UsageLog                 `json:"policy_errors"`
	SlowRequests           []*UsageLog                 `json:"slow_requests"`
	Notes                  []string                    `json:"notes"`
	LastCyberPolicyAt      *time.Time                  `json:"last_cyber_policy_at,omitempty"`
	LastOAuthCyberPolicyAt *time.Time                  `json:"last_oauth_cyber_policy_at,omitempty"`
	LastRelayCyberPolicyAt *time.Time                  `json:"last_relay_cyber_policy_at,omitempty"`
}

type CodexAuditSummary struct {
	PromptLogs                 int64 `json:"prompt_logs"`
	PromptBlocks               int64 `json:"prompt_blocks"`
	ReviewFlagged              int64 `json:"review_flagged"`
	ReviewErrors               int64 `json:"review_errors"`
	HighScoreAllowed           int64 `json:"high_score_allowed"`
	SemanticDisagreements      int64 `json:"semantic_disagreements"`
	SemanticDisagreementBlocks int64 `json:"semantic_disagreement_blocks"`
	UpstreamCyberPolicy        int64 `json:"upstream_cyber_policy"`
	SessionBleed               int64 `json:"session_bleed"`
	ProbeObserved              int64 `json:"probe_observed"`
	ProbeShortCircuits         int64 `json:"probe_short_circuits"`
	ProbeHighFrequency         int64 `json:"probe_high_frequency"`
	RelayRequests              int64 `json:"relay_requests"`
	RelayDirect                int64 `json:"relay_direct"`
	RelayPinned                int64 `json:"relay_pinned"`
	RelayLegacyUnknown         int64 `json:"relay_legacy_unknown"`
	RelayRouteFailures         int64 `json:"relay_route_failures"`
	RelayFallbackPrevented     int64 `json:"relay_fallback_prevented"`
	OAuthCyberMissRequests     int64 `json:"oauth_cyber_miss_requests"`
	OAuthCyberMissAttempts     int64 `json:"oauth_cyber_miss_attempts"`
	RelayCyberRequests         int64 `json:"relay_cyber_requests"`
	RelayCyberAttempts         int64 `json:"relay_cyber_attempts"`
	LegacyCyberUnattributed    int64 `json:"legacy_cyber_unattributed"`
	RouteInvariantViolations   int64 `json:"route_invariant_violations"`
	LegacyUsageRows            int64 `json:"legacy_usage_rows"`
}

type CodexAuditPromptFilterRow struct {
	Source        string `json:"source"`
	Action        string `json:"action"`
	Mode          string `json:"mode"`
	ReviewModel   string `json:"review_model"`
	ReviewFlagged bool   `json:"review_flagged"`
	Count         int64  `json:"count"`
	MinScore      int    `json:"min_score"`
	MaxScore      int    `json:"max_score"`
	ReviewErrors  int64  `json:"review_errors"`
}

type CodexAuditUsageSummary struct {
	Requests          int64   `json:"requests"`
	UpstreamAttempts  int64   `json:"upstream_attempts"`
	Errors4xx         int64   `json:"errors_4xx"`
	Errors5xx         int64   `json:"errors_5xx"`
	WebSocketRequests int64   `json:"websocket_requests"`
	WebSocketRatio    float64 `json:"websocket_ratio"`
	PolicyLikeErrors  int64   `json:"policy_like_errors"`
	FirstTokenSamples int64   `json:"first_token_samples"`
	FirstTokenMinMS   int     `json:"first_token_min_ms"`
	FirstTokenP50MS   int     `json:"first_token_p50_ms"`
	FirstTokenP95MS   int     `json:"first_token_p95_ms"`
	FirstTokenMaxMS   int     `json:"first_token_max_ms"`
}

type CodexAuditTimelinePoint struct {
	Bucket                   time.Time `json:"bucket"`
	Requests                 int64     `json:"requests"`
	PromptBlocks             int64     `json:"prompt_blocks"`
	ReviewFlagged            int64     `json:"review_flagged"`
	UpstreamCyberPolicy      int64     `json:"upstream_cyber_policy"`
	Errors4xx                int64     `json:"errors_4xx"`
	Errors5xx                int64     `json:"errors_5xx"`
	FirstTokenP95MS          int       `json:"first_token_p95_ms"`
	DefaultRequests          int64     `json:"default_requests"`
	RelayDirect              int64     `json:"relay_direct"`
	RelayPinned              int64     `json:"relay_pinned"`
	RelayLegacyUnknown       int64     `json:"relay_legacy_unknown"`
	RelayRouteFailures       int64     `json:"relay_route_failures"`
	OAuthCyberAttempts       int64     `json:"oauth_cyber_attempts"`
	RelayCyberAttempts       int64     `json:"relay_cyber_attempts"`
	RouteInvariantViolations int64     `json:"route_invariant_violations"`
}

type CodexAuditRelayRouteRow struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name"`
	RouteSource string `json:"route_source"`
	PinKind     string `json:"pin_kind"`
	Requests    int64  `json:"requests"`
	Attempts    int64  `json:"attempts"`
	Successes   int64  `json:"successes"`
	Errors4xx   int64  `json:"errors_4xx"`
	Errors5xx   int64  `json:"errors_5xx"`
	CyberPolicy int64  `json:"cyber_policy"`
}

type CodexAuditRouteSignalRow struct {
	Signal   string    `json:"signal"`
	Requests int64     `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
}

type CodexAuditModelRow struct {
	Model           string `json:"model"`
	Requests        int64  `json:"requests"`
	Errors4xx       int64  `json:"errors_4xx"`
	Errors5xx       int64  `json:"errors_5xx"`
	WebSocket       int64  `json:"websocket"`
	FirstTokenP95MS int    `json:"first_token_p95_ms"`
}

type CodexAuditProbeRow struct {
	APIKeyID               int64     `json:"api_key_id"`
	APIKeyName             string    `json:"api_key_name"`
	APIKeyMasked           string    `json:"api_key_masked"`
	Endpoint               string    `json:"endpoint"`
	Model                  string    `json:"model"`
	Signature              string    `json:"signature"`
	Stream                 bool      `json:"stream"`
	Count                  int64     `json:"count"`
	FirstSeen              time.Time `json:"first_seen"`
	LastSeen               time.Time `json:"last_seen"`
	SpanSeconds            float64   `json:"span_seconds"`
	AverageIntervalSeconds float64   `json:"average_interval_seconds"`
	RatePerMinute          float64   `json:"rate_per_minute"`
}

func (db *DB) BuildCodexAuditReport(ctx context.Context, query CodexAuditQuery) (*CodexAuditReport, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	now := time.Now()
	end := query.End
	if end.IsZero() {
		end = now
	}
	start := query.Start
	if start.IsZero() {
		start = end.Add(-30 * time.Minute)
	}
	if !start.Before(end) {
		start = end.Add(-30 * time.Minute)
	}
	if query.BucketMinutes <= 0 {
		query.BucketMinutes = 5
	}
	if query.BucketMinutes > 1440 {
		query.BucketMinutes = 1440
	}
	if query.Limit <= 0 || query.Limit > 100 {
		query.Limit = 20
	}

	report := &CodexAuditReport{
		WindowStart: start,
		WindowEnd:   end,
		GeneratedAt: now,
		Notes: []string{
			"Sub2 bridge account state is not queried from inside codex2api; use the external s12 audit workflow when bridge schedulability must be confirmed.",
		},
	}
	var err error
	if report.PromptFilter, err = db.codexAuditPromptFilterRows(ctx, start, end); err != nil {
		return nil, err
	}
	if report.Usage, err = db.codexAuditUsageSummary(ctx, start, end); err != nil {
		return nil, err
	}
	if report.Timeline, err = db.codexAuditTimeline(ctx, start, end, query.BucketMinutes); err != nil {
		return nil, err
	}
	if report.Models, err = db.codexAuditModels(ctx, start, end, query.Limit); err != nil {
		return nil, err
	}
	if report.RelayRoutes, err = db.codexAuditRelayRouteRows(ctx, start, end); err != nil {
		return nil, err
	}
	if report.RouteSignals, err = db.codexAuditRouteSignalRows(ctx, start, end); err != nil {
		return nil, err
	}
	if report.RouteSamples, _, err = db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{Page: 1, PageSize: query.Limit, Source: "cyb_relay_routed", Start: start, End: end}); err != nil {
		return nil, err
	}
	if report.OAuthCyberCases, _, err = db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{Page: 1, PageSize: query.Limit, Source: "upstream_cyber_policy", CyberScope: "oauth", Start: start, End: end}); err != nil {
		return nil, err
	}
	if report.RelayCyberCases, _, err = db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{Page: 1, PageSize: query.Limit, Source: "upstream_cyber_policy", CyberScope: "relay", Start: start, End: end}); err != nil {
		return nil, err
	}
	if report.SuspiciousSamples, err = db.codexAuditSuspiciousSamples(ctx, start, end, query.Limit); err != nil {
		return nil, err
	}
	if report.ProbeObserved, err = db.codexAuditProbeObserved(ctx, start, end, query.Limit); err != nil {
		return nil, err
	}
	if report.ProbeShortCircuits, err = db.codexAuditProbeShortCircuits(ctx, start, end, query.Limit); err != nil {
		return nil, err
	}
	if report.ProbeHighFrequency, err = db.codexAuditProbeHighFrequency(ctx, start, end, query.Limit); err != nil {
		return nil, err
	}
	if report.PolicyErrors, err = db.codexAuditUsageSamples(ctx, start, end, query.Limit, "policy"); err != nil {
		return nil, err
	}
	if report.SlowRequests, err = db.codexAuditUsageSamples(ctx, start, end, query.Limit, "slow"); err != nil {
		return nil, err
	}
	report.Summary = summarizeCodexAudit(report)
	routeSummary, routeErr := db.codexAuditRouteSummary(ctx, start, end)
	if routeErr != nil {
		return nil, routeErr
	}
	mergeCodexAuditRouteSummary(&report.Summary, routeSummary)
	report.Verdict = codexAuditVerdict(report)
	if report.LastOAuthCyberPolicyAt, err = db.codexAuditLastCyberPolicyAt(ctx, end, "oauth"); err != nil {
		return nil, err
	}
	report.LastCyberPolicyAt = report.LastOAuthCyberPolicyAt
	if report.LastRelayCyberPolicyAt, err = db.codexAuditLastCyberPolicyAt(ctx, end, "relay"); err != nil {
		return nil, err
	}
	return report, nil
}

// codexAuditLastCyberPolicyAt 查询窗口外最近一次精确 cyber_policy 使用事件（30 天回看）。
// usage_logs 是上游账号归属与实际调用结果的权威来源；prompt_filter_logs 只用于案卷正文。
func (db *DB) codexAuditLastCyberPolicyAt(ctx context.Context, end time.Time, scope string) (*time.Time, error) {
	start := end.Add(-30 * 24 * time.Hour)
	startArg, endArg := db.timeRangeArgs(start, end)
	accountType := "oauth"
	routeClause := ""
	if scope == "relay" {
		accountType = "openai_responses"
		routeClause = " AND COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) > 0"
	}
	var raw any
	if err := db.conn.QueryRowContext(ctx, `
		SELECT MAX(created_at) FROM usage_logs
		WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy'
		  AND COALESCE(upstream_account_type, '') = $3
		  AND created_at >= $1 AND created_at <= $2`+routeClause,
		startArg, endArg, accountType).Scan(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	ts, err := parseDBTimeValue(raw)
	if err != nil {
		return nil, nil
	}
	return &ts, nil
}

func (db *DB) codexAuditPromptFilterRows(ctx context.Context, start, end time.Time) ([]CodexAuditPromptFilterRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(source, ''), COALESCE(action, ''), COALESCE(mode, ''), COALESCE(review_model, ''),
		       COALESCE(review_flagged, false), COUNT(*), COALESCE(MIN(score), 0), COALESCE(MAX(score), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(review_error, '') <> '' THEN 1 ELSE 0 END), 0)
		FROM prompt_filter_logs
		WHERE created_at >= $1 AND created_at <= $2
		GROUP BY 1, 2, 3, 4, 5
		ORDER BY COUNT(*) DESC, 1, 2
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CodexAuditPromptFilterRow, 0)
	for rows.Next() {
		var item CodexAuditPromptFilterRow
		if err := rows.Scan(&item.Source, &item.Action, &item.Mode, &item.ReviewModel, &item.ReviewFlagged, &item.Count, &item.MinScore, &item.MaxScore, &item.ReviewErrors); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (db *DB) codexAuditUsageSummary(ctx context.Context, start, end time.Time) (CodexAuditUsageSummary, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	var summary CodexAuditUsageSummary
	err := db.conn.QueryRowContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(via_websocket, false) THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN lower(COALESCE(error_message, '')) LIKE '%cyber%'
		                           OR lower(COALESCE(error_message, '')) LIKE '%policy%'
		                           OR lower(COALESCE(error_message, '')) LIKE '%violat%'
		                           OR lower(COALESCE(error_message, '')) LIKE '%safety%'
		                           OR lower(COALESCE(upstream_error_kind, '')) LIKE '%policy%'
		                           OR lower(COALESCE(upstream_error_kind, '')) LIKE '%cyber%'
		                           OR lower(COALESCE(upstream_error_kind, '')) LIKE '%violat%'
		                           OR lower(COALESCE(upstream_error_kind, '')) LIKE '%safety%'
		                      THEN 1 ELSE 0 END), 0),
		       COALESCE(MIN(CASE WHEN first_token_ms > 0 THEN first_token_ms END), 0),
		       COALESCE(MAX(first_token_ms), 0),
		       (SELECT COUNT(*) FROM ranked_usage)
		FROM final_usage
	`, startArg, endArg).Scan(&summary.Requests, &summary.Errors4xx, &summary.Errors5xx, &summary.WebSocketRequests, &summary.PolicyLikeErrors, &summary.FirstTokenMinMS, &summary.FirstTokenMaxMS, &summary.UpstreamAttempts)
	if err != nil {
		return summary, err
	}
	if summary.Requests > 0 {
		summary.WebSocketRatio = float64(summary.WebSocketRequests) / float64(summary.Requests)
	}
	tokens, err := db.codexAuditFirstTokenValues(ctx, start, end, "")
	if err != nil {
		return summary, err
	}
	summary.FirstTokenSamples = int64(len(tokens))
	summary.FirstTokenP50MS = percentileInt(tokens, 0.50)
	summary.FirstTokenP95MS = percentileInt(tokens, 0.95)
	return summary, nil
}

func (db *DB) codexAuditFirstTokenValues(ctx context.Context, start, end time.Time, model string) ([]int, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	args := []any{startArg, endArg}
	where := "first_token_ms > 0"
	if strings.TrimSpace(model) != "" {
		args = append(args, model)
		where += fmt.Sprintf(" AND COALESCE(NULLIF(effective_model, ''), model, '') = $%d", len(args))
	}
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`SELECT first_token_ms FROM final_usage WHERE `+where+` ORDER BY first_token_ms ASC LIMIT 20000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]int, 0)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func (db *DB) codexAuditTimeline(ctx context.Context, start, end time.Time, bucketMinutes int) ([]CodexAuditTimelinePoint, error) {
	buckets := map[int64]*CodexAuditTimelinePoint{}
	bucketOf := func(t time.Time) int64 {
		sec := int64(bucketMinutes) * 60
		if sec <= 0 {
			sec = 300
		}
		return t.Unix() / sec * sec
	}
	pointFor := func(created time.Time) *CodexAuditTimelinePoint {
		key := bucketOf(created)
		point := buckets[key]
		if point == nil {
			point = &CodexAuditTimelinePoint{Bucket: time.Unix(key, 0)}
			buckets[key] = point
		}
		return point
	}
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT created_at, status_code, COALESCE(first_token_ms, 0),
		       COALESCE(route_class, ''), COALESCE(route_source, ''), COALESCE(route_group_id, 0),
		       COALESCE(logical_request_id, ''), COALESCE(upstream_account_type, ''),
		       COALESCE(upstream_error_kind, ''), COALESCE(account_id, 0),
		       COALESCE(route_signals, '[]'), COALESCE(pin_kind, '')
		FROM final_usage
		ORDER BY created_at ASC
		LIMIT 100000
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	firstTokens := map[int64][]int{}
	for rows.Next() {
		var raw any
		var status, ft int
		var routeClass, routeSource, logicalID, accountType, errorKind, routeSignals, pinKind string
		var routeGroupID, accountID int64
		if err := rows.Scan(&raw, &status, &ft, &routeClass, &routeSource, &routeGroupID, &logicalID, &accountType, &errorKind, &accountID, &routeSignals, &pinKind); err != nil {
			rows.Close()
			return nil, err
		}
		created, err := parseDBTimeValue(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		point := pointFor(created)
		point.Requests++
		if routeClass == "cyb_relay" {
			switch routeSource {
			case "direct":
				point.RelayDirect++
			case "pin":
				point.RelayPinned++
			default:
				point.RelayLegacyUnknown++
			}
			if status >= 500 || errorKind == "relay_route_unavailable" || errorKind == "no_available_relay_account" || errorKind == "relay_affinity_unavailable" || errorKind == "route_switch_requires_replay" {
				point.RelayRouteFailures++
			}
		} else {
			point.DefaultRequests++
		}
		if logicalID != "" {
			invariant := (routeClass == "cyb_relay" && accountID > 0 && accountType != "openai_responses") ||
				(routeClass == "cyb_relay" && routeGroupID <= 0) ||
				(routeClass == "cyb_relay" && routeSource != "direct" && routeSource != "pin") ||
				(routeSource == "pin" && pinKind == "") ||
				(routeSource == "direct" && (routeSignals == "" || routeSignals == "[]" || routeSignals == "null")) ||
				(routeSource == "pin" && routeSignals != "" && routeSignals != "[]" && routeSignals != "null") ||
				((routeSource == "direct" || routeSource == "pin") && routeClass != "cyb_relay")
			if invariant {
				point.RouteInvariantViolations++
			}
		}
		if status >= 500 {
			point.Errors5xx++
		} else if status >= 400 {
			point.Errors4xx++
		}
		if ft > 0 {
			firstTokens[bucketOf(created)] = append(firstTokens[bucketOf(created)], ft)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	cyberRows, err := db.conn.QueryContext(ctx, `
		SELECT created_at, COALESCE(upstream_account_type, ''),
		       COALESCE(route_class, ''), COALESCE(route_group_id, 0)
		FROM usage_logs
		WHERE created_at >= $1 AND created_at <= $2
		  AND LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy'
		ORDER BY created_at ASC
		LIMIT 100000
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	for cyberRows.Next() {
		var raw any
		var accountType, routeClass string
		var routeGroupID int64
		if err := cyberRows.Scan(&raw, &accountType, &routeClass, &routeGroupID); err != nil {
			cyberRows.Close()
			return nil, err
		}
		created, err := parseDBTimeValue(raw)
		if err != nil {
			cyberRows.Close()
			return nil, err
		}
		point := pointFor(created)
		if accountType == "oauth" {
			point.OAuthCyberAttempts++
			point.UpstreamCyberPolicy++
		} else if accountType == "openai_responses" && routeClass == "cyb_relay" && routeGroupID > 0 {
			point.RelayCyberAttempts++
		}
	}
	if err := cyberRows.Err(); err != nil {
		cyberRows.Close()
		return nil, err
	}
	cyberRows.Close()

	keys := make([]int64, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	result := make([]CodexAuditTimelinePoint, 0, len(keys))
	for _, key := range keys {
		point := *buckets[key]
		point.FirstTokenP95MS = percentileInt(firstTokens[key], 0.95)
		result = append(result, point)
	}
	return result, nil
}

func (db *DB) codexAuditModels(ctx context.Context, start, end time.Time, limit int) ([]CodexAuditModelRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT COALESCE(NULLIF(effective_model, ''), model, '') AS m,
		       COUNT(*),
		       COALESCE(SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(via_websocket, false) THEN 1 ELSE 0 END), 0)
		FROM final_usage
		GROUP BY 1
		ORDER BY COUNT(*) DESC, 1
		LIMIT $3
	`, startArg, endArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CodexAuditModelRow, 0)
	for rows.Next() {
		var item CodexAuditModelRow
		if err := rows.Scan(&item.Model, &item.Requests, &item.Errors4xx, &item.Errors5xx, &item.WebSocket); err != nil {
			return nil, err
		}
		values, err := db.codexAuditFirstTokenValues(ctx, start, end, item.Model)
		if err != nil {
			return nil, err
		}
		item.FirstTokenP95MS = percentileInt(values, 0.95)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (db *DB) codexAuditSuspiciousSamples(ctx context.Context, start, end time.Time, limit int) ([]*PromptFilterLog, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, created_at, COALESCE(source, ''), COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(action, ''), COALESCE(mode, ''), COALESCE(score, 0), COALESCE(threshold_value, 0),
		       COALESCE(matched_patterns, '[]'), COALESCE(text_preview, ''), COALESCE(api_key_id, 0),
		       COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''), COALESCE(client_ip, ''), COALESCE(error_code, ''),
		       COALESCE(review_model, ''), COALESCE(review_flagged, false), COALESCE(review_error, ''), COALESCE(full_text, '')
		FROM prompt_filter_logs
		WHERE created_at >= $1 AND created_at <= $2
		  AND (
		    action = 'block'
		    OR source IN ('upstream_cyber_policy', 'semantic_review_disagreement')
		    OR COALESCE(review_error, '') <> ''
		    OR (action = 'allow' AND COALESCE(review_model, '') <> '' AND COALESCE(review_flagged, false) = false AND score >= 50)
		  )
		ORDER BY CASE
		    WHEN source = 'upstream_cyber_policy' THEN 0
		    WHEN source = 'semantic_review_disagreement' THEN 1
		    WHEN action = 'block' THEN 2
		    WHEN COALESCE(review_error, '') <> '' THEN 3
		    ELSE 4
		  END,
		  score DESC,
		  created_at DESC
		LIMIT $3
	`, startArg, endArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPromptFilterLogs(rows)
}

func (db *DB) codexAuditProbeObserved(ctx context.Context, start, end time.Time, limit int) ([]CodexAuditProbeRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		WITH grouped AS (
			SELECT COALESCE(api_key_id, 0) AS api_key_id,
			       COALESCE(api_key_name, '') AS api_key_name,
			       COALESCE(api_key_masked, '') AS api_key_masked,
			       COALESCE(endpoint, '') AS endpoint,
			       COALESCE(model, '') AS model,
			       COALESCE(substring(COALESCE(text_preview, '') FROM 'signature=([^ ]+)'), '') AS signature,
			       COALESCE(text_preview, '') LIKE '%stream=true%' AS stream,
			       COUNT(*) AS n,
			       MIN(created_at) AS first_seen,
			       MAX(created_at) AS last_seen,
			       EXTRACT(EPOCH FROM MAX(created_at) - MIN(created_at))::float8 AS span_seconds
		FROM prompt_filter_logs
		WHERE created_at >= $1 AND created_at <= $2 AND source = 'local_probe_observed'
			GROUP BY 1, 2, 3, 4, 5, 6, 7
		)
		SELECT api_key_id, api_key_name, api_key_masked, endpoint, model, signature, stream, n, first_seen, last_seen,
		       COALESCE(span_seconds, 0),
		       CASE WHEN n > 1 THEN COALESCE(span_seconds, 0) / (n - 1) ELSE 0 END AS average_interval_seconds,
		       CASE WHEN COALESCE(span_seconds, 0) > 0 THEN n * 60.0 / span_seconds ELSE n * 60.0 END AS rate_per_minute
		FROM grouped
		ORDER BY n DESC, first_seen
		LIMIT $3
	`, startArg, endArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCodexAuditProbeRows(rows)
}

func (db *DB) codexAuditProbeShortCircuits(ctx context.Context, start, end time.Time, limit int) ([]CodexAuditProbeRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		WITH grouped AS (
			SELECT COALESCE(api_key_id, 0) AS api_key_id,
			       COALESCE(api_key_name, '') AS api_key_name,
			       COALESCE(api_key_masked, '') AS api_key_masked,
			       COALESCE(inbound_endpoint, endpoint, '') AS endpoint,
			       COALESCE(NULLIF(effective_model, ''), model, '') AS model,
			       COALESCE(substring(COALESCE(error_message, '') FROM 'repeated probe short-circuited: ([^ ]+)'), '') AS signature,
			       COALESCE(stream, false) AS stream,
			       COUNT(*) AS n,
			       MIN(created_at) AS first_seen,
			       MAX(created_at) AS last_seen,
			       EXTRACT(EPOCH FROM MAX(created_at) - MIN(created_at))::float8 AS span_seconds
		FROM usage_logs
		WHERE created_at >= $1 AND created_at <= $2 AND upstream_error_kind = 'local_probe_short_circuit'
			GROUP BY 1, 2, 3, 4, 5, 6, 7
		)
		SELECT api_key_id, api_key_name, api_key_masked, endpoint, model, signature, stream, n, first_seen, last_seen,
		       COALESCE(span_seconds, 0),
		       CASE WHEN n > 1 THEN COALESCE(span_seconds, 0) / (n - 1) ELSE 0 END AS average_interval_seconds,
		       CASE WHEN COALESCE(span_seconds, 0) > 0 THEN n * 60.0 / span_seconds ELSE n * 60.0 END AS rate_per_minute
		FROM grouped
		ORDER BY n DESC, first_seen
		LIMIT $3
	`, startArg, endArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCodexAuditProbeRows(rows)
}

func (db *DB) codexAuditProbeHighFrequency(ctx context.Context, start, end time.Time, limit int) ([]CodexAuditProbeRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		WITH grouped AS (
			SELECT COALESCE(api_key_id, 0) AS api_key_id,
			       COALESCE(api_key_name, '') AS api_key_name,
			       COALESCE(api_key_masked, '') AS api_key_masked,
			       COALESCE(inbound_endpoint, endpoint, '') AS endpoint,
			       COALESCE(NULLIF(effective_model, ''), model, '') AS model,
			       COALESCE(substring(COALESCE(error_message, '') FROM 'repeated probe short-circuited: ([^ ]+)'), '') AS signature,
			       COALESCE(stream, false) AS stream,
			       COUNT(*) AS n,
			       MIN(created_at) AS first_seen,
			       MAX(created_at) AS last_seen,
			       EXTRACT(EPOCH FROM MAX(created_at) - MIN(created_at))::float8 AS span_seconds
			FROM usage_logs
			WHERE created_at >= $1 AND created_at <= $2 AND upstream_error_kind = 'local_probe_short_circuit'
			GROUP BY 1, 2, 3, 4, 5, 6, 7
		)
		SELECT api_key_id, api_key_name, api_key_masked, endpoint, model, signature, stream, n, first_seen, last_seen,
		       COALESCE(span_seconds, 0),
		       CASE WHEN n > 1 THEN COALESCE(span_seconds, 0) / (n - 1) ELSE 0 END AS average_interval_seconds,
		       CASE WHEN COALESCE(span_seconds, 0) > 0 THEN n * 60.0 / span_seconds ELSE n * 60.0 END AS rate_per_minute
		FROM grouped
		WHERE n > 0
		ORDER BY rate_per_minute DESC, n DESC, first_seen
		LIMIT $3
	`, startArg, endArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCodexAuditProbeRows(rows)
}

func scanCodexAuditProbeRows(rows scannerRows) ([]CodexAuditProbeRow, error) {
	result := make([]CodexAuditProbeRow, 0)
	for rows.Next() {
		var item CodexAuditProbeRow
		var firstRaw, lastRaw any
		if err := rows.Scan(
			&item.APIKeyID,
			&item.APIKeyName,
			&item.APIKeyMasked,
			&item.Endpoint,
			&item.Model,
			&item.Signature,
			&item.Stream,
			&item.Count,
			&firstRaw,
			&lastRaw,
			&item.SpanSeconds,
			&item.AverageIntervalSeconds,
			&item.RatePerMinute,
		); err != nil {
			return nil, err
		}
		first, err := parseDBTimeValue(firstRaw)
		if err != nil {
			return nil, err
		}
		last, err := parseDBTimeValue(lastRaw)
		if err != nil {
			return nil, err
		}
		item.FirstSeen = first
		item.LastSeen = last
		result = append(result, item)
	}
	return result, rows.Err()
}

func (db *DB) codexAuditUsageSamples(ctx context.Context, start, end time.Time, limit int, kind string) ([]*UsageLog, error) {
	if kind == "policy" {
		return db.codexAuditPolicyErrorSamples(ctx, start, end, limit)
	}

	filter := UsageLogFilter{
		Start:    start,
		End:      end,
		Page:     1,
		PageSize: limit,
	}
	switch kind {
	case "slow":
		filter.PageSize = limit
	default:
		filter.PageSize = limit
	}
	page, err := db.ListUsageLogsByTimeRangePaged(ctx, filter)
	if err != nil {
		return nil, err
	}
	logs := page.Logs
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].FirstTokenMs > logs[j].FirstTokenMs
	})
	if len(logs) > limit {
		logs = logs[:limit]
	}
	return logs, nil
}

func (db *DB) codexAuditPolicyErrorSamples(ctx context.Context, start, end time.Time, limit int) ([]*UsageLog, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	where, args := db.buildUsageLogWhere(UsageLogFilter{
		Start:           start,
		End:             end,
		ErrorOnly:       true,
		IncludeCanceled: true,
	})
	where += ` AND (
		LOWER(COALESCE(u.error_message, '')) LIKE '%policy%'
		OR LOWER(COALESCE(u.error_message, '')) LIKE '%cyber%'
		OR LOWER(COALESCE(u.error_message, '')) LIKE '%violat%'
		OR LOWER(COALESCE(u.error_message, '')) LIKE '%safety%'
		OR LOWER(COALESCE(u.upstream_error_kind, '')) LIKE '%policy%'
		OR LOWER(COALESCE(u.upstream_error_kind, '')) LIKE '%cyber%'
		OR LOWER(COALESCE(u.upstream_error_kind, '')) LIKE '%violat%'
		OR LOWER(COALESCE(u.upstream_error_kind, '')) LIKE '%safety%'
	)`
	limitArg := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, limit)

	query := `SELECT u.id, u.account_id, COALESCE(u.client_ip, ''), u.endpoint, u.model, COALESCE(u.effective_model, ''), u.prompt_tokens, u.completion_tokens, u.total_tokens, u.status_code, u.duration_ms,
			COALESCE(u.input_tokens, 0), COALESCE(u.output_tokens, 0), COALESCE(u.reasoning_tokens, 0),
			COALESCE(u.first_token_ms, 0), COALESCE(u.reasoning_effort, ''), COALESCE(u.inbound_endpoint, ''),
			COALESCE(u.upstream_endpoint, ''), COALESCE(u.stream, false), COALESCE(u.compact, false), COALESCE(u.via_websocket, false), COALESCE(u.cached_tokens, 0), COALESCE(u.service_tier, ''),
			COALESCE(u.requested_service_tier, ''), COALESCE(u.actual_service_tier, ''), COALESCE(u.billing_service_tier, ''),
			COALESCE(u.api_key_id, 0), COALESCE(u.api_key_name, ''), COALESCE(u.api_key_masked, ''),
			COALESCE(u.image_count, 0), COALESCE(u.image_width, 0), COALESCE(u.image_height, 0), COALESCE(u.image_bytes, 0),
			COALESCE(u.image_format, ''), COALESCE(u.image_size, ''),
			COALESCE(u.account_billed, 0), COALESCE(u.user_billed, 0),
			COALESCE(u.is_retry_attempt, false), COALESCE(u.attempt_index, 0), COALESCE(u.upstream_error_kind, ''), COALESCE(u.error_message, ''),
			COALESCE(CAST(a.credentials AS TEXT), '{}'), u.created_at
		FROM usage_logs u
		LEFT JOIN accounts a ON u.account_id = a.id
		WHERE ` + where + ` ORDER BY u.created_at DESC LIMIT ` + limitArg

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]*UsageLog, 0)
	for rows.Next() {
		l := &UsageLog{}
		var credentialRaw interface{}
		var createdAtRaw interface{}
		if err := rows.Scan(&l.ID, &l.AccountID, &l.ClientIP, &l.Endpoint, &l.Model, &l.EffectiveModel, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.StatusCode, &l.DurationMs,
			&l.InputTokens, &l.OutputTokens, &l.ReasoningTokens, &l.FirstTokenMs, &l.ReasoningEffort, &l.InboundEndpoint, &l.UpstreamEndpoint, &l.Stream, &l.Compact, &l.ViaWebsocket, &l.CachedTokens,
			&l.ServiceTier, &l.RequestedServiceTier, &l.ActualServiceTier, &l.BillingServiceTier, &l.APIKeyID, &l.APIKeyName, &l.APIKeyMasked, &l.ImageCount, &l.ImageWidth, &l.ImageHeight, &l.ImageBytes, &l.ImageFormat, &l.ImageSize,
			&l.AccountBilled, &l.UserBilled, &l.IsRetryAttempt, &l.AttemptIndex, &l.UpstreamErrorKind, &l.ErrorMessage, &credentialRaw, &createdAtRaw); err != nil {
			return nil, err
		}
		l.AccountEmail = accountEmailFromRawCredentials(credentialRaw)
		l.CreatedAt, err = parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, err
		}
		l.populateBillingBreakdown()
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

type scannerRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanPromptFilterLogs(rows scannerRows) ([]*PromptFilterLog, error) {
	result := make([]*PromptFilterLog, 0)
	for rows.Next() {
		item := &PromptFilterLog{}
		var createdAtRaw any
		if err := rows.Scan(&item.ID, &createdAtRaw, &item.Source, &item.Endpoint, &item.Model, &item.Action, &item.Mode,
			&item.Score, &item.Threshold, &item.MatchedPatterns, &item.TextPreview, &item.APIKeyID, &item.APIKeyName,
			&item.APIKeyMasked, &item.ClientIP, &item.ErrorCode, &item.ReviewModel, &item.ReviewFlagged, &item.ReviewError, &item.FullText); err != nil {
			return nil, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = createdAt
		result = append(result, item)
	}
	return result, rows.Err()
}

const codexAuditCanonicalUsageCTE = `
WITH ranked_usage AS (
	SELECT u.*,
	       COALESCE(NULLIF(u.logical_request_id, ''), 'legacy:' || CAST(u.id AS TEXT)) AS audit_request_id,
	       ROW_NUMBER() OVER (
		   PARTITION BY COALESCE(NULLIF(u.logical_request_id, ''), 'legacy:' || CAST(u.id AS TEXT))
		   -- Retry failures carry attempt_index, while the terminal success row is
		   -- currently written with the default zero value. The final append is the
		   -- authoritative logical-request outcome, so rank by write order only.
		   ORDER BY u.id DESC
	       ) AS audit_rn
	FROM usage_logs u
	WHERE u.created_at >= $1 AND u.created_at <= $2
), final_usage AS (
	SELECT * FROM ranked_usage WHERE audit_rn = 1
)
`

func (db *DB) codexAuditRouteSummary(ctx context.Context, start, end time.Time) (CodexAuditSummary, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	var summary CodexAuditSummary
	err := db.conn.QueryRowContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_source, '') = 'direct' THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_source, '') = 'pin' THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_source, '') NOT IN ('direct', 'pin') THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' AND (status_code >= 500 OR COALESCE(upstream_error_kind, '') IN ('no_available_relay_account', 'relay_route_unavailable', 'relay_affinity_unavailable', 'route_switch_requires_replay')) THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(upstream_error_kind, '') IN ('no_available_relay_account', 'relay_route_unavailable', 'relay_affinity_unavailable', 'route_switch_requires_replay') THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(logical_request_id, '') = '' THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN COALESCE(logical_request_id, '') <> '' AND (
		      (COALESCE(route_class, '') = 'cyb_relay' AND account_id > 0 AND COALESCE(upstream_account_type, '') <> 'openai_responses') OR
		      (COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) <= 0) OR
		      (COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_source, '') NOT IN ('direct', 'pin')) OR
		      (COALESCE(route_source, '') = 'pin' AND COALESCE(pin_kind, '') = '') OR
		      (COALESCE(route_source, '') = 'direct' AND COALESCE(route_signals, '[]') IN ('', '[]', 'null')) OR
		      (COALESCE(route_source, '') = 'pin' AND COALESCE(route_signals, '[]') NOT IN ('', '[]', 'null')) OR
		      (COALESCE(route_source, '') IN ('direct', 'pin') AND COALESCE(route_class, '') <> 'cyb_relay')
		  ) THEN 1 ELSE 0 END), 0),
		  (SELECT COUNT(DISTINCT audit_request_id) FROM ranked_usage WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy' AND COALESCE(upstream_account_type, '') = 'oauth'),
		  (SELECT COUNT(*) FROM ranked_usage WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy' AND COALESCE(upstream_account_type, '') = 'oauth'),
		  (SELECT COUNT(DISTINCT audit_request_id) FROM ranked_usage
		   WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy'
		     AND COALESCE(upstream_account_type, '') = 'openai_responses'
		     AND COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) > 0),
		  (SELECT COUNT(*) FROM ranked_usage
		   WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy'
		     AND COALESCE(upstream_account_type, '') = 'openai_responses'
		     AND COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) > 0),
		  (SELECT COUNT(*) FROM ranked_usage
		   WHERE LOWER(COALESCE(upstream_error_kind, '')) = 'cyber_policy'
		     AND NOT (
		       COALESCE(upstream_account_type, '') = 'oauth' OR
		       (COALESCE(upstream_account_type, '') = 'openai_responses'
		        AND COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) > 0)
		     ))
		FROM final_usage
	`, startArg, endArg).Scan(
		&summary.RelayRequests,
		&summary.RelayDirect,
		&summary.RelayPinned,
		&summary.RelayLegacyUnknown,
		&summary.RelayRouteFailures,
		&summary.RelayFallbackPrevented,
		&summary.LegacyUsageRows,
		&summary.RouteInvariantViolations,
		&summary.OAuthCyberMissRequests,
		&summary.OAuthCyberMissAttempts,
		&summary.RelayCyberRequests,
		&summary.RelayCyberAttempts,
		&summary.LegacyCyberUnattributed,
	)
	return summary, err
}

func mergeCodexAuditRouteSummary(target *CodexAuditSummary, route CodexAuditSummary) {
	if target == nil {
		return
	}
	target.RelayRequests = route.RelayRequests
	target.RelayDirect = route.RelayDirect
	target.RelayPinned = route.RelayPinned
	target.RelayLegacyUnknown = route.RelayLegacyUnknown
	target.RelayRouteFailures = route.RelayRouteFailures
	target.RelayFallbackPrevented = route.RelayFallbackPrevented
	target.OAuthCyberMissRequests = route.OAuthCyberMissRequests
	target.OAuthCyberMissAttempts = route.OAuthCyberMissAttempts
	target.RelayCyberRequests = route.RelayCyberRequests
	target.RelayCyberAttempts = route.RelayCyberAttempts
	target.LegacyCyberUnattributed = route.LegacyCyberUnattributed
	target.RouteInvariantViolations = route.RouteInvariantViolations
	target.LegacyUsageRows = route.LegacyUsageRows
	// Backward-compatible aggregate now follows the protected OAuth scope only;
	// Relay provider policy events must never re-enter the leak counter.
	target.UpstreamCyberPolicy = route.OAuthCyberMissAttempts
}

func (db *DB) codexAuditRelayRouteRows(ctx context.Context, start, end time.Time) ([]CodexAuditRelayRouteRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT r.account_id, COALESCE(a.name, ''), COALESCE(r.route_source, ''), COALESCE(r.pin_kind, ''),
		       COUNT(DISTINCT CASE WHEN r.audit_rn = 1 THEN r.audit_request_id END),
		       COUNT(*),
		       COALESCE(SUM(CASE WHEN r.audit_rn = 1 AND r.status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN r.audit_rn = 1 AND r.status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN r.audit_rn = 1 AND r.status_code >= 500 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN LOWER(COALESCE(r.upstream_error_kind, '')) = 'cyber_policy'
		                              AND COALESCE(r.upstream_account_type, '') = 'openai_responses'
		                              AND COALESCE(r.route_class, '') = 'cyb_relay'
		                              AND COALESCE(r.route_group_id, 0) > 0
		                         THEN 1 ELSE 0 END), 0)
		FROM ranked_usage r
		LEFT JOIN accounts a ON a.id = r.account_id
		WHERE COALESCE(r.route_class, '') = 'cyb_relay'
		GROUP BY r.account_id, COALESCE(a.name, ''), COALESCE(r.route_source, ''), COALESCE(r.pin_kind, '')
		ORDER BY COUNT(DISTINCT CASE WHEN r.audit_rn = 1 THEN r.audit_request_id END) DESC, r.account_id
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CodexAuditRelayRouteRow, 0)
	for rows.Next() {
		var item CodexAuditRelayRouteRow
		if err := rows.Scan(&item.AccountID, &item.AccountName, &item.RouteSource, &item.PinKind, &item.Requests, &item.Attempts, &item.Successes, &item.Errors4xx, &item.Errors5xx, &item.CyberPolicy); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (db *DB) codexAuditRouteSignalRows(ctx context.Context, start, end time.Time) ([]CodexAuditRouteSignalRow, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`
		SELECT COALESCE(route_signals, '[]'), created_at
		FROM final_usage
		WHERE COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_source, '') = 'direct'
		ORDER BY created_at DESC
		LIMIT 100000
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type aggregate struct {
		count int64
		last  time.Time
	}
	aggregates := map[string]aggregate{}
	for rows.Next() {
		var rawSignals string
		var createdRaw any
		if err := rows.Scan(&rawSignals, &createdRaw); err != nil {
			return nil, err
		}
		created, err := parseDBTimeValue(createdRaw)
		if err != nil {
			continue
		}
		var signals []string
		if err := json.Unmarshal([]byte(rawSignals), &signals); err != nil {
			if fallback := strings.TrimSpace(rawSignals); fallback != "" && fallback != "[]" {
				signals = []string{fallback}
			}
		}
		seen := map[string]struct{}{}
		for _, signal := range signals {
			signal = strings.TrimSpace(signal)
			if signal == "" {
				continue
			}
			if _, ok := seen[signal]; ok {
				continue
			}
			seen[signal] = struct{}{}
			item := aggregates[signal]
			item.count++
			if item.last.IsZero() || created.After(item.last) {
				item.last = created
			}
			aggregates[signal] = item
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]CodexAuditRouteSignalRow, 0, len(aggregates))
	for signal, item := range aggregates {
		result = append(result, CodexAuditRouteSignalRow{Signal: signal, Requests: item.count, LastSeen: item.last})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Requests == result[j].Requests {
			return result[i].Signal < result[j].Signal
		}
		return result[i].Requests > result[j].Requests
	})
	return result, nil
}

func summarizeCodexAudit(report *CodexAuditReport) CodexAuditSummary {
	var summary CodexAuditSummary
	for _, row := range report.PromptFilter {
		summary.PromptLogs += row.Count
		if row.Action == "block" {
			summary.PromptBlocks += row.Count
		}
		if row.ReviewFlagged {
			summary.ReviewFlagged += row.Count
		}
		summary.ReviewErrors += row.ReviewErrors
		if row.Source == "upstream_cyber_policy" {
			summary.UpstreamCyberPolicy += row.Count
		}
		if row.Source == "session_bleed" {
			summary.SessionBleed += row.Count
		}
		if row.Source == "semantic_review_disagreement" {
			summary.SemanticDisagreements += row.Count
			if row.Action == "block" {
				summary.SemanticDisagreementBlocks += row.Count
			}
		}
		if row.Source == "local_probe_observed" {
			summary.ProbeObserved += row.Count
		}
		if row.Action == "allow" && row.ReviewModel != "" && !row.ReviewFlagged && row.MaxScore >= 50 {
			summary.HighScoreAllowed += row.Count
		}
	}
	for _, row := range report.ProbeShortCircuits {
		summary.ProbeShortCircuits += row.Count
	}
	for _, row := range report.ProbeHighFrequency {
		summary.ProbeHighFrequency += row.Count
	}
	return summary
}

func codexAuditVerdict(report *CodexAuditReport) string {
	switch {
	case report.Summary.OAuthCyberMissAttempts > 0:
		return "oauth_cyber_risk"
	case report.Summary.RouteInvariantViolations > 0:
		return "route_invariant_violation"
	case report.Summary.RelayRouteFailures > 0 || report.Usage.Errors5xx > 0:
		return "operational_issue"
	case report.Summary.RelayCyberAttempts > 0:
		return "relay_quality_issue"
	default:
		return "normal"
	}
}

func percentileInt(values []int, p float64) int {
	if len(values) == 0 {
		return 0
	}
	sort.Ints(values)
	if p <= 0 {
		return values[0]
	}
	if p >= 1 {
		return values[len(values)-1]
	}
	pos := p * float64(len(values)-1)
	lower := int(math.Floor(pos))
	upper := int(math.Ceil(pos))
	if lower == upper {
		return values[lower]
	}
	weight := pos - float64(lower)
	return int(math.Round(float64(values[lower])*(1-weight) + float64(values[upper])*weight))
}
