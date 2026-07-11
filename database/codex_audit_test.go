package database

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func newCodexAuditSQLiteTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "codex-audit.db"))
	if err != nil {
		t.Fatalf("New(sqlite) returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertCodexAuditUsage(t *testing.T, db *DB, rows ...*UsageLogInput) {
	t.Helper()
	ctx := context.Background()
	for _, row := range rows {
		if err := db.InsertUsageLog(ctx, row); err != nil {
			t.Fatalf("InsertUsageLog returned error: %v", err)
		}
	}
	db.flushLogs()
}

func buildCodexAuditTestReport(t *testing.T, db *DB) *CodexAuditReport {
	t.Helper()
	start := time.Now().Add(-time.Minute)
	end := time.Now().Add(time.Minute)
	ctx := context.Background()
	report := &CodexAuditReport{WindowStart: start, WindowEnd: end}
	var err error
	if report.Usage, err = db.codexAuditUsageSummary(ctx, start, end); err != nil {
		t.Fatalf("usage summary query returned error: %v", err)
	}
	if report.Timeline, err = db.codexAuditTimeline(ctx, start, end, 5); err != nil {
		t.Fatalf("timeline query returned error: %v", err)
	}
	if report.Models, err = db.codexAuditModels(ctx, start, end, 50); err != nil {
		t.Fatalf("models query returned error: %v", err)
	}
	if report.RelayRoutes, err = db.codexAuditRelayRouteRows(ctx, start, end); err != nil {
		t.Fatalf("relay routes query returned error: %v", err)
	}
	if report.RouteSignals, err = db.codexAuditRouteSignalRows(ctx, start, end); err != nil {
		t.Fatalf("route signals query returned error: %v", err)
	}
	if report.Summary, err = db.codexAuditRouteSummary(ctx, start, end); err != nil {
		t.Fatalf("route summary query returned error: %v", err)
	}
	if report.LastOAuthCyberPolicyAt, err = db.codexAuditLastCyberPolicyAt(ctx, end, "oauth"); err != nil {
		t.Fatalf("last oauth cyber query returned error: %v", err)
	}
	if report.LastRelayCyberPolicyAt, err = db.codexAuditLastCyberPolicyAt(ctx, end, "relay"); err != nil {
		t.Fatalf("last relay cyber query returned error: %v", err)
	}
	return report
}

func TestCodexAuditLogicalRequestDedupAndDistinctWebSocketTurns(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)

	insertCodexAuditUsage(t, db,
		&UsageLogInput{
			LogicalRequestID:  "retry-request",
			Model:             "gpt-5.4",
			EffectiveModel:    "gpt-5.4",
			StatusCode:        502,
			AttemptIndex:      1,
			IsRetryAttempt:    true,
			UpstreamErrorKind: "upstream_5xx",
		},
		&UsageLogInput{
			LogicalRequestID: "retry-request",
			Model:            "gpt-5.4",
			EffectiveModel:   "gpt-5.4",
			StatusCode:       200,
			FirstTokenMs:     120,
		},
		&UsageLogInput{
			LogicalRequestID: "ws-turn-1",
			Model:            "gpt-5.4",
			EffectiveModel:   "gpt-5.4",
			StatusCode:       200,
			FirstTokenMs:     80,
			ViaWebsocket:     true,
		},
		&UsageLogInput{
			LogicalRequestID: "ws-turn-2",
			Model:            "gpt-5.4",
			EffectiveModel:   "gpt-5.4",
			StatusCode:       200,
			FirstTokenMs:     90,
			ViaWebsocket:     true,
		},
	)

	report := buildCodexAuditTestReport(t, db)
	if report.Usage.Requests != 3 {
		t.Fatalf("logical requests = %d, want 3", report.Usage.Requests)
	}
	if report.Usage.UpstreamAttempts != 4 {
		t.Fatalf("upstream attempts = %d, want 4", report.Usage.UpstreamAttempts)
	}
	if report.Usage.Errors5xx != 0 {
		t.Fatalf("final 5xx requests = %d, want 0", report.Usage.Errors5xx)
	}
	if report.Usage.WebSocketRequests != 2 {
		t.Fatalf("websocket logical requests = %d, want 2", report.Usage.WebSocketRequests)
	}
	if report.Usage.FirstTokenSamples != 3 {
		t.Fatalf("first-token samples = %d, want 3", report.Usage.FirstTokenSamples)
	}

	var modelRequests int64
	for _, row := range report.Models {
		modelRequests += row.Requests
	}
	if modelRequests != 3 {
		t.Fatalf("model logical requests = %d, want 3", modelRequests)
	}
	var timelineRequests int64
	for _, point := range report.Timeline {
		timelineRequests += point.Requests
	}
	if timelineRequests != 3 {
		t.Fatalf("timeline logical requests = %d, want 3", timelineRequests)
	}
}

func TestCodexAuditRouteCyberAndUnavailableAccounting(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)

	insertCodexAuditUsage(t, db,
		&UsageLogInput{
			LogicalRequestID:    "relay-direct",
			AccountID:           101,
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteSource:         "direct",
			RouteSignals:        `["local_threshold"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			LogicalRequestID:    "relay-pin",
			AccountID:           101,
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteSource:         "pin",
			RouteSignals:        `[]`,
			PinKind:             "session_id",
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			AccountID:           101,
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			LogicalRequestID:  "relay-unavailable",
			StatusCode:        503,
			RouteClass:        "cyb_relay",
			RouteSource:       "direct",
			RouteSignals:      `["technical_cyber_intent"]`,
			RouteGroupID:      42,
			UpstreamErrorKind: "relay_route_unavailable",
		},
		&UsageLogInput{
			LogicalRequestID:    "oauth-cyber-then-success",
			AccountID:           201,
			StatusCode:          400,
			AttemptIndex:        1,
			IsRetryAttempt:      true,
			UpstreamErrorKind:   "cyber_policy",
			UpstreamAccountType: "oauth",
		},
		&UsageLogInput{
			LogicalRequestID:    "oauth-cyber-then-success",
			AccountID:           202,
			StatusCode:          200,
			UpstreamAccountType: "oauth",
		},
		&UsageLogInput{
			LogicalRequestID:    "isolated-relay-cyber",
			AccountID:           301,
			StatusCode:          400,
			UpstreamErrorKind:   "cyber_policy",
			RouteClass:          "cyb_relay",
			RouteSource:         "direct",
			RouteSignals:        `["explicit_high_risk_rule"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			LogicalRequestID:    "non-isolated-relay-cyber",
			AccountID:           401,
			StatusCode:          400,
			UpstreamErrorKind:   "cyber_policy",
			RouteClass:          "default",
			RouteSource:         "default",
			UpstreamAccountType: "openai_responses",
		},
	)

	report := buildCodexAuditTestReport(t, db)
	if report.Summary.RelayRequests != 5 || report.Summary.RelayDirect != 3 || report.Summary.RelayPinned != 1 || report.Summary.RelayLegacyUnknown != 1 {
		t.Fatalf("relay summary = requests:%d direct:%d pin:%d legacy:%d, want 5/3/1/1",
			report.Summary.RelayRequests, report.Summary.RelayDirect, report.Summary.RelayPinned, report.Summary.RelayLegacyUnknown)
	}
	if report.Summary.RelayRouteFailures != 1 || report.Summary.RelayFallbackPrevented != 1 {
		t.Fatalf("relay unavailable = failures:%d fallback_prevented:%d, want 1/1",
			report.Summary.RelayRouteFailures, report.Summary.RelayFallbackPrevented)
	}
	if report.Summary.OAuthCyberMissRequests != 1 || report.Summary.OAuthCyberMissAttempts != 1 {
		t.Fatalf("oauth cyber = requests:%d attempts:%d, want 1/1",
			report.Summary.OAuthCyberMissRequests, report.Summary.OAuthCyberMissAttempts)
	}
	if report.Summary.RelayCyberRequests != 1 || report.Summary.RelayCyberAttempts != 1 {
		t.Fatalf("isolated relay cyber = requests:%d attempts:%d, want 1/1",
			report.Summary.RelayCyberRequests, report.Summary.RelayCyberAttempts)
	}
	if report.Summary.LegacyCyberUnattributed != 1 {
		t.Fatalf("unattributed cyber = %d, want 1", report.Summary.LegacyCyberUnattributed)
	}
	if report.Summary.LegacyUsageRows != 1 {
		t.Fatalf("legacy usage rows = %d, want 1", report.Summary.LegacyUsageRows)
	}
	if report.Summary.RouteInvariantViolations != 0 {
		t.Fatalf("route invariant violations = %d, want 0", report.Summary.RouteInvariantViolations)
	}
	if report.LastOAuthCyberPolicyAt == nil || report.LastRelayCyberPolicyAt == nil {
		t.Fatalf("last cyber timestamps missing: oauth=%v relay=%v", report.LastOAuthCyberPolicyAt, report.LastRelayCyberPolicyAt)
	}

	var routeCyberAttempts int64
	for _, row := range report.RelayRoutes {
		routeCyberAttempts += row.CyberPolicy
	}
	if routeCyberAttempts != 1 {
		t.Fatalf("relay route cyber attempts = %d, want 1", routeCyberAttempts)
	}
	var oauthTimeline, relayTimeline int64
	for _, point := range report.Timeline {
		oauthTimeline += point.OAuthCyberAttempts
		relayTimeline += point.RelayCyberAttempts
	}
	if oauthTimeline != 1 || relayTimeline != 1 {
		t.Fatalf("timeline cyber attempts = oauth:%d relay:%d, want 1/1", oauthTimeline, relayTimeline)
	}
}

func TestPromptFilterCyberScopeSeparatesOAuthAndIsolatedRelay(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	ctx := context.Background()

	rows := []*PromptFilterLogInput{
		{
			LogicalRequestID:    "prompt-oauth",
			Source:              "upstream_cyber_policy",
			Action:              "allow",
			UpstreamAccountType: "oauth",
		},
		{
			LogicalRequestID:    "prompt-isolated-relay",
			Source:              "upstream_cyber_policy",
			Action:              "allow",
			RouteClass:          "cyb_relay",
			RouteSource:         "direct",
			RouteSignals:        `["local_threshold"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		{
			LogicalRequestID:    "prompt-non-isolated-relay",
			Source:              "upstream_cyber_policy",
			Action:              "allow",
			RouteClass:          "default",
			RouteSource:         "default",
			UpstreamAccountType: "openai_responses",
		},
	}
	for _, row := range rows {
		if err := db.InsertPromptFilterLog(ctx, row); err != nil {
			t.Fatalf("InsertPromptFilterLog returned error: %v", err)
		}
	}

	start := time.Now().Add(-time.Minute)
	end := time.Now().Add(time.Minute)
	oauthLogs, oauthTotal, err := db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{
		Page: 1, PageSize: 10, Source: "upstream_cyber_policy", CyberScope: "oauth", Start: start, End: end,
	})
	if err != nil {
		t.Fatalf("ListPromptFilterLogsPage(oauth) returned error: %v", err)
	}
	if oauthTotal != 1 || len(oauthLogs) != 1 || oauthLogs[0].LogicalRequestID != "prompt-oauth" {
		t.Fatalf("oauth cyber scope = total:%d logs:%v, want only prompt-oauth", oauthTotal, promptLogicalIDs(oauthLogs))
	}

	relayLogs, relayTotal, err := db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{
		Page: 1, PageSize: 10, Source: "upstream_cyber_policy", CyberScope: "relay", Start: start, End: end,
	})
	if err != nil {
		t.Fatalf("ListPromptFilterLogsPage(relay) returned error: %v", err)
	}
	if relayTotal != 1 || len(relayLogs) != 1 || relayLogs[0].LogicalRequestID != "prompt-isolated-relay" {
		t.Fatalf("relay cyber scope = total:%d logs:%v, want only prompt-isolated-relay", relayTotal, promptLogicalIDs(relayLogs))
	}
}

func promptLogicalIDs(logs []*PromptFilterLog) []string {
	result := make([]string, 0, len(logs))
	for _, log := range logs {
		result = append(result, log.LogicalRequestID)
	}
	return result
}

func TestCodexAuditRelayCasesCanonicalPaginationAndStableWindow(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts (id, name, credentials) VALUES (105, 'final-relay', '{}')`); err != nil {
		t.Fatalf("insert relay account: %v", err)
	}
	insertCodexAuditUsage(t, db,
		&UsageLogInput{LogicalRequestID: "duplicate", AccountID: 104, StatusCode: 502, RouteClass: "cyb_relay", RouteSource: "direct", RouteSignals: `["local_threshold"]`, RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "duplicate", AccountID: 105, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "continuation", RouteSignals: `["previous_response_owner"]`, RouteGroupID: 42, UpstreamAccountType: "openai_responses", Endpoint: "/v1/responses", EffectiveModel: "gpt-5.5", APIKeyID: 7, APIKeyName: "case-key"},
		&UsageLogInput{LogicalRequestID: "alpha", AccountID: 101, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "direct", RouteSignals: `["local_threshold"]`, RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "probe", AccountID: 102, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "probe", RouteSignals: `["probe_request"]`, RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "overflow", AccountID: 103, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "overflow", RouteSignals: `["oauth_no_dispatch_slot"]`, RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "pin", AccountID: 103, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "pin", PinKind: "prompt_cache_key", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{AccountID: 103, StatusCode: 200, RouteClass: "cyb_relay", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{AccountID: 103, StatusCode: 200, RouteClass: "cyb_relay", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "outside-window", AccountID: 103, StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "overflow", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "default-route", AccountID: 201, StatusCode: 200, RouteClass: "default", RouteSource: "default", UpstreamAccountType: "oauth"},
	)

	prompts := []*PromptFilterLogInput{
		{LogicalRequestID: "duplicate", Source: "cyb_relay_routed", FullText: "superseded", RouteSource: "direct", AccountID: 999},
		{LogicalRequestID: "duplicate", Source: "cyb_relay_routed", FullText: "canonical", RouteSource: "direct", AccountID: 999},
		{LogicalRequestID: "alpha", Source: "cyb_relay_routed", FullText: "alpha payload"},
		{LogicalRequestID: "probe", Source: "cyb_relay_routed", FullText: "probe payload"},
		{LogicalRequestID: "different-kind", Source: "session_bleed"},
	}
	for _, input := range prompts {
		if err := db.InsertPromptFilterLog(ctx, input); err != nil {
			t.Fatalf("InsertPromptFilterLog: %v", err)
		}
	}
	if _, err := db.conn.ExecContext(ctx, `UPDATE usage_logs SET created_at = $1`, db.timeArg(now)); err != nil {
		t.Fatalf("set stable usage created_at: %v", err)
	}
	if _, err := db.conn.ExecContext(ctx, `UPDATE prompt_filter_logs SET created_at = $1`, db.timeArg(now)); err != nil {
		t.Fatalf("set stable created_at: %v", err)
	}
	if _, err := db.conn.ExecContext(ctx, `UPDATE usage_logs SET created_at = $1 WHERE logical_request_id = 'outside-window'`, db.timeArg(now.Add(-2*time.Hour))); err != nil {
		t.Fatalf("move outside-window record: %v", err)
	}

	query := CodexAuditCasesQuery{
		Kind:     CodexAuditCaseRelayRoute,
		Start:    now.Add(-time.Minute),
		End:      now.Add(time.Minute),
		Page:     1,
		PageSize: 3,
	}
	page1, err := db.ListCodexAuditCasesPage(ctx, query)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if page1.Total != 7 || len(page1.Items) != 3 || page1.Page != 1 || page1.PageSize != 3 {
		t.Fatalf("page 1 metadata = total:%d len:%d page:%d size:%d, want 7/3/1/3", page1.Total, len(page1.Items), page1.Page, page1.PageSize)
	}

	all := append([]*PromptFilterLog{}, page1.Items...)
	for page := 2; page <= 3; page++ {
		query.Page = page
		result, err := db.ListCodexAuditCasesPage(ctx, query)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if result.Total != page1.Total || !result.WindowStart.Equal(page1.WindowStart) || !result.WindowEnd.Equal(page1.WindowEnd) {
			t.Fatalf("page %d changed total/window: %+v", page, result)
		}
		all = append(all, result.Items...)
	}
	if len(all) != 7 {
		t.Fatalf("combined canonical items = %d, want 7", len(all))
	}
	ids := make([]int64, 0, len(all))
	logicalCounts := map[string]int{}
	duplicateText := ""
	routeSources := map[string]int{}
	for _, item := range all {
		ids = append(ids, item.ID)
		logicalCounts[item.LogicalRequestID]++
		routeSources[item.RouteSource]++
		if item.LogicalRequestID == "duplicate" {
			duplicateText = item.FullText
			if item.RouteSource != "continuation" || item.AccountID != 105 || item.AccountName != "final-relay" || item.APIKeyID != 7 || item.APIKeyName != "case-key" {
				t.Fatalf("final usage metadata was not authoritative: %+v", item)
			}
		}
		if item.LogicalRequestID == "outside-window" || item.Source != "cyb_relay_routed" {
			t.Fatalf("unexpected item in relay window: %+v", item)
		}
	}
	if logicalCounts["duplicate"] != 1 || duplicateText != "canonical" {
		t.Fatalf("duplicate canonicalization = count:%d text:%q, want 1/canonical", logicalCounts["duplicate"], duplicateText)
	}
	for _, source := range []string{"direct", "probe", "overflow", "continuation", "pin", ""} {
		if routeSources[source] == 0 {
			t.Fatalf("missing final route source %q in cases: %v", source, routeSources)
		}
	}
	if !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] > ids[j] }) {
		t.Fatalf("case ids are not stably ordered descending: %v", ids)
	}
}

func TestCodexAuditSummaryCountsProbeAndOAuthOverflowRoutes(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	insertCodexAuditUsage(t, db,
		&UsageLogInput{
			LogicalRequestID:    "probe-route",
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteSource:         "probe",
			RouteSignals:        `["probe_request"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			LogicalRequestID:    "overflow-route",
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteSource:         "overflow",
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
		&UsageLogInput{
			LogicalRequestID:    "continuation-route",
			StatusCode:          200,
			RouteClass:          "cyb_relay",
			RouteSource:         "continuation",
			RouteSignals:        `["previous_response_owner"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		},
	)
	report := buildCodexAuditTestReport(t, db)
	if report.Summary.RelayProbe != 1 || report.Summary.RelayOverflow != 1 || report.Summary.RelayContinuation != 1 || report.Summary.RelayLegacyUnknown != 0 {
		t.Fatalf("new route sources = probe:%d overflow:%d continuation:%d legacy:%d, want 1/1/1/0", report.Summary.RelayProbe, report.Summary.RelayOverflow, report.Summary.RelayContinuation, report.Summary.RelayLegacyUnknown)
	}
	if report.Summary.RouteInvariantViolations != 0 {
		t.Fatalf("new route sources were treated as invariant violations: %d", report.Summary.RouteInvariantViolations)
	}
	var timelineContinuation int64
	for _, point := range report.Timeline {
		timelineContinuation += point.RelayContinuation
		if point.RelayLegacyUnknown != 0 {
			t.Fatalf("continuation leaked into timeline legacy bucket: %+v", point)
		}
	}
	if timelineContinuation != 1 {
		t.Fatalf("timeline continuation = %d, want 1", timelineContinuation)
	}
}
