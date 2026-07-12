package database

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
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

func TestCodexAuditRelayFailoverSummary(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	insertCodexAuditUsage(t, db,
		&UsageLogInput{LogicalRequestID: "relay-recovered", AccountID: 50, StatusCode: 502, AttemptIndex: 1, RouteClass: "cyb_relay", RouteSource: "direct", RouteGroupID: 3, UpstreamAccountType: "openai_responses", UpstreamErrorKind: "server"},
		&UsageLogInput{LogicalRequestID: "relay-recovered", AccountID: 53, StatusCode: 200, AttemptIndex: 2, IsRetryAttempt: true, RouteClass: "cyb_relay", RouteSource: "direct", RouteGroupID: 3, UpstreamAccountType: "openai_responses"},
		&UsageLogInput{LogicalRequestID: "relay-exhausted", AccountID: 50, StatusCode: 502, AttemptIndex: 1, RouteClass: "cyb_relay", RouteSource: "probe", RouteGroupID: 3, UpstreamAccountType: "openai_responses", UpstreamErrorKind: "server"},
		&UsageLogInput{LogicalRequestID: "relay-exhausted", AccountID: 53, StatusCode: 504, AttemptIndex: 2, IsRetryAttempt: true, RouteClass: "cyb_relay", RouteSource: "probe", RouteGroupID: 3, UpstreamAccountType: "openai_responses", UpstreamErrorKind: "server"},
		&UsageLogInput{LogicalRequestID: "relay-direct-success", AccountID: 53, StatusCode: 200, AttemptIndex: 1, RouteClass: "cyb_relay", RouteSource: "direct", RouteGroupID: 3, UpstreamAccountType: "openai_responses"},
	)
	report := buildCodexAuditTestReport(t, db)
	if report.Summary.RelayFailovers != 2 || report.Summary.RelayFailoverSuccesses != 1 || report.Summary.RelayFailoverFailures != 1 || report.Summary.RelayAbsorbed5xx != 1 {
		t.Fatalf("relay failovers = total:%d success:%d failure:%d absorbed:%d, want 2/1/1/1",
			report.Summary.RelayFailovers, report.Summary.RelayFailoverSuccesses,
			report.Summary.RelayFailoverFailures, report.Summary.RelayAbsorbed5xx)
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

func TestCodexAuditReportAggregatesSixRelayCyberCasesWithoutOAuthLeakage(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	usageRows := make([]*UsageLogInput, 0, 6)
	for i := 0; i < 6; i++ {
		logicalID := fmt.Sprintf("relay-cyber-%d", i)
		usageRows = append(usageRows, &UsageLogInput{
			LogicalRequestID:    logicalID,
			AccountID:           500 + int64(i%2),
			StatusCode:          400,
			UpstreamErrorKind:   "cyber_policy",
			RouteClass:          "cyb_relay",
			RouteSource:         "direct",
			RouteSignals:        `["local_threshold"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		})
		if err := db.InsertPromptFilterLog(ctx, &PromptFilterLogInput{
			LogicalRequestID:    logicalID,
			Source:              "upstream_cyber_policy",
			Action:              "allow",
			ErrorCode:           "cyber_policy",
			RouteClass:          "cyb_relay",
			RouteSource:         "direct",
			RouteSignals:        `["local_threshold"]`,
			RouteGroupID:        42,
			UpstreamAccountType: "openai_responses",
		}); err != nil {
			t.Fatalf("insert relay cyber prompt %d: %v", i, err)
		}
	}
	insertCodexAuditUsage(t, db, usageRows...)

	report, err := db.BuildCodexAuditReport(ctx, CodexAuditQuery{
		Start:         now.Add(-24 * time.Hour),
		End:           now.Add(time.Minute),
		BucketMinutes: 60,
		Limit:         20,
	})
	if err != nil {
		t.Fatalf("BuildCodexAuditReport: %v", err)
	}
	if report.Summary.OAuthCyberMissRequests != 0 || report.Summary.OAuthCyberMissAttempts != 0 || len(report.OAuthCyberCases) != 0 {
		t.Fatalf("oauth cyber leaked from relay pool: requests=%d attempts=%d cases=%d",
			report.Summary.OAuthCyberMissRequests, report.Summary.OAuthCyberMissAttempts, len(report.OAuthCyberCases))
	}
	if report.Summary.RelayCyberRequests != 6 || report.Summary.RelayCyberAttempts != 6 || len(report.RelayCyberCases) != 6 {
		t.Fatalf("relay cyber report = requests:%d attempts:%d cases:%d, want 6/6/6",
			report.Summary.RelayCyberRequests, report.Summary.RelayCyberAttempts, len(report.RelayCyberCases))
	}
	if report.LastOAuthCyberPolicyAt != nil || report.LastRelayCyberPolicyAt == nil {
		t.Fatalf("last cyber timestamps = oauth:%v relay:%v, want nil/non-nil",
			report.LastOAuthCyberPolicyAt, report.LastRelayCyberPolicyAt)
	}
	if report.Verdict != "relay_quality_issue" {
		t.Fatalf("verdict = %q, want relay_quality_issue", report.Verdict)
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
			if len(item.AuditAttempts) != 2 || item.AuditAttempts[0].AccountID != 104 || item.AuditAttempts[0].StatusCode != 502 || item.AuditAttempts[1].AccountID != 105 || item.AuditAttempts[1].StatusCode != 200 {
				t.Fatalf("relay attempt timeline = %+v, want 104(502) -> 105(200)", item.AuditAttempts)
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

func TestCodexAuditRelayCasesHighVolumePagesBeforePromptEnrichment(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts (id, name, credentials) VALUES (500, 'bulk-relay', '{}')`); err != nil {
		t.Fatalf("insert relay account: %v", err)
	}
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin bulk fixture: %v", err)
	}
	usageStmt, err := tx.PrepareContext(ctx, `INSERT INTO usage_logs
		(logical_request_id, account_id, status_code, route_class, route_source, route_group_id, upstream_account_type, created_at)
		VALUES ($1, 500, 200, $2, $3, 42, $4, $5)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("prepare usage fixture: %v", err)
	}
	promptStmt, err := tx.PrepareContext(ctx, `INSERT INTO prompt_filter_logs
		(logical_request_id, source, action, full_text, route_class, route_source, route_group_id, upstream_account_type, created_at)
		VALUES ($1, 'cyb_relay_routed', 'route', $2, 'cyb_relay', 'direct', 42, 'openai_responses', $3)`)
	if err != nil {
		_ = usageStmt.Close()
		_ = tx.Rollback()
		t.Fatalf("prepare prompt fixture: %v", err)
	}
	largePayload := strings.Repeat("payload-", 512)
	const relayRows = 4000
	const defaultRows = 4000
	for i := 0; i < relayRows+defaultRows; i++ {
		logicalID := fmt.Sprintf("bulk-%05d", i)
		createdAt := now.Add(time.Duration(i) * time.Microsecond)
		routeClass, routeSource, accountType := "default", "default", "oauth"
		if i < relayRows {
			routeClass, routeSource, accountType = "cyb_relay", "direct", "openai_responses"
		}
		if _, err := usageStmt.ExecContext(ctx, logicalID, routeClass, routeSource, accountType, db.timeArg(createdAt)); err != nil {
			_ = promptStmt.Close()
			_ = usageStmt.Close()
			_ = tx.Rollback()
			t.Fatalf("insert usage fixture %d: %v", i, err)
		}
		if i < relayRows {
			if _, err := promptStmt.ExecContext(ctx, logicalID, largePayload, db.timeArg(createdAt)); err != nil {
				_ = promptStmt.Close()
				_ = usageStmt.Close()
				_ = tx.Rollback()
				t.Fatalf("insert prompt fixture %d: %v", i, err)
			}
		}
	}
	_ = promptStmt.Close()
	_ = usageStmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit bulk fixture: %v", err)
	}

	// Keep the deadline generous enough for the race detector's SQLite
	// instrumentation. Production PostgreSQL latency is guarded separately by
	// the real-volume EXPLAIN regression used for this query shape.
	queryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := db.ListCodexAuditCasesPage(queryCtx, CodexAuditCasesQuery{
		Kind:     CodexAuditCaseRelayRoute,
		Start:    now.Add(-time.Minute),
		End:      now.Add(time.Minute),
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("high-volume relay page: %v", err)
	}
	if page.Total != relayRows || len(page.Items) != 20 {
		t.Fatalf("high-volume page = total:%d items:%d, want %d/20", page.Total, len(page.Items), relayRows)
	}
	for _, item := range page.Items {
		if item.RouteClass != "cyb_relay" || item.AccountName != "bulk-relay" || item.FullText != largePayload {
			t.Fatalf("page enrichment mismatch: id=%s route=%s account=%s payload_bytes=%d",
				item.LogicalRequestID, item.RouteClass, item.AccountName, len(item.FullText))
		}
	}
}

func TestCodexAuditVerdictPreservesGlobal5xxCompatibility(t *testing.T) {
	report := &CodexAuditReport{
		Usage:   CodexAuditUsageSummary{Errors5xx: 1},
		Summary: CodexAuditSummary{},
	}
	if got := codexAuditVerdict(report); got != "operational_issue" {
		t.Fatalf("default-route 5xx verdict = %q, want operational_issue", got)
	}
	report.Usage.Errors5xx = 0
	report.Summary.RelayRouteFailures = 1
	if got := codexAuditVerdict(report); got != "operational_issue" {
		t.Fatalf("relay failure verdict = %q, want operational_issue", got)
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
