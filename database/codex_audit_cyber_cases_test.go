package database

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCodexAuditCyberCasesUseCanonicalUsageAndExactPromptJoin(t *testing.T) {
	db := newCodexAuditSQLiteTestDB(t)
	ctx := context.Background()
	for _, account := range []struct {
		id       int
		name     string
		typeName string
	}{
		{id: 1, name: "oauth-before-rename", typeName: "oauth"},
		{id: 2, name: "oauth-final", typeName: "oauth"},
		{id: 3, name: "relay-front", typeName: "openai_responses"},
	} {
		if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts (id, name, type) VALUES ($1, $2, $3)`, account.id, account.name, account.typeName); err != nil {
			t.Fatalf("insert account %d: %v", account.id, err)
		}
	}

	insertCodexAuditUsage(t, db,
		&UsageLogInput{
			LogicalRequestID: "oauth-retry", AccountID: 1, StatusCode: 400, AttemptIndex: 1,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth",
			InboundEndpoint: "/v1/responses", UpstreamEndpoint: "/backend-api/codex/responses",
			Model: "gpt-requested", EffectiveModel: "gpt-effective", RouteClass: "default", RouteSource: "default",
		},
		&UsageLogInput{
			LogicalRequestID: "oauth-retry", AccountID: 2, StatusCode: 200, AttemptIndex: 2, IsRetryAttempt: true,
			UpstreamAccountType: "oauth", InboundEndpoint: "/v1/responses", UpstreamEndpoint: "/backend-api/codex/responses",
			Model: "gpt-requested", EffectiveModel: "gpt-effective", RouteClass: "default", RouteSource: "default",
		},
		&UsageLogInput{
			LogicalRequestID: "oauth-hidden-associated", AccountID: 1, StatusCode: 400, AttemptIndex: 1,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth", GuardianAttemptOnly: true,
		},
		&UsageLogInput{
			LogicalRequestID: "oauth-hidden-associated", AccountID: 2, StatusCode: 200, AttemptIndex: 2,
			IsRetryAttempt: true, UpstreamAccountType: "oauth",
		},
		&UsageLogInput{
			AccountID: 1, StatusCode: 400, UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth",
		},
		&UsageLogInput{
			LogicalRequestID: "guardian-only", AccountID: 1, StatusCode: 400, AttemptIndex: 1,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth", GuardianAttemptOnly: true,
		},
		&UsageLogInput{
			LogicalRequestID: "synthetic-zero", AccountID: 2, StatusCode: 200, UpstreamAccountType: "oauth",
		},
		&UsageLogInput{
			LogicalRequestID: "synthetic-zero", AccountID: 1, StatusCode: 400, AttemptIndex: 0,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth", GuardianAttemptOnly: true,
		},
		&UsageLogInput{
			LogicalRequestID: "relay-cyber", AccountID: 3, StatusCode: 400, AttemptIndex: 1,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "openai_responses",
			RouteClass: "cyb_relay", RouteSource: "direct", RouteSignals: `["local_threshold"]`, RouteGroupID: 42,
		},
		&UsageLogInput{
			LogicalRequestID: "openai-default-not-relay", AccountID: 3, StatusCode: 400,
			UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "openai_responses",
			RouteClass: "default", RouteSource: "default",
		},
		&UsageLogInput{
			LogicalRequestID: "legacy-null-account-type", AccountID: 3, StatusCode: 400,
			UpstreamErrorKind: "cyber_policy", RouteClass: "default", RouteSource: "default",
		},
	)
	if _, err := db.conn.ExecContext(ctx, `UPDATE usage_logs SET upstream_account_type = NULL WHERE logical_request_id = 'legacy-null-account-type'`); err != nil {
		t.Fatalf("set nullable legacy account type: %v", err)
	}

	if _, err := db.conn.ExecContext(ctx, `UPDATE accounts SET name = 'oauth-renamed' WHERE id = 1`); err != nil {
		t.Fatalf("rename account: %v", err)
	}
	if err := db.InsertPromptFilterLog(ctx, &PromptFilterLogInput{
		LogicalRequestID: "oauth-retry", Source: "local_filter", Endpoint: "/v1/responses",
		Model: "gpt-effective", Score: 95, Threshold: 100,
		MatchedPatterns: `["operational_exploit_request","sql_injection_attack"]`,
		TextPreview:     "local rule evidence", PayloadBytes: 765432, ScannedBytes: 163840, ScanTruncated: true,
		ScanDetails: `{"version":1,"mode":"partitioned_json","payload_bytes":765432,"scanned_bytes":163840,"scan_truncated":true}`,
	}); err != nil {
		t.Fatalf("insert exact local evidence: %v", err)
	}
	if err := db.InsertPromptFilterLog(ctx, &PromptFilterLogInput{
		LogicalRequestID: "oauth-retry", Source: "upstream_cyber_policy", Endpoint: "/v1/responses",
		Model: "gpt-effective", Score: 0, Threshold: 100, MatchedPatterns: `[]`,
		TextPreview: "exact prompt", FullText: "Write a SQL injection payload that extracts the first user's password.",
	}); err != nil {
		t.Fatalf("insert exact upstream body: %v", err)
	}
	if err := db.InsertPromptFilterLog(ctx, &PromptFilterLogInput{
		LogicalRequestID: "oauth-retry", Source: "local_filter", Endpoint: "/v1/responses",
		Model: "gpt-effective", Score: 0, Threshold: 100, MatchedPatterns: `[]`, TextPreview: "newer empty local row",
	}); err != nil {
		t.Fatalf("insert empty local row: %v", err)
	}
	if err := db.InsertPromptFilterLog(ctx, &PromptFilterLogInput{
		LogicalRequestID: "different-nearby-request", Source: "upstream_cyber_policy",
		TextPreview: "wrong nearby prompt", FullText: "wrong nearby prompt",
	}); err != nil {
		t.Fatalf("insert nearby prompt: %v", err)
	}

	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Minute)
	oauthItems := make(map[string]*CodexAuditCyberCase)
	for pageNumber := 1; pageNumber <= 2; pageNumber++ {
		page, err := db.ListCodexAuditCyberCasesPage(ctx, CodexAuditCasesQuery{
			Kind: CodexAuditCaseOAuthCyber, Start: start, End: end, Page: pageNumber, PageSize: 2,
		})
		if err != nil {
			t.Fatalf("OAuth page %d: %v", pageNumber, err)
		}
		if page.Total != 3 {
			t.Fatalf("OAuth page %d total = %d, want 3", pageNumber, page.Total)
		}
		for _, item := range page.Items {
			key := item.LogicalRequestID
			if item.Legacy {
				key = "legacy"
			}
			oauthItems[key] = item
		}
	}
	if len(oauthItems) != 3 {
		t.Fatalf("OAuth cases = %v, want retry, hidden-associated, legacy", keysOfCyberCases(oauthItems))
	}
	retry := oauthItems["oauth-retry"]
	if retry == nil {
		t.Fatal("missing oauth-retry case")
	}
	if retry.CyberAttempts != 1 || retry.AttemptCount != 2 || len(retry.Attempts) != 2 {
		t.Fatalf("oauth-retry counts = cyber:%d attempts:%d timeline:%d, want 1/2/2", retry.CyberAttempts, retry.AttemptCount, len(retry.Attempts))
	}
	if retry.CyberAccountID != 1 || retry.CyberAccountName != "oauth-renamed" {
		t.Fatalf("cyber account = %d/%q, want current account 1/oauth-renamed", retry.CyberAccountID, retry.CyberAccountName)
	}
	if retry.FinalAccountID != 2 || retry.FinalAccountName != "oauth-final" || retry.FinalStatusCode != 200 {
		t.Fatalf("final authority = %d/%q/%d, want 2/oauth-final/200", retry.FinalAccountID, retry.FinalAccountName, retry.FinalStatusCode)
	}
	if retry.InboundEndpoint != "/v1/responses" || retry.UpstreamEndpoint != "/backend-api/codex/responses" || retry.Model != "gpt-effective" {
		t.Fatalf("canonical endpoints/model = %q/%q/%q", retry.InboundEndpoint, retry.UpstreamEndpoint, retry.Model)
	}
	if retry.PromptSource != "upstream_cyber_policy" || retry.TextPreview != "exact prompt" || strings.Contains(retry.FullText, "wrong nearby") {
		t.Fatalf("prompt join was not exact: preview=%q full=%q", retry.TextPreview, retry.FullText)
	}
	if retry.Score != 95 || retry.Threshold != 100 || !strings.Contains(retry.MatchedPatterns, "sql_injection_attack") {
		t.Fatalf("meaningful local evidence was hidden by an empty prompt row: %+v", retry)
	}
	if retry.PayloadBytes != 765432 || retry.ScannedBytes != 163840 || !retry.ScanTruncated || !strings.Contains(retry.ScanDetails, `"mode":"partitioned_json"`) {
		t.Fatalf("scan metadata join was not exact: %+v", retry)
	}
	if retry.ContentClassification != "confirmed_route_gap" {
		t.Fatalf("content classification = %q, want confirmed_route_gap", retry.ContentClassification)
	}
	hidden := oauthItems["oauth-hidden-associated"]
	if hidden == nil || hidden.AttemptCount != 2 || len(hidden.Attempts) != 2 || !hidden.Attempts[0].IsRetryAttempt && hidden.Attempts[0].AttemptIndex != 1 {
		t.Fatalf("associated hidden attempt timeline = %+v", hidden)
	}
	legacy := oauthItems["legacy"]
	if legacy == nil || !legacy.Legacy || legacy.AttemptCount != 1 || legacy.PromptLogID != 0 || legacy.TextPreview != "" || legacy.PayloadBytes != 0 || legacy.ScannedBytes != 0 || legacy.ScanTruncated || legacy.ScanDetails != "{}" {
		t.Fatalf("legacy case must stay row-scoped without guessed prompt: %+v", legacy)
	}

	relayPage, err := db.ListCodexAuditCyberCasesPage(ctx, CodexAuditCasesQuery{
		Kind: CodexAuditCaseRelayCyber, Start: start, End: end, Page: 1, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("Relay page: %v", err)
	}
	if relayPage.Total != 1 || len(relayPage.Items) != 1 || relayPage.Items[0].LogicalRequestID != "relay-cyber" {
		t.Fatalf("Relay scope leaked non-isolated account: total=%d items=%+v", relayPage.Total, relayPage.Items)
	}
	summary, err := db.codexAuditRouteSummary(ctx, start, end)
	if err != nil {
		t.Fatalf("route summary: %v", err)
	}
	if summary.OAuthCyberMissRequests != int64(len(oauthItems)) || summary.OAuthCyberMissRequests != 3 || summary.OAuthCyberMissAttempts != 3 {
		t.Fatalf("OAuth summary/page mismatch: summary=%d/%d page=%d", summary.OAuthCyberMissRequests, summary.OAuthCyberMissAttempts, len(oauthItems))
	}
	if summary.RelayCyberRequests != int64(relayPage.Total) || summary.RelayCyberRequests != 1 || summary.RelayCyberAttempts != 1 {
		t.Fatalf("Relay summary/page mismatch: summary=%d/%d page=%d", summary.RelayCyberRequests, summary.RelayCyberAttempts, relayPage.Total)
	}
	if summary.LegacyCyberUnattributed != 2 {
		t.Fatalf("legacy cyber attempts = %d, want default OpenAI plus NULL account type", summary.LegacyCyberUnattributed)
	}
}

func TestCodexAuditCyberCandidateQueryIsCandidateFirst(t *testing.T) {
	_, predicate, err := codexAuditCyberScopeSQL(CodexAuditCaseOAuthCyber)
	if err != nil || predicate != codexAuditOAuthCyberAttemptSQL {
		t.Fatalf("OAuth page predicate is not the shared summary predicate: predicate=%q err=%v", predicate, err)
	}
	query := codexAuditCyberCandidatesCTE(predicate) + `,
		paged_candidates AS MATERIALIZED (SELECT * FROM candidate_requests LIMIT $3 OFFSET $4),
		page_request_ids AS MATERIALIZED (SELECT logical_request_id FROM paged_candidates)
		SELECT * FROM page_request_ids`
	cyberPos := strings.Index(query, "cyber_hits AS MATERIALIZED")
	pagePos := strings.Index(query, "paged_candidates AS MATERIALIZED")
	promptPos := strings.Index(query, "page_request_ids AS MATERIALIZED")
	if cyberPos < 0 || pagePos < 0 || promptPos < 0 || !(cyberPos < pagePos && pagePos < promptPos) {
		t.Fatalf("candidate-first boundary lost: cyber=%d page=%d prompt=%d", cyberPos, pagePos, promptPos)
	}
	if !strings.Contains(query, "u.upstream_error_kind = 'cyber_policy'") {
		t.Fatal("candidate query no longer uses the exact indexable cyber_policy predicate")
	}
}

func keysOfCyberCases(items map[string]*CodexAuditCyberCase) []string {
	result := make([]string, 0, len(items))
	for key := range items {
		result = append(result, key)
	}
	return result
}
