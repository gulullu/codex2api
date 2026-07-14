package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestGetCodexAuditCasesUsesExplicitWindowAndPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	for _, input := range []*database.UsageLogInput{
		{LogicalRequestID: "relay-one", StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "direct", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
		{LogicalRequestID: "relay-two", StatusCode: 200, RouteClass: "cyb_relay", RouteSource: "overflow", RouteGroupID: 42, UpstreamAccountType: "openai_responses"},
	} {
		if err := db.InsertUsageLog(context.Background(), input); err != nil {
			t.Fatalf("InsertUsageLog: %v", err)
		}
	}

	start := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	end := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err := db.ListCodexAuditCasesPage(context.Background(), database.CodexAuditCasesQuery{
			Kind: database.CodexAuditCaseRelayRoute, Start: start, End: end, Page: 1, PageSize: 10,
		})
		if err == nil && result.Total == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage logs were not flushed before deadline: result=%+v err=%v", result, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	params := url.Values{
		"kind":      {database.CodexAuditCaseRelayRoute},
		"start":     {start.Format(time.RFC3339)},
		"end":       {end.Format(time.RFC3339)},
		"page":      {"2"},
		"page_size": {"1"},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/audit/codex2api/cases?"+params.Encode(), nil)
	(&Handler{db: db}).GetCodexAuditCases(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	var page database.CodexAuditCasesPage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if page.Total != 2 || page.Page != 2 || page.PageSize != 1 || len(page.Items) != 1 {
		t.Fatalf("page metadata = total:%d page:%d size:%d items:%d, want 2/2/1/1", page.Total, page.Page, page.PageSize, len(page.Items))
	}
	if page.Items[0].Source != "cyb_relay_routed" || !page.WindowStart.Equal(start) || !page.WindowEnd.Equal(end) {
		t.Fatalf("unexpected case response: %+v", page)
	}
}

func TestGetCodexAuditCasesServesCanonicalOAuthCyberPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	for _, input := range []*database.UsageLogInput{
		{
			LogicalRequestID: "oauth-cyber-retry", AccountID: 11, StatusCode: 400,
			AttemptIndex: 1, UpstreamErrorKind: "cyber_policy", UpstreamAccountType: "oauth",
		},
		{
			LogicalRequestID: "oauth-cyber-retry", AccountID: 12, StatusCode: 200,
			AttemptIndex: 2, IsRetryAttempt: true, UpstreamAccountType: "oauth",
		},
	} {
		if err := db.InsertUsageLog(context.Background(), input); err != nil {
			t.Fatalf("InsertUsageLog: %v", err)
		}
	}

	start := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	end := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err := db.ListCodexAuditCyberCasesPage(context.Background(), database.CodexAuditCasesQuery{
			Kind: database.CodexAuditCaseOAuthCyber, Start: start, End: end, Page: 1, PageSize: 10,
		})
		if err == nil && result.Total == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage logs were not flushed before deadline: result=%+v err=%v", result, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	params := url.Values{
		"kind":      {database.CodexAuditCaseOAuthCyber},
		"start":     {start.Format(time.RFC3339)},
		"end":       {end.Format(time.RFC3339)},
		"page":      {"1"},
		"page_size": {"5"},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/audit/codex2api/cases?"+params.Encode(), nil)
	(&Handler{db: db}).GetCodexAuditCases(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	var page database.CodexAuditCyberCasesPage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if page.Total != 1 || page.Page != 1 || page.PageSize != 5 || len(page.Items) != 1 {
		t.Fatalf("page metadata = total:%d page:%d size:%d items:%d, want 1/1/5/1", page.Total, page.Page, page.PageSize, len(page.Items))
	}
	item := page.Items[0]
	if item.LogicalRequestID != "oauth-cyber-retry" || item.CyberAttempts != 1 || item.AttemptCount != 2 || item.FinalStatusCode != 200 {
		t.Fatalf("unexpected canonical cyber case: %+v", item)
	}
}

func TestGetCodexAuditCasesRejectsInvalidKindAndWindow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &Handler{db: newTestAdminDB(t)}

	for _, rawURL := range []string{
		"/api/admin/audit/codex2api/cases?kind=unknown",
		"/api/admin/audit/codex2api/cases?kind=relay_route&start=2026-07-12T03:00:00Z&end=2026-07-12T02:00:00Z",
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, rawURL, nil)
		handler.GetCodexAuditCases(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400 body=%s", rawURL, recorder.Code, recorder.Body.String())
		}
	}
}
