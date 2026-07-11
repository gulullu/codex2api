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
	for _, input := range []*database.PromptFilterLogInput{
		{LogicalRequestID: "relay-one", Source: "cyb_relay_routed"},
		{LogicalRequestID: "relay-two", Source: "cyb_relay_routed"},
		{LogicalRequestID: "bleed-one", Source: "session_bleed"},
	} {
		if err := db.InsertPromptFilterLog(context.Background(), input); err != nil {
			t.Fatalf("InsertPromptFilterLog: %v", err)
		}
	}

	start := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	end := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
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
