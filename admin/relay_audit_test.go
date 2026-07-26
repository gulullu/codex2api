package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestRelayAuditEndpointsValidateWindowAndKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "relay-audit-admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := &Handler{db: db}

	for _, test := range []struct {
		name       string
		path       string
		invoke     func(*gin.Context)
		wantStatus int
	}{
		{
			name: "report", path: "/api/admin/relay-audit/report?hours=1&bucket_minutes=5",
			invoke: handler.GetRelayAuditReport, wantStatus: http.StatusOK,
		},
		{
			name: "oversized window", path: "/api/admin/relay-audit/report?hours=169",
			invoke: handler.GetRelayAuditReport, wantStatus: http.StatusBadRequest,
		},
		{
			name: "partial explicit range", path: "/api/admin/relay-audit/report?start=2026-07-27T00:00:00Z",
			invoke: handler.GetRelayAuditReport, wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid case kind", path: "/api/admin/relay-audit/cases?hours=1&kind=unknown",
			invoke: handler.GetRelayAuditCases, wantStatus: http.StatusBadRequest,
		},
		{
			name: "cases", path: "/api/admin/relay-audit/cases?hours=1&kind=relay_route&page=1&page_size=20",
			invoke: handler.GetRelayAuditCases, wantStatus: http.StatusOK,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, test.path, nil)
			test.invoke(ctx)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}
