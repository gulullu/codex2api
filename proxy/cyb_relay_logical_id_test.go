package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/codex2api/api"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestLogicalRequestIDIsServerOwnedAndStablePerTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request.Header.Set("X-Request-ID", "client-controlled-id")
	c.Set("request_context", &api.RequestContext{RequestID: "client-controlled-id"})

	first := logicalRequestID(c)
	if first == "" || first == "client-controlled-id" {
		t.Fatalf("logicalRequestID = %q, want a server-generated ID", first)
	}
	if _, err := uuid.Parse(first); err != nil {
		t.Fatalf("logicalRequestID = %q, want UUID: %v", first, err)
	}
	if got := logicalRequestID(c); got != first {
		t.Fatalf("logicalRequestID changed within one turn: first=%q got=%q", first, got)
	}

	second := beginLogicalRequest(c)
	if second == first {
		t.Fatalf("beginLogicalRequest reused previous turn ID %q", first)
	}
	if got := logicalRequestID(c); got != second {
		t.Fatalf("logicalRequestID = %q after new turn, want %q", got, second)
	}
}
