package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

type finalCancelAfterWriteGinWriter struct {
	gin.ResponseWriter
	cancel context.CancelFunc
}

func (w *finalCancelAfterWriteGinWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil && n == len(data) && w.cancel != nil {
		w.cancel()
	}
	return n, err
}

func (w *finalCancelAfterWriteGinWriter) WriteString(data string) (int, error) {
	n, err := w.ResponseWriter.WriteString(data)
	if err == nil && n == len(data) && w.cancel != nil {
		w.cancel()
	}
	return n, err
}

type finalShortWriteGinWriter struct{ gin.ResponseWriter }

func (w *finalShortWriteGinWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func (w *finalShortWriteGinWriter) WriteString(data string) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func TestPublishHTTPFinalWithAuditUsesSynchronousWriteBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("complete write is canonical", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		canonical, hidden := 0, 0
		delivered := publishHTTPFinalWithAudit(c,
			func() { c.Data(http.StatusBadGateway, "application/json", []byte(`{"error":"upstream"}`)) },
			func() { canonical++ },
			func() { hidden++ },
		)
		if !delivered || canonical != 1 || hidden != 0 {
			t.Fatalf("delivered=%t canonical=%d hidden=%d", delivered, canonical, hidden)
		}
	})

	t.Run("pre-write cancellation is hidden", func(t *testing.T) {
		requestCtx, cancel := context.WithCancel(context.Background())
		cancel()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(requestCtx)
		canonical, hidden, sends := 0, 0, 0
		delivered := publishHTTPFinalWithAudit(c,
			func() { sends++; c.Data(http.StatusBadGateway, "application/json", []byte(`{"error":"upstream"}`)) },
			func() { canonical++ },
			func() { hidden++ },
		)
		if delivered || sends != 0 || canonical != 0 || hidden != 1 {
			t.Fatalf("delivered=%t sends=%d canonical=%d hidden=%d", delivered, sends, canonical, hidden)
		}
	})

	t.Run("cancellation after full write remains canonical", func(t *testing.T) {
		requestCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Writer = &finalCancelAfterWriteGinWriter{ResponseWriter: c.Writer, cancel: cancel}
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(requestCtx)
		canonical, hidden := 0, 0
		delivered := publishHTTPFinalWithAudit(c,
			func() { c.Data(http.StatusBadGateway, "application/json", []byte(`{"error":"upstream"}`)) },
			func() { canonical++ },
			func() { hidden++ },
		)
		if !delivered || requestCtx.Err() == nil || canonical != 1 || hidden != 0 {
			t.Fatalf("delivered=%t ctxErr=%v canonical=%d hidden=%d", delivered, requestCtx.Err(), canonical, hidden)
		}
	})

	t.Run("short write is hidden", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Writer = &finalShortWriteGinWriter{ResponseWriter: c.Writer}
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		canonical, hidden := 0, 0
		delivered := publishHTTPFinalWithAudit(c,
			func() { c.Data(http.StatusBadGateway, "application/json", []byte(`{"error":"upstream"}`)) },
			func() { canonical++ },
			func() { hidden++ },
		)
		if delivered || canonical != 0 || hidden != 1 {
			t.Fatalf("delivered=%t canonical=%d hidden=%d", delivered, canonical, hidden)
		}
	})

	t.Run("send error is hidden even after write", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		canonical, hidden := 0, 0
		delivered := publishHTTPFinalWithAuditErr(c,
			func() error {
				c.Data(http.StatusBadGateway, "application/json", []byte(`{"error":"upstream"}`))
				return errors.New("renderer failed")
			},
			func() { canonical++ },
			func() { hidden++ },
		)
		if delivered || canonical != 0 || hidden != 1 {
			t.Fatalf("delivered=%t canonical=%d hidden=%d", delivered, canonical, hidden)
		}
	})
}

func TestHTTPFinalUsageCopySeparatesMappedCanonicalFromRawHidden(t *testing.T) {
	base := &database.UsageLogInput{StatusCode: http.StatusUnauthorized}
	canonical := httpFinalUsageCopy(base, http.StatusServiceUnavailable, false)
	hidden := httpFinalUsageCopy(base, http.StatusUnauthorized, true)

	if canonical == nil || canonical.StatusCode != http.StatusServiceUnavailable || canonical.GuardianAttemptOnly {
		t.Fatalf("canonical copy=%+v", canonical)
	}
	if hidden == nil || hidden.StatusCode != http.StatusUnauthorized || !hidden.GuardianAttemptOnly {
		t.Fatalf("hidden copy=%+v", hidden)
	}
	if base.StatusCode != http.StatusUnauthorized || base.GuardianAttemptOnly {
		t.Fatalf("base mutated=%+v", base)
	}
}

func TestFirstNoAccountPublishesOneAccountNeutralCanonicalFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.4","input":"hello"}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}],"stream":false}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "first-no-account.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
			t.Cleanup(func() { _ = db.Close() })
			store := auth.NewStore(nil, nil, &database.SystemSettings{
				MaxConcurrency:      4,
				MaxRetries:          0,
				MaxRateLimitRetries: 0,
			})
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

			recorder := runRelayTextHandler(t, handler, test.path, []byte(test.body))
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d want=503 body=%s", recorder.Code, recorder.Body.String())
			}
			logs := waitForRetryUsageLogs(t, db, 1)
			if len(logs) != 1 || logs[0].AccountID != 0 || logs[0].StatusCode != http.StatusServiceUnavailable || logs[0].UpstreamErrorKind != ErrorCodeNoAvailableAccount || logs[0].LogicalRequestID == "" {
				t.Fatalf("canonical no-account rows=%+v", logs)
			}
		})
	}
}

func TestBuildRetryAttemptUsageLogKeepsLogicalRequestAcrossEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	beginLogicalRequest(ctx)

	tests := []struct {
		name         string
		endpoint     string
		stream       bool
		viaWebsocket bool
	}{
		{name: "responses relay or oauth", endpoint: "/v1/responses", stream: true},
		{name: "compact", endpoint: "/v1/responses/compact"},
		{name: "chat", endpoint: "/v1/chat/completions", stream: true},
		{name: "anthropic", endpoint: "/v1/messages", stream: true},
		{name: "responses websocket", endpoint: "/v1/responses", stream: true, viaWebsocket: true},
	}

	var logicalID string
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempt := index % 2
			input := buildRetryAttemptUsageLog(ctx, retryAttemptUsageSpec{
				AccountID:         100 + int64(index),
				Endpoint:          tt.endpoint,
				Model:             "gpt-5.4",
				EffectiveModel:    "gpt-5.4",
				StatusCode:        logStatusUpstreamStreamBreak,
				DurationMs:        25,
				UpstreamEndpoint:  "/v1/responses",
				Stream:            tt.stream,
				ViaWebsocket:      tt.viaWebsocket,
				Attempt:           attempt,
				UpstreamErrorKind: "transport",
				ErrorMessage:      "upstream stream ended",
			})

			if input.AttemptIndex != attempt+1 || input.IsRetryAttempt != (attempt > 0) {
				t.Fatalf("retry fields = (%d, %t), want (%d, %t)", input.AttemptIndex, input.IsRetryAttempt, attempt+1, attempt > 0)
			}
			if input.Endpoint != tt.endpoint || input.InboundEndpoint != tt.endpoint || input.Stream != tt.stream || input.ViaWebsocket != tt.viaWebsocket {
				t.Fatalf("route fields = endpoint %q inbound %q stream %t ws %t", input.Endpoint, input.InboundEndpoint, input.Stream, input.ViaWebsocket)
			}
			if input.LogicalRequestID == "" {
				t.Fatal("logical_request_id is empty")
			}
			if logicalID == "" {
				logicalID = input.LogicalRequestID
			} else if input.LogicalRequestID != logicalID {
				t.Fatalf("logical_request_id = %q, want %q", input.LogicalRequestID, logicalID)
			}
		})
	}
}

func TestRetryRequestFailureClassifiesTimeoutAndTransport(t *testing.T) {
	statusCode, kind, message := retryRequestFailure(errors.New("connection reset"), false)
	if statusCode != http.StatusBadGateway || kind != "transport" || message != "connection reset" {
		t.Fatalf("transport failure = (%d, %q, %q)", statusCode, kind, message)
	}

	statusCode, kind, _ = retryRequestFailure(errors.New("first token timeout"), true)
	if statusCode != logStatusUpstreamStreamBreak || kind != "timeout" {
		t.Fatalf("timeout failure = (%d, %q), want (%d, timeout)", statusCode, kind, logStatusUpstreamStreamBreak)
	}
}

func TestRelayTransparentRetryPersistsOneUsageRowPerAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"hello","stream":true}`},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.4","input":"hello"}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "anthropic", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/compact") {
					w.WriteHeader(http.StatusBadGateway)
					_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"gateway failed"}}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"first attempt failed"}}}`+"\n\n")
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(writeRelayTestSuccess))
			defer second.Close()

			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
			if err != nil {
				t.Fatalf("database.New: %v", err)
			}
			defer db.Close()
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)

			handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), db, nil, nil)
			recorder := runRelayTextHandler(t, handler, tt.path, []byte(tt.body))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}

			logs := waitForRetryUsageLogs(t, db, 2)
			byAttempt := make(map[int]*database.UsageLog, len(logs))
			for _, row := range logs {
				byAttempt[row.AttemptIndex] = row
			}
			firstAttempt := byAttempt[1]
			secondAttempt := byAttempt[2]
			if firstAttempt == nil || secondAttempt == nil {
				t.Fatalf("attempt indexes = %v, want 1 and 2", usageAttemptIndexes(logs))
			}
			if firstAttempt.IsRetryAttempt || !secondAttempt.IsRetryAttempt {
				t.Fatalf("retry flags = first:%t second:%t, want false/true", firstAttempt.IsRetryAttempt, secondAttempt.IsRetryAttempt)
			}
			if firstAttempt.StatusCode < 500 || secondAttempt.StatusCode != http.StatusOK {
				t.Fatalf("statuses = first:%d second:%d, want failure then 200", firstAttempt.StatusCode, secondAttempt.StatusCode)
			}
			if firstAttempt.LogicalRequestID == "" || firstAttempt.LogicalRequestID != secondAttempt.LogicalRequestID {
				t.Fatalf("logical IDs = first:%q second:%q", firstAttempt.LogicalRequestID, secondAttempt.LogicalRequestID)
			}
			if len(logs) != 2 {
				t.Fatalf("usage rows = %d, want exactly 2 (no duplicate final row)", len(logs))
			}
		})
	}
}

func TestResponsesWebSocketTransparentStreamRetryPersistsFailedAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)

	store := newRelayFailoverStore("https://first.example", "https://second.example")
	account := store.FindByID(101)
	handler := NewHandler(store, db, nil, nil)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	beginLogicalRequest(ctx)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"ws first attempt failed"}}}` + "\n\n",
		)),
	}

	err = handler.streamResponsesWSUpstream(
		ctx, nil, resp, account, inactiveRelayCircuitAttempt(), "", "affinity", "gpt-5.4", "gpt-5.4", "gpt-5.4", "", "", "owner", "", time.Now(), 0,
		newFirstTokenTimeoutGuard(0, func() {}), true, false, true, nil, 1,
	)
	if _, ok := err.(*responsesWSRetryableStreamError); !ok {
		t.Fatalf("error = %T %v, want responsesWSRetryableStreamError", err, err)
	}

	logs := waitForRetryUsageLogs(t, db, 1)
	if len(logs) != 1 {
		t.Fatalf("usage rows = %d, want 1", len(logs))
	}
	row := logs[0]
	if row.AttemptIndex != 1 || row.IsRetryAttempt || row.StatusCode < 500 || !row.Stream || !row.ViaWebsocket {
		t.Fatalf("WS retry row = attempt:%d retry:%t status:%d stream:%t ws:%t", row.AttemptIndex, row.IsRetryAttempt, row.StatusCode, row.Stream, row.ViaWebsocket)
	}
	if row.LogicalRequestID == "" {
		t.Fatal("WS retry logical_request_id is empty")
	}
}

func waitForRetryUsageLogs(t *testing.T, db *database.DB, want int) []*database.UsageLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		logs, err := db.ListRecentUsageLogs(t.Context(), 20)
		if err == nil && len(logs) >= want {
			// Give the async flusher one more turn so an accidental duplicate
			// final row cannot arrive just after the minimum count is observed.
			time.Sleep(30 * time.Millisecond)
			stable, stableErr := db.ListRecentUsageLogs(t.Context(), 20)
			if stableErr == nil {
				return stable
			}
			return logs
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage logs not flushed before deadline: got=%d want=%d err=%v", len(logs), want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func usageAttemptIndexes(logs []*database.UsageLog) []int {
	indexes := make([]int, 0, len(logs))
	for _, row := range logs {
		indexes = append(indexes, row.AttemptIndex)
	}
	return indexes
}
