package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func resetProbeShortCircuitTestState(t *testing.T) {
	t.Helper()
	probeShortCircuitState = &probeShortCircuitTracker{lastSeen: map[string]time.Time{}, replies: map[string]probeCachedResponse{}}
	t.Cleanup(func() {
		probeShortCircuitState = &probeShortCircuitTracker{lastSeen: map[string]time.Time{}, replies: map[string]probeCachedResponse{}}
	})
}

func newProbeAuditHandler(t *testing.T) (*Handler, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "probe-audit.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	return &Handler{db: db}, db
}

func probeAuditRows(t *testing.T, db *database.DB, want int) []*database.UsageLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	settled := time.Now().Add(200 * time.Millisecond)
	for {
		rows, err := db.ListUsageLogsByTimeRange(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("ListUsageLogsByTimeRange: %v", err)
		}
		if want == 0 {
			if len(rows) > 0 || time.Now().After(settled) {
				return rows
			}
		} else if len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProbeShortCircuitReplaysFirstResponseWithinWindow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_WINDOW_SECONDS", "300")

	handler := &Handler{}
	body := []byte(`{"model":"gpt-5.4","input":"hi"}`)

	firstRecorder := httptest.NewRecorder()
	firstCtx, _ := gin.CreateTestContext(firstRecorder)
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	firstCtx.Set(contextAPIKeyID, int64(1))

	firstCapture, handled := handler.prepareProbeShortCircuit(firstCtx, body, "/v1/responses", "gpt-5.4", false, "responses")
	if handled {
		t.Fatal("first probe was short-circuited; want first occurrence to pass through")
	}
	if firstCapture == nil {
		t.Fatal("first probe did not create a response capture")
	}
	firstCtx.JSON(http.StatusOK, gin.H{"id": "first-real-response", "output": "hello"})
	firstCapture.finish()

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	secondCtx.Set(contextAPIKeyID, int64(1))

	if _, handled := handler.prepareProbeShortCircuit(secondCtx, body, "/v1/responses", "gpt-5.4", false, "responses"); !handled {
		t.Fatal("repeated probe was not short-circuited")
	}
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", secondRecorder.Code)
	}
	if !strings.Contains(secondRecorder.Body.String(), "first-real-response") {
		t.Fatalf("body = %q, want cached first response", secondRecorder.Body.String())
	}
}

func TestProbeShortCircuitWriteFailureDoesNotCreateCanonicalUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")
	handler, db := newProbeAuditHandler(t)
	body := []byte(`{"model":"gpt-5.4","input":"hi"}`)

	firstRecorder := httptest.NewRecorder()
	firstCtx, _ := gin.CreateTestContext(firstRecorder)
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	firstCtx.Set(contextAPIKeyID, int64(11))
	if _, handled := handler.prepareProbeShortCircuit(firstCtx, body, "/v1/responses", "gpt-5.4", false, "responses"); handled {
		t.Fatal("first probe was short-circuited")
	}

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	secondCtx.Set(contextAPIKeyID, int64(11))
	secondCtx.Writer = &auditFailingGinWriter{ResponseWriter: secondCtx.Writer, writeErr: errors.New("client write failed")}
	if _, handled := handler.prepareProbeShortCircuit(secondCtx, body, "/v1/responses", "gpt-5.4", false, "responses"); !handled {
		t.Fatal("repeated probe was not handled")
	}
	if rows := probeAuditRows(t, db, 0); len(rows) != 0 {
		t.Fatalf("usage rows = %+v, want none for undelivered local response", rows)
	}
}

func TestProbeShortCircuitFlushFailureDoesNotCreateCanonicalUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")
	handler, db := newProbeAuditHandler(t)
	body := []byte(`{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"Count to seven."}]}`)

	firstRecorder := httptest.NewRecorder()
	firstCtx, _ := gin.CreateTestContext(firstRecorder)
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	firstCtx.Set(contextAPIKeyID, int64(12))
	if _, handled := handler.prepareProbeShortCircuit(firstCtx, body, "/v1/chat/completions", "gpt-5.4", true, "chat"); handled {
		t.Fatal("first probe was short-circuited")
	}

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	secondCtx.Set(contextAPIKeyID, int64(12))
	secondCtx.Writer = &auditFailingGinWriter{ResponseWriter: secondCtx.Writer, flushErr: errors.New("flush failed")}
	if _, handled := handler.prepareProbeShortCircuit(secondCtx, body, "/v1/chat/completions", "gpt-5.4", true, "chat"); !handled {
		t.Fatal("repeated probe was not handled")
	}
	if rows := probeAuditRows(t, db, 0); len(rows) != 0 {
		t.Fatalf("usage rows = %+v, want none for unflushed terminal response", rows)
	}
}

func TestProbeCaptureWriterUnwrapExposesUnderlyingFlushError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	flushErr := errors.New("probe underlying flush failed")
	underlying := &auditFlushErrorHTTPWriter{flushErr: flushErr}
	ginWrapper := &auditUnwrapAndFlushGinWriter{
		ResponseWriter: ctx.Writer,
		target:         underlying,
	}
	capture := &probeCaptureWriter{ResponseWriter: ginWrapper, limit: 1024}

	err := flushTerminalHTTPResponse(capture)
	if !errors.Is(err, flushErr) {
		t.Fatalf("flush error = %v, want %v", err, flushErr)
	}
	if ginWrapper.flushCalls != 0 {
		t.Fatalf("legacy Gin Flush calls = %d, want 0", ginWrapper.flushCalls)
	}
	if underlying.flushCalls != 1 {
		t.Fatalf("underlying FlushError calls = %d, want 1", underlying.flushCalls)
	}
}

func TestProbeShortCircuitSuccessfulPublicationCreatesOneCanonicalUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")
	handler, db := newProbeAuditHandler(t)
	body := []byte(`{"model":"gpt-5.4","input":"hi"}`)

	firstCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	firstCtx.Set(contextAPIKeyID, int64(13))
	_, _ = handler.prepareProbeShortCircuit(firstCtx, body, "/v1/responses", "gpt-5.4", false, "responses")

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
	secondCtx.Set(contextAPIKeyID, int64(13))
	if _, handled := handler.prepareProbeShortCircuit(secondCtx, body, "/v1/responses", "gpt-5.4", false, "responses"); !handled {
		t.Fatal("repeated probe was not handled")
	}
	rows := probeAuditRows(t, db, 1)
	if len(rows) != 1 || rows[0].UpstreamErrorKind != "local_probe_short_circuit" || rows[0].StatusCode != http.StatusOK {
		t.Fatalf("usage rows = %+v, want one canonical local probe success", rows)
	}
}

func TestProbeShortCircuitDoesNotMatchNormalShortQuestion(t *testing.T) {
	resetProbeShortCircuitTestState(t)
	body := []byte(`{"model":"gpt-5.4","input":"please write a login page title"}`)
	decision := classifyProbeShortCircuit(nil, body, "/v1/responses", "gpt-5.4", false, "responses", 5*time.Minute, probeShortCircuitDefaultMaxEntries)
	if decision.Probe {
		t.Fatalf("normal short request classified as probe: %+v", decision)
	}
}

func TestProbeShortCircuitRequiresExactRequestBodyHash(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")

	handler := &Handler{}
	firstBody := []byte(`{"model":"gpt-5.4","input":"hi"}`)
	secondBody := []byte(`{"model":"gpt-5.4","input":"hello"}`)

	firstRecorder := httptest.NewRecorder()
	firstCtx, _ := gin.CreateTestContext(firstRecorder)
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(firstBody)))
	firstCtx.Set(contextAPIKeyID, int64(1))
	firstCapture, handled := handler.prepareProbeShortCircuit(firstCtx, firstBody, "/v1/responses", "gpt-5.4", false, "responses")
	if handled {
		t.Fatal("first probe was short-circuited")
	}
	if firstCapture == nil {
		t.Fatal("first probe did not create a response capture")
	}
	firstCtx.JSON(http.StatusOK, gin.H{"id": "first-real-response"})
	firstCapture.finish()

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(secondBody)))
	secondCtx.Set(contextAPIKeyID, int64(1))
	secondCapture, handled := handler.prepareProbeShortCircuit(secondCtx, secondBody, "/v1/responses", "gpt-5.4", false, "responses")
	if handled {
		t.Fatal("probe with different body hash was short-circuited")
	}
	if secondCapture == nil {
		t.Fatal("probe with different body hash should create its own capture")
	}
}

func TestProbeShortCircuitLogOnlyNeverHandlesOrCaptures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_LOG_ONLY", "true")
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_WINDOW_SECONDS", "120")

	handler := &Handler{}
	body := []byte(`{"model":"gpt-5.4","input":"hi"}`)

	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
		ctx.Set(contextAPIKeyID, int64(1))

		capture, handled := handler.prepareProbeShortCircuit(ctx, body, "/v1/responses", "gpt-5.4", false, "responses")
		if handled {
			t.Fatalf("iteration %d was handled in log-only mode", i)
		}
		if capture != nil {
			t.Fatalf("iteration %d created a response capture in log-only mode", i)
		}
		if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
			t.Fatalf("iteration %d wrote response status=%d body=%q in log-only mode", i, recorder.Code, recorder.Body.String())
		}
	}
}

func TestProbeShortCircuitCapsCacheEntries(t *testing.T) {
	resetProbeShortCircuitTestState(t)
	tracker := probeShortCircuitState
	for i := 0; i < 5; i++ {
		key := "key:" + string(rune('a'+i))
		tracker.markAndGet(key, time.Minute, 3)
		tracker.storeReply(key, probeCachedResponse{
			StatusCode:  http.StatusOK,
			ContentType: "application/json",
			Body:        []byte(`{"ok":true}`),
			CreatedAt:   time.Now(),
		}, 3)
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.lastSeen) > 3 {
		t.Fatalf("lastSeen entries = %d, want <= 3", len(tracker.lastSeen))
	}
	if len(tracker.replies) > 3 {
		t.Fatalf("cached replies = %d, want <= 3", len(tracker.replies))
	}
}

func TestProbeShortCircuitChatStreamReplaysCachedSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetProbeShortCircuitTestState(t)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "true")

	handler := &Handler{}
	body := []byte(`{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"Count to seven."}]}`)

	firstRecorder := httptest.NewRecorder()
	firstCtx, _ := gin.CreateTestContext(firstRecorder)
	firstCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	firstCtx.Set(contextAPIKeyID, int64(7))
	firstCapture, handled := handler.prepareProbeShortCircuit(firstCtx, body, "/v1/chat/completions", "gpt-5.4", true, "chat")
	if handled {
		t.Fatal("first chat probe was short-circuited")
	}
	if firstCapture == nil {
		t.Fatal("first chat probe did not create a response capture")
	}
	_, _ = firstCtx.Writer.WriteString("data: cached-stream-response\n\n")
	_, _ = firstCtx.Writer.WriteString("data: [DONE]\n\n")
	firstCapture.finish()

	secondRecorder := httptest.NewRecorder()
	secondCtx, _ := gin.CreateTestContext(secondRecorder)
	secondCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	secondCtx.Set(contextAPIKeyID, int64(7))
	if _, handled := handler.prepareProbeShortCircuit(secondCtx, body, "/v1/chat/completions", "gpt-5.4", true, "chat"); !handled {
		t.Fatal("second chat probe was not short-circuited")
	}
	if !strings.Contains(secondRecorder.Body.String(), "cached-stream-response") {
		t.Fatalf("stream body = %q, want cached stream", secondRecorder.Body.String())
	}
}
