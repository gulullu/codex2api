package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	messagesPublicationBody       = `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`
	messagesPublicationStreamBody = `{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`
)

type messagesTerminalFailWriter struct {
	gin.ResponseWriter
	marker          []byte
	err             error
	flushMarker     []byte
	terminalWritten bool
	flushErr        error
}

type messagesSecondTerminalFlushFailWriter struct {
	gin.ResponseWriter
	flushMarker       []byte
	terminalWritten   bool
	terminalFlushes   int
	secondTerminalErr error
}

func (w *messagesSecondTerminalFlushFailWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil && len(w.flushMarker) > 0 && bytes.Contains(data, w.flushMarker) {
		w.terminalWritten = true
	}
	return n, err
}

func (w *messagesSecondTerminalFlushFailWriter) WriteString(data string) (int, error) {
	n, err := w.ResponseWriter.WriteString(data)
	if err == nil && len(w.flushMarker) > 0 && bytes.Contains([]byte(data), w.flushMarker) {
		w.terminalWritten = true
	}
	return n, err
}

func (w *messagesSecondTerminalFlushFailWriter) FlushError() error {
	if w.terminalWritten {
		w.terminalFlushes++
		if w.terminalFlushes > 1 {
			return w.secondTerminalErr
		}
	}
	w.ResponseWriter.Flush()
	return nil
}

func (w *messagesTerminalFailWriter) Write(data []byte) (int, error) {
	if len(w.marker) > 0 && bytes.Contains(data, w.marker) {
		return 0, w.err
	}
	n, err := w.ResponseWriter.Write(data)
	if err == nil && len(w.flushMarker) > 0 && bytes.Contains(data, w.flushMarker) {
		w.terminalWritten = true
	}
	return n, err
}

func (w *messagesTerminalFailWriter) WriteString(data string) (int, error) {
	if len(w.marker) > 0 && bytes.Contains([]byte(data), w.marker) {
		return 0, w.err
	}
	n, err := w.ResponseWriter.WriteString(data)
	if err == nil && len(w.flushMarker) > 0 && bytes.Contains([]byte(data), w.flushMarker) {
		w.terminalWritten = true
	}
	return n, err
}

func (w *messagesTerminalFailWriter) FlushError() error {
	if w.flushErr != nil && w.terminalWritten {
		return w.flushErr
	}
	w.ResponseWriter.Flush()
	return nil
}

func newMessagesPublicationDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "messages-publication.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func waitMessagesPublicationRows(t *testing.T, db *database.DB, want int) []database.RelayGuardianUsageRow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, err := db.ListRelayGuardianUsage(
			context.Background(),
			relayFailoverGroupID,
			time.Now().Add(-time.Minute),
			time.Now().Add(time.Minute),
			100,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= want {
			time.Sleep(30 * time.Millisecond)
			stable, stableErr := db.ListRelayGuardianUsage(
				context.Background(),
				relayFailoverGroupID,
				time.Now().Add(-time.Minute),
				time.Now().Add(time.Minute),
				100,
			)
			if stableErr == nil {
				return stable
			}
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("Messages usage rows=%d want at least %d", len(rows), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitMessagesUsageLogs(t *testing.T, db *database.DB, want int) []*database.UsageLog {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		logs, err := db.ListRecentUsageLogs(context.Background(), 20)
		if err == nil && len(logs) >= want {
			time.Sleep(30 * time.Millisecond)
			stable, stableErr := db.ListRecentUsageLogs(context.Background(), 20)
			if stableErr == nil {
				return stable
			}
			return logs
		}
		if time.Now().After(deadline) {
			t.Fatalf("Messages usage logs=%d want at least %d err=%v", len(logs), want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runMessagesPublicationHandler(t *testing.T, handler *Handler, body string, wrap func(gin.ResponseWriter) gin.ResponseWriter) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	if wrap != nil {
		c.Writer = wrap(c.Writer)
	}
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	handler.Messages(c)
	return recorder
}

func TestMessagesFirstNoAccountPublishesOneCanonicalFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newMessagesPublicationDB(t)
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      4,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	t.Cleanup(store.Stop)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	recorder := runMessagesPublicationHandler(t, handler, `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`, nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	if got := gjson.GetBytes(recorder.Body.Bytes(), "error.type").String(); got != "overloaded_error" {
		t.Fatalf("error.type=%q want overloaded_error body=%s", got, recorder.Body.String())
	}

	logs := waitMessagesUsageLogs(t, db, 1)
	if len(logs) != 1 {
		t.Fatalf("usage logs=%d want exactly 1: %+v", len(logs), logs)
	}
	if logs[0].AccountID != 0 || logs[0].StatusCode != http.StatusServiceUnavailable || logs[0].UpstreamErrorKind != ErrorCodeNoAvailableAccount || logs[0].LogicalRequestID == "" {
		t.Fatalf("first no-account canonical row=%+v", logs[0])
	}
}

func TestMessagesNonStreamResponseFailedMatchesCanonicalStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantType   string
	}{
		{
			name:       "invalid request remains 400",
			payload:    `{"type":"response.failed","response":{"error":{"code":"invalid_value","type":"invalid_request_error","message":"bad request","status_code":400}}}`,
			wantStatus: http.StatusBadRequest,
			wantType:   "invalid_request_error",
		},
		{
			name:       "account credential 401 becomes 503",
			payload:    `{"type":"response.failed","response":{"error":{"code":"invalid_api_key","type":"invalid_request_error","message":"invalid upstream key","status_code":401}}}`,
			wantStatus: http.StatusServiceUnavailable,
			wantType:   "overloaded_error",
		},
		{
			name:       "rate limit remains 429",
			payload:    `{"type":"response.failed","response":{"error":{"code":"rate_limit_exceeded","type":"rate_limit_error","message":"rate limited","status_code":429}}}`,
			wantStatus: http.StatusTooManyRequests,
			wantType:   "rate_limit_error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+test.payload+"\n\n")
			}))
			defer upstream.Close()

			db := newMessagesPublicationDB(t)
			store := newSingleRelayFailoverStore(upstream.URL, 0)
			store.SetMaxRetries(0)
			store.SetMaxRateLimitRetries(0)
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

			recorder := runMessagesPublicationHandler(t, handler, messagesPublicationBody, nil)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if got := gjson.GetBytes(recorder.Body.Bytes(), "error.type").String(); got != test.wantType {
				t.Fatalf("error.type=%q want=%q body=%s", got, test.wantType, recorder.Body.String())
			}

			rows := waitMessagesPublicationRows(t, db, 1)
			if len(rows) != 1 || rows[0].GuardianAttemptOnly || rows[0].StatusCode != test.wantStatus {
				t.Fatalf("response.failed rows=%+v want one canonical status %d", rows, test.wantStatus)
			}
		})
	}
}

func TestMessagesNon2xxWriteFailureKeepsOnlyHiddenRawAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"invalid_api_key","message":"invalid upstream key"}}`)
	}))
	defer upstream.Close()

	db := newMessagesPublicationDB(t)
	store := newSingleRelayFailoverStore(upstream.URL, 0)
	store.SetMaxRetries(0)
	store.SetMaxRateLimitRetries(0)
	t.Cleanup(store.Stop)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
	writeErr := errors.New("downstream write failed")

	runMessagesPublicationHandler(t, handler, messagesPublicationBody, func(writer gin.ResponseWriter) gin.ResponseWriter {
		return &messagesTerminalFailWriter{ResponseWriter: writer, marker: []byte(`"type"`), err: writeErr}
	})

	rows := waitMessagesPublicationRows(t, db, 1)
	if len(rows) != 1 || !rows[0].GuardianAttemptOnly || rows[0].StatusCode != http.StatusUnauthorized || rows[0].AccountID != 101 {
		t.Fatalf("non-2xx write-failure rows=%+v want one hidden raw 401 attempt", rows)
	}
}

func TestMessagesTransportWriteFailureKeepsOnlyHiddenAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newMessagesPublicationDB(t)
	store := newSingleRelayFailoverStore(closedLoopbackURL(t), 0)
	store.SetMaxRetries(0)
	store.SetMaxRateLimitRetries(0)
	t.Cleanup(store.Stop)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
	writeErr := errors.New("downstream write failed")

	runMessagesPublicationHandler(t, handler, messagesPublicationBody, func(writer gin.ResponseWriter) gin.ResponseWriter {
		return &messagesTerminalFailWriter{ResponseWriter: writer, marker: []byte(`"type"`), err: writeErr}
	})

	rows := waitMessagesPublicationRows(t, db, 1)
	if len(rows) != 1 || !rows[0].GuardianAttemptOnly || rows[0].AccountID != 101 {
		t.Fatalf("transport write-failure rows=%+v want one hidden attempt", rows)
	}
}

func TestMessagesStreamTerminalFlushFailureKeepsOnlyHiddenAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.StreamFlushPolicy = StreamFlushPolicyImmediate
	ApplyRuntimeSettings(settings)

	tests := []struct {
		name       string
		events     []string
		marker     string
		wantStatus int
	}{
		{
			name: "completed terminal",
			events: []string{
				`{"type":"response.created","response":{"id":"resp_done"}}`,
				`{"type":"response.output_item.added","item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
				`{"type":"response.output_text.delta","delta":"done"}`,
				`{"type":"response.completed","response":{"id":"resp_done","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}`,
			},
			marker:     "event: message_stop",
			wantStatus: http.StatusOK,
		},
		{
			name: "failed terminal",
			events: []string{
				`{"type":"response.failed","response":{"error":{"code":"invalid_value","type":"invalid_request_error","message":"bad request","status_code":400}}}`,
			},
			marker:     "event: error",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, event := range test.events {
					_, _ = io.WriteString(w, "data: "+event+"\n\n")
				}
			}))
			defer upstream.Close()

			db := newMessagesPublicationDB(t)
			store := newSingleRelayFailoverStore(upstream.URL, 0)
			store.SetMaxRetries(0)
			store.SetMaxRateLimitRetries(0)
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
			flushErr := errors.New("downstream terminal flush failed")

			recorder := runMessagesPublicationHandler(t, handler, messagesPublicationStreamBody, func(writer gin.ResponseWriter) gin.ResponseWriter {
				return &messagesTerminalFailWriter{ResponseWriter: writer, flushMarker: []byte(test.marker), flushErr: flushErr}
			})
			if !bytes.Contains(recorder.Body.Bytes(), []byte(test.marker)) {
				t.Fatalf("terminal bytes were not written before flush failure: %s", recorder.Body.String())
			}

			rows := waitMessagesPublicationRows(t, db, 1)
			if len(rows) != 1 || !rows[0].GuardianAttemptOnly || rows[0].StatusCode != test.wantStatus {
				t.Fatalf("terminal flush-failure rows=%+v want one hidden raw status %d", rows, test.wantStatus)
			}
		})
	}
}

func TestMessagesStreamTerminalFlushesOnceAndStaysCanonical(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.StreamFlushPolicy = StreamFlushPolicyImmediate
	ApplyRuntimeSettings(settings)

	tests := []struct {
		name       string
		events     []string
		marker     string
		wantStatus int
	}{
		{
			name: "completed terminal",
			events: []string{
				`{"type":"response.created","response":{"id":"resp_done"}}`,
				`{"type":"response.output_item.added","item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
				`{"type":"response.output_text.delta","delta":"done"}`,
				`{"type":"response.completed","response":{"id":"resp_done","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}`,
			},
			marker:     "event: message_stop",
			wantStatus: http.StatusOK,
		},
		{
			name: "failed terminal",
			events: []string{
				`{"type":"response.failed","response":{"error":{"code":"invalid_value","type":"invalid_request_error","message":"bad request","status_code":400}}}`,
			},
			marker:     "event: error",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "truncated terminal",
			events: []string{
				`{"type":"response.created","response":{"id":"resp_partial"}}`,
				`{"type":"response.output_item.added","item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
				`{"type":"response.output_text.delta","delta":"partial"}`,
			},
			marker:     "event: error",
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, event := range test.events {
					_, _ = io.WriteString(w, "data: "+event+"\n\n")
				}
			}))
			defer upstream.Close()

			db := newMessagesPublicationDB(t)
			store := newSingleRelayFailoverStore(upstream.URL, 0)
			store.SetMaxRetries(0)
			store.SetMaxRateLimitRetries(0)
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
			var terminalWriter *messagesSecondTerminalFlushFailWriter

			recorder := runMessagesPublicationHandler(t, handler, messagesPublicationStreamBody, func(writer gin.ResponseWriter) gin.ResponseWriter {
				terminalWriter = &messagesSecondTerminalFlushFailWriter{
					ResponseWriter:    writer,
					flushMarker:       []byte(test.marker),
					secondTerminalErr: errors.New("redundant terminal flush"),
				}
				return terminalWriter
			})
			if !bytes.Contains(recorder.Body.Bytes(), []byte(test.marker)) {
				t.Fatalf("terminal marker missing: %s", recorder.Body.String())
			}
			if terminalWriter == nil {
				t.Fatal("terminal writer was not installed")
			}
			if terminalWriter.terminalFlushes != 1 {
				t.Fatalf("terminal flushes=%d want 1", terminalWriter.terminalFlushes)
			}

			rows := waitMessagesPublicationRows(t, db, 1)
			if len(rows) != 1 || rows[0].GuardianAttemptOnly || rows[0].StatusCode != test.wantStatus {
				t.Fatalf("terminal rows=%+v want one canonical status %d", rows, test.wantStatus)
			}
		})
	}
}

func TestMessagesTruncatedStreamTerminalPublicationBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.StreamFlushPolicy = StreamFlushPolicyImmediate
	ApplyRuntimeSettings(settings)

	for _, mode := range []string{"delivered", "write_failed", "flush_failed"} {
		t.Run(mode, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, event := range []string{
					`{"type":"response.created","response":{"id":"resp_partial"}}`,
					`{"type":"response.output_item.added","item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
					`{"type":"response.output_text.delta","delta":"partial"}`,
				} {
					_, _ = io.WriteString(w, "data: "+event+"\n\n")
				}
			}))
			defer upstream.Close()

			db := newMessagesPublicationDB(t)
			store := newSingleRelayFailoverStore(upstream.URL, 0)
			store.SetMaxRetries(0)
			store.SetMaxRateLimitRetries(0)
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
			var wrap func(gin.ResponseWriter) gin.ResponseWriter
			switch mode {
			case "write_failed":
				wrap = func(writer gin.ResponseWriter) gin.ResponseWriter {
					return &messagesTerminalFailWriter{ResponseWriter: writer, marker: []byte("event: error"), err: errors.New("terminal write failed")}
				}
			case "flush_failed":
				wrap = func(writer gin.ResponseWriter) gin.ResponseWriter {
					return &messagesTerminalFailWriter{ResponseWriter: writer, flushMarker: []byte("event: error"), flushErr: errors.New("terminal flush failed")}
				}
			}

			recorder := runMessagesPublicationHandler(t, handler, messagesPublicationStreamBody, wrap)
			if !bytes.Contains(recorder.Body.Bytes(), []byte("partial")) {
				t.Fatalf("partial stream was not delivered: %s", recorder.Body.String())
			}
			rows := waitMessagesPublicationRows(t, db, 1)
			if len(rows) != 1 {
				t.Fatalf("truncated stream rows=%+v want exactly one", rows)
			}
			if mode != "delivered" {
				if !rows[0].GuardianAttemptOnly || rows[0].StatusCode != logStatusUpstreamStreamBreak {
					t.Fatalf("failed terminal publication row=%+v body=%s", rows[0], recorder.Body.String())
				}
				if mode == "write_failed" && bytes.Contains(recorder.Body.Bytes(), []byte("event: error")) {
					t.Fatalf("write-failed terminal unexpectedly reached body: %s", recorder.Body.String())
				}
				if mode == "flush_failed" && !bytes.Contains(recorder.Body.Bytes(), []byte("event: error")) {
					t.Fatalf("flush-failed terminal bytes were not written: %s", recorder.Body.String())
				}
				return
			}
			if rows[0].GuardianAttemptOnly || rows[0].StatusCode != http.StatusBadGateway || !bytes.Contains(recorder.Body.Bytes(), []byte("event: error")) {
				t.Fatalf("delivered terminal publication row=%+v body=%s", rows[0], recorder.Body.String())
			}
		})
	}
}
