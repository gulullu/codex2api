package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestResponsesHTTPActualCYBLongUserTailReachesLearningAndUI(t *testing.T) {
	const (
		label       = "RSP_E2E_91A7"
		successText = "responses-retry-ok"
	)
	handler, db, calls := newActualCYBHTTPTestHandler(t, func(call int32, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		if call == 1 {
			writeCodexSSE(w,
				`{"type":"response.failed","response":{"error":{"codex_error_info":"cyber_policy","message":"blocked"}}}`,
			)
			return
		}
		writeCodexSSE(w,
			`{"type":"response.created","response":{"id":"resp_http_cyb_retry"}}`,
			`{"type":"response.output_item.added","item":{"type":"message"}}`,
			`{"type":"response.output_text.delta","delta":"`+successText+`"}`,
			`{"type":"response.completed","response":{"id":"resp_http_cyb_retry","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`,
		)
	})

	userText := actualCYBE2ELongUserText(label)
	body := relayCYBMarshalTestBody(t, map[string]any{
		"model":        "gpt-5.4",
		"stream":       true,
		"instructions": label + "_INSTRUCTIONS_NONUSER",
		"input":        userText,
	})
	recorder := invokeActualCYBE2EHandler(t, handler, "/v1/responses", body, (*Handler).Responses)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), successText) {
		t.Fatalf("transparent retry response = %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "cyber_policy") {
		t.Fatalf("retryable first-attempt CYB leaked downstream: %q", recorder.Body.String())
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want failed CYB attempt plus successful retry", got)
	}
	assertActualCYBE2ELearningAndUI(t, db, label, []string{
		label + "_INSTRUCTIONS_NONUSER",
	})
}

func TestChatCompletionsActualCYBLongUserTailReachesLearningAndUI(t *testing.T) {
	const (
		label       = "CHAT_E2E_42C9"
		successText = "chat-retry-ok"
	)
	handler, db, calls := newActualCYBHTTPTestHandler(t, func(call int32, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		if call == 1 {
			writeCodexSSE(w,
				`{"type":"response.failed","response":{"error":{"codex_error_info":"cyber_policy","message":"blocked"}}}`,
			)
			return
		}
		writeCodexSSE(w,
			`{"type":"response.created","response":{"id":"resp_chat_cyb_retry"}}`,
			`{"type":"response.output_item.added","item":{"type":"message"}}`,
			`{"type":"response.output_text.delta","delta":"`+successText+`"}`,
			`{"type":"response.completed","response":{"id":"resp_chat_cyb_retry","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`,
		)
	})

	userText := actualCYBE2ELongUserText(label)
	body := relayCYBMarshalTestBody(t, map[string]any{
		"model":  "gpt-5.4",
		"stream": true,
		"messages": []any{
			map[string]any{"role": "system", "content": label + "_SYSTEM_NONUSER"},
			map[string]any{"role": "assistant", "content": label + "_ASSISTANT_NONUSER"},
			map[string]any{"role": "user", "content": userText},
		},
	})
	recorder := invokeActualCYBE2EHandler(t, handler, "/v1/chat/completions", body, (*Handler).ChatCompletions)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), successText) {
		t.Fatalf("transparent retry response = %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "cyber_policy") {
		t.Fatalf("retryable first-attempt CYB leaked downstream: %q", recorder.Body.String())
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want failed CYB attempt plus successful retry", got)
	}
	assertActualCYBE2ELearningAndUI(t, db, label, []string{
		label + "_SYSTEM_NONUSER",
		label + "_ASSISTANT_NONUSER",
	})
}

func TestResponsesCompactActualCYBLongUserTailReachesLearningAndUI(t *testing.T) {
	const label = "COMPACT_E2E_73D4"
	handler, db, calls := newActualCYBHTTPTestHandler(t, func(call int32, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"cyber_policy","message":"blocked"}}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"id":"resp_compact_cyb_retry",
			"object":"response",
			"status":"completed",
			"model":"gpt-5.4",
			"output":[],
			"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}
		}`))
	})

	userText := actualCYBE2ELongUserText(label)
	body := relayCYBMarshalTestBody(t, map[string]any{
		"model":        "gpt-5.4",
		"instructions": label + "_INSTRUCTIONS_NONUSER",
		"input":        userText,
	})
	recorder := invokeActualCYBE2EHandler(t, handler, "/v1/responses/compact", body, (*Handler).ResponsesCompact)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "resp_compact_cyb_retry") {
		t.Fatalf("transparent retry response = %d %q", recorder.Code, recorder.Body.String())
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want failed CYB attempt plus successful retry", got)
	}
	assertActualCYBE2ELearningAndUI(t, db, label, []string{
		label + "_INSTRUCTIONS_NONUSER",
	})
}

func newActualCYBHTTPTestHandler(
	t *testing.T,
	serve func(call int32, w http.ResponseWriter),
) (*Handler, *database.DB, *atomic.Int32) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "7")

	previousRuntime := CurrentRuntimeSettings()
	runtime := previousRuntime
	runtime.CodexForceWebsocket = false
	ApplyRuntimeSettings(runtime)
	t.Cleanup(func() { ApplyRuntimeSettings(previousRuntime) })

	previousResin := resinCfg.Load()
	t.Cleanup(func() { resinCfg.Store(previousResin) })

	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(calls.Add(1), w)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "actual-cyb-http-e2e.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("database.Close: %v", err)
		}
	})

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          1,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	store.SetCodexForceWebsocket(false)
	store.SetMaxRetries(1)
	store.SetMaxRateLimitRetries(0)
	store.SetRetryIntervalMS(0)
	store.AddAccount(&auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"})
	store.AddAccount(&auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "pro", AccountID: "acct-2"})

	handler := NewHandler(store, db, &config.Config{
		AllowAnonymousV1:       true,
		CodexUpstreamTransport: "http",
	}, nil)
	return handler, db, &calls
}

func invokeActualCYBE2EHandler(
	t *testing.T,
	handler *Handler,
	path string,
	body []byte,
	invoke func(*Handler, *gin.Context),
) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("User-Agent", "codex_cli_rs/0.114.0")
	invoke(handler, ctx)
	return recorder
}

func actualCYBE2ELongUserText(label string) string {
	return label + "_FIXED_TEMPLATE_HEAD " +
		strings.Repeat("routine-reference-context ", 90_000) +
		" " + label + "_OMITTED_MIDDLE " +
		strings.Repeat("ordinary-project-context ", 55_000) +
		" " + label + "_ACTUAL_USER_TAIL"
}

func assertActualCYBE2ELearningAndUI(
	t *testing.T,
	db *database.DB,
	label string,
	nonUserSentinels []string,
) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("CYB audit/learning writer did not drain")
	}

	sample, err := db.ClaimNextRelayCYBMissSample(context.Background(), "gpt-5.4")
	if err != nil {
		t.Fatalf("ClaimNextRelayCYBMissSample: %v", err)
	}
	if sample == nil {
		t.Fatal("actual upstream CYB did not create a learning sample")
	}
	if sample.SampleSource != database.RelayCYBMissSourceOAuth {
		t.Fatalf("sample source = %q, want %q", sample.SampleSource, database.RelayCYBMissSourceOAuth)
	}
	if !sample.UserTextTruncated {
		t.Fatal("oversized user text was not marked truncated")
	}
	for _, sentinel := range []string{
		label + "_FIXED_TEMPLATE_HEAD",
		"USER_TEXT_MIDDLE_TRUNCATED",
		"CURRENT_USER_TERMINAL_SUFFIX",
		label + "_ACTUAL_USER_TAIL",
	} {
		if !strings.Contains(sample.UserText, sentinel) {
			t.Fatalf("worker sample lost %q", sentinel)
		}
	}
	if strings.Contains(sample.UserText, label+"_OMITTED_MIDDLE") {
		t.Fatal("worker sample retained omitted middle instead of the actual current-user tail")
	}
	for _, sentinel := range nonUserSentinels {
		if strings.Contains(sample.UserText, sentinel) {
			t.Fatalf("non-user provenance %q entered worker sample", sentinel)
		}
	}

	detail, err := db.GetRelayAuditCaseDetail(context.Background(), sample.RequestID)
	if err != nil {
		t.Fatalf("GetRelayAuditCaseDetail: %v", err)
	}
	if detail.CYBMiss == nil {
		t.Fatal("UI audit detail did not include the CYB learning sample")
	}
	if detail.CYBMiss.UserText != sample.UserText {
		t.Fatal("worker Claim and UI audit detail read different user_text values")
	}
	if detail.CYBMiss.UserTextTruncated != sample.UserTextTruncated {
		t.Fatal("worker Claim and UI audit detail read different truncation flags")
	}
}
