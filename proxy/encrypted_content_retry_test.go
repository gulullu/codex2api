package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func newEncryptedRetryRelayStore(upstreamURL string) *auth.Store {
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	store.AddAccount(&auth.Account{
		DBID:         1,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      upstreamURL,
		APIKey:       "sk-direct",
		Models:       []string{"gpt-4.1-direct"},
		PlanType:     "api",
		Status:       auth.StatusReady,
	})
	return store
}

func TestEncryptedContentInvalidFallbackRetriesWithRebuiltBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_ENABLED", "false")

	for _, test := range []struct {
		name string
		path string
		call func(*Handler, *gin.Context)
	}{
		{name: "responses-relay", path: "/v1/responses", call: func(handler *Handler, ctx *gin.Context) { handler.Responses(ctx) }},
		{name: "compact-relay", path: "/v1/responses/compact", call: func(handler *Handler, ctx *gin.Context) { handler.ResponsesCompact(ctx) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			requestBodies := make([][]byte, 0, 2)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				requestBodies = append(requestBodies, append([]byte(nil), body...))
				attempt := len(requestBodies)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if attempt == 1 {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":{"code":"invalid_encrypted_content","type":"invalid_request_error","message":"Encrypted content could not be verified"}}`))
					return
				}
				_, _ = w.Write([]byte(`{"id":"resp_repaired","object":"response","model":"gpt-4.1-direct","output":[],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}`))
			}))
			defer upstream.Close()

			handler := NewHandler(newEncryptedRetryRelayStore(upstream.URL), nil, nil, nil)
			body := []byte(`{
				"model":"gpt-4.1-direct",
				"stream":false,
				"input":[
					{"type":"message","role":"user","content":"continue"},
					{"type":"context_compaction","encrypted_content":"bad-context","summary":"safe summary"}
				]
			}`)
			req := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = req

			test.call(handler, ctx)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(requestBodies) != 2 {
				t.Fatalf("upstream attempts=%d want 2", len(requestBodies))
			}
			secondInput := gjson.GetBytes(requestBodies[1], "input")
			if !secondInput.IsArray() || len(secondInput.Array()) != 2 {
				t.Fatalf("unexpected rebuilt input: %s", requestBodies[1])
			}
			if bytes.Contains([]byte(secondInput.Raw), []byte("encrypted_content")) || bytes.Contains([]byte(secondInput.Raw), []byte("context_compaction")) {
				t.Fatalf("retry retained malformed encrypted history: %s", requestBodies[1])
			}
			if text := gjson.GetBytes(requestBodies[1], "input.1.content.0.text").String(); text != responsesCompactionSummaryPrefix+"safe summary" {
				t.Fatalf("retry lost recoverable summary: %q body=%s", text, requestBodies[1])
			}
		})
	}
}

func TestEncryptedContentFallbackDoesNotRetryEmptyInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_ENABLED", "false")

	var mu sync.Mutex
	attempts := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_encrypted_content","type":"invalid_request_error","message":"Encrypted content could not be verified"}}`))
	}))
	defer upstream.Close()

	handler := NewHandler(newEncryptedRetryRelayStore(upstream.URL), nil, nil, nil)
	body := []byte(`{"model":"gpt-4.1-direct","stream":false,"input":[{"type":"context_compaction","encrypted_content":"bad-context"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses/compact", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req

	handler.ResponsesCompact(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want original 400; body=%s", recorder.Code, recorder.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("upstream attempts=%d want exactly 1", attempts)
	}
}
