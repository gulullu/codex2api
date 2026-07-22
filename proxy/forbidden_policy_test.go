package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

func TestResponseFailedForbiddenPolicyByAccountOwnership(t *testing.T) {
	payload := []byte(`{
		"type":"response.failed",
		"response":{
			"status_code":403,
			"error":{"code":"codex_access_restricted","message":"account forbidden"}
		}
	}`)
	oauth := &auth.Account{DBID: 1, AccessToken: "oauth-token"}
	relay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "relay-key",
	}
	grok := &auth.Account{
		DBID:         3,
		UpstreamType: auth.UpstreamGrok,
		APIKey:       "xai-test-key",
	}

	tests := []struct {
		name          string
		account       *auth.Account
		bound         bool
		wantPenalize  bool
		wantRetry     bool
		wantCanonical int
	}{
		{
			name:          "fresh oauth may switch accounts",
			account:       oauth,
			wantPenalize:  true,
			wantRetry:     true,
			wantCanonical: http.StatusServiceUnavailable,
		},
		{
			name:          "bound oauth stays on owner but remains unhealthy",
			account:       oauth,
			bound:         true,
			wantPenalize:  true,
			wantRetry:     false,
			wantCanonical: http.StatusServiceUnavailable,
		},
		{
			name:          "relay front door is neutral and transparent",
			account:       relay,
			wantPenalize:  false,
			wantRetry:     false,
			wantCanonical: http.StatusForbidden,
		},
		{
			name:          "grok is an external RelayStyle account",
			account:       grok,
			wantPenalize:  false,
			wantRetry:     false,
			wantCanonical: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := classifyResponseFailedRequest(tt.account, tt.bound, payload)
			if policy.outcome.logStatusCode != http.StatusForbidden {
				t.Fatalf("raw status = %d, want 403", policy.outcome.logStatusCode)
			}
			if policy.outcome.penalize != tt.wantPenalize {
				t.Fatalf("penalize = %v, want %v", policy.outcome.penalize, tt.wantPenalize)
			}
			if policy.retryable != tt.wantRetry {
				t.Fatalf("retryable = %v, want %v", policy.retryable, tt.wantRetry)
			}
			if policy.canonicalStatus != tt.wantCanonical {
				t.Fatalf("canonical = %d, want %d", policy.canonicalStatus, tt.wantCanonical)
			}
			retryOutcome := responseFailedRetryOutcome(policy.outcome, policy)
			if retryOutcome.penalize != tt.wantRetry {
				t.Fatalf("retry outcome penalize = %v, want %v", retryOutcome.penalize, tt.wantRetry)
			}
			if policy.outcome.penalize != tt.wantPenalize {
				t.Fatalf("retry projection mutated health outcome: penalize = %v, want %v", policy.outcome.penalize, tt.wantPenalize)
			}
		})
	}
}

func TestResponsesWSOAuthForbiddenUsesPoolLevelStatus(t *testing.T) {
	oauth := &auth.Account{DBID: 1, AccessToken: "oauth-token"}
	relay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "relay-key",
	}
	grok := &auth.Account{
		DBID:         3,
		UpstreamType: auth.UpstreamGrok,
		APIKey:       "xai-test-key",
	}
	body := []byte(`{"error":{"code":"codex_access_restricted","message":"account forbidden"}}`)

	if got := responsesWSFinalHTTPStatusForAccount(oauth, http.StatusForbidden); got != http.StatusServiceUnavailable {
		t.Fatalf("OAuth 403 visible status = %d, want 503", got)
	}
	oauthErr := responsesWSUpstreamAPIError(
		responsesWSFinalHTTPStatusForAccount(oauth, http.StatusForbidden),
		body,
	)
	if oauthErr.Code == api.ErrCodeInvalidAuth || oauthErr.Type == api.ErrorTypeAuthentication {
		t.Fatalf("OAuth 403 leaked as downstream invalid_auth: %+v", oauthErr)
	}

	if got := responsesWSFinalHTTPStatusForAccount(relay, http.StatusForbidden); got != http.StatusForbidden {
		t.Fatalf("Relay 403 visible status = %d, want 403", got)
	}
	if got := responsesWSFinalHTTPStatusForAccount(grok, http.StatusForbidden); got != http.StatusForbidden {
		t.Fatalf("Grok 403 visible status = %d, want 403", got)
	}
	relayErr := responsesWSUpstreamAPIError(
		responsesWSFinalHTTPStatusForAccount(relay, http.StatusForbidden),
		body,
	)
	if relayErr.Code != api.ErrCodeUpstreamError || relayErr.Type != api.ErrorTypeUpstream {
		t.Fatalf("Relay 403 error = %+v, want ordinary upstream_error", relayErr)
	}
	if got := responsesWSFinalHTTPStatusForAccount(oauth, http.StatusBadRequest); got != http.StatusBadRequest {
		t.Fatalf("non-403 status changed to %d", got)
	}
}

func TestResponsesWSResponseFailedForbiddenPublicationPolicy(t *testing.T) {
	payload := []byte(`{
		"type":"response.failed",
		"response":{
			"status_code":403,
			"error":{"code":"codex_access_restricted","message":"account forbidden"}
		}
	}`)
	oauth := &auth.Account{DBID: 1, AccessToken: "oauth-token"}
	relay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "relay-key",
	}
	grok := &auth.Account{
		DBID:         3,
		UpstreamType: auth.UpstreamGrok,
		APIKey:       "xai-test-key",
	}

	for _, silentRetry := range []bool{false, true} {
		for _, hideErrors := range []bool{false, true} {
			name := "silent=" + boolString(silentRetry) + "/hide=" + boolString(hideErrors)
			t.Run(name, func(t *testing.T) {
				action := classifyResponsesWSResponseFailedAction(
					oauth,
					false,
					payload,
					true,
					silentRetry,
					true,
					silentRetry,
					hideErrors,
				)
				if !action.suppressRaw {
					t.Fatal("fresh OAuth 403 must never publish raw response.failed")
				}
				if !action.retry {
					t.Fatal("fresh OAuth 403 must rotate while account-safety budget remains")
				}
				if action.policy.canonicalStatus != http.StatusServiceUnavailable {
					t.Fatalf("canonical status = %d, want 503", action.policy.canonicalStatus)
				}
			})
		}
	}

	t.Run("bound OAuth does not replay", func(t *testing.T) {
		action := classifyResponsesWSResponseFailedAction(oauth, true, payload, true, true, true, true, false)
		if !action.suppressRaw || action.retry {
			t.Fatalf("bound OAuth action = %+v, want suppress without retry", action)
		}
		if action.policy.canonicalStatus != http.StatusServiceUnavailable {
			t.Fatalf("canonical status = %d, want 503", action.policy.canonicalStatus)
		}
	})

	t.Run("Relay remains neutral 403", func(t *testing.T) {
		action := classifyResponsesWSResponseFailedAction(relay, false, payload, true, true, true, true, true)
		if !action.suppressRaw || action.retry {
			t.Fatalf("Relay action = %+v, want one canonical non-retryable error", action)
		}
		if action.policy.outcome.penalize {
			t.Fatal("Relay embedded 403 must not penalize account health")
		}
		if action.policy.canonicalStatus != http.StatusForbidden {
			t.Fatalf("canonical status = %d, want 403", action.policy.canonicalStatus)
		}
	})

	t.Run("Grok does not enter OAuth 403 rotation", func(t *testing.T) {
		action := classifyResponsesWSResponseFailedAction(grok, false, payload, true, true, true, true, true)
		if !action.suppressRaw || action.retry {
			t.Fatalf("Grok action = %+v, want one canonical non-OAuth error", action)
		}
		if action.policy.canonicalStatus != http.StatusForbidden {
			t.Fatalf("canonical status = %d, want 403", action.policy.canonicalStatus)
		}
	})

	t.Run("after output does not rewrite published stream", func(t *testing.T) {
		action := classifyResponsesWSResponseFailedAction(oauth, false, payload, false, true, true, true, true)
		if action.suppressRaw || action.retry {
			t.Fatalf("post-output action = %+v, want no replay/rewrite", action)
		}
	})
}

func TestResponsesWebSocketFreshOAuthForbiddenAcrossDisplaySettings(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, silentRetry := range []bool{false, true} {
		for _, hideErrors := range []bool{false, true} {
			name := "silent=" + boolString(silentRetry) + "/hide=" + boolString(hideErrors)
			t.Run(name, func(t *testing.T) {
				previousExec := WebsocketExecuteFunc
				previousSettings := CurrentRuntimeSettings()
				t.Cleanup(func() {
					WebsocketExecuteFunc = previousExec
					ApplyRuntimeSettings(previousSettings)
				})

				settings := previousSettings
				settings.CodexWSSilentRetry = silentRetry
				settings.CodexWSHideErrors = hideErrors
				settings.CodexWSSilentRetries = 1
				ApplyRuntimeSettings(settings)

				attempts := make(chan int64, 4)
				WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, _ []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
					attempts <- account.ID()
					sse := `data: {"type":"response.failed","response":{"status_code":403,"error":{"code":"codex_access_restricted","message":"account forbidden"}}}` + "\n\n"
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(sse)),
					}, nil
				}

				store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2, TestConcurrency: 1, TestModel: "gpt-5.4"})
				store.AddAccount(&auth.Account{DBID: 1, AccessToken: "oauth-1", PlanType: "pro", AccountID: "acct-1"})
				store.AddAccount(&auth.Account{DBID: 2, AccessToken: "oauth-2", PlanType: "pro", AccountID: "acct-2"})
				handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
				router := gin.New()
				handler.RegisterRoutes(router)
				server := httptest.NewServer(router)
				defer server.Close()

				conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
				if err != nil {
					if resp != nil {
						t.Fatalf("dial failed: %v status=%d", err, resp.StatusCode)
					}
					t.Fatalf("dial failed: %v", err)
				}
				defer conn.Close()

				if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"model":"gpt-5.4","input":"fresh"}`)); err != nil {
					t.Fatalf("write request: %v", err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, message, err := conn.ReadMessage()
				if err != nil {
					t.Fatalf("read final error: %v", err)
				}
				if got := gjson.GetBytes(message, "type").String(); got != "error" {
					t.Fatalf("first frame type = %q, want error; body=%s", got, message)
				}
				if strings.Contains(string(message), `"type":"response.failed"`) {
					t.Fatalf("raw OAuth response.failed leaked to client: %s", message)
				}

				_, _, closeErr := conn.ReadMessage()
				var wsClose *websocket.CloseError
				if !errors.As(closeErr, &wsClose) || wsClose.Code != websocket.CloseInternalServerErr {
					t.Fatalf("close error = %T %v, want 1011 for canonical 503", closeErr, closeErr)
				}

				seen := make(map[int64]bool)
				for i := 0; i < 2; i++ {
					select {
					case accountID := <-attempts:
						seen[accountID] = true
					case <-time.After(time.Second):
						t.Fatalf("timed out waiting for attempt %d", i+1)
					}
				}
				if len(seen) != 2 {
					t.Fatalf("attempt accounts = %v, want two distinct OAuth accounts", seen)
				}
				select {
				case extra := <-attempts:
					t.Fatalf("unexpected third attempt on account %d", extra)
				case <-time.After(50 * time.Millisecond):
				}
			})
		}
	}
}

func boolString(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
