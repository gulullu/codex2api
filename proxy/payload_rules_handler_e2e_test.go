package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// This exercises the full request path, rather than only the late-scan helper:
// an account-gated rule may turn an initially-safe request into a CYB route,
// but the OAuth executor must never see that body. The retry-free re-selection
// must land on Relay, where account-gated PayloadRules are not applied.
func TestResponsesAccountPayloadRuleLateCYBReroutesBeforeOAuthWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withPayloadRules(t, `{"override":[{"account_plans":["plus"],"params":{"instructions":"trigger cyb route"}}]}`)

	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	ApplyRuntimeSettings(nextSettings)

	var oauthCalls atomic.Int32
	var oauthBody []byte
	WebsocketExecuteFunc = func(_ context.Context, _ *auth.Account, body []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		oauthCalls.Add(1)
		oauthBody = append([]byte(nil), body...)
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"unexpected OAuth write"}}`)),
		}, nil
	}

	var relayCalls atomic.Int32
	var relayBody []byte
	relayUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayCalls.Add(1)
		relayBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.output_text.delta","delta":"relay-late-cyb"}`+"\n\n"+
				`data: {"type":"response.completed","response":{"id":"resp_late_cyb","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`+"\n\n")
	}))
	t.Cleanup(relayUpstream.Close)

	store := newPromptFilterRoutingStore("http://127.0.0.1:1")
	t.Cleanup(store.Stop)
	store.SetCybRelayConfig(auth.CybRelayConfig{Enabled: true, GroupID: 7, SessionPinEnabled: false})
	store.AddAccount(&auth.Account{
		DBID:              101,
		Name:              "oauth-plus",
		AccessToken:       "at-oauth-plus",
		AccountID:         "acct-oauth-plus",
		PlanType:          "plus",
		GroupIDs:          []int64{1},
		SchedulerPriority: 100,
	})
	store.AddAccount(&auth.Account{
		DBID:         202,
		Name:         "relay-cyb",
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      relayUpstream.URL,
		APIKey:       "sk-relay-test",
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		GroupIDs:     []int64{7},
	})

	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	body := []byte(`{"model":"gpt-5.4","instructions":"base-safe","input":"safe request","stream":true}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set(contextAPIKeyRow, &database.APIKeyRow{ID: 9001, Name: "payload-rule-e2e"})

	handler.Responses(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "relay-late-cyb") {
		t.Fatalf("late CYB route response = status %d body %s; oauth_calls=%d oauth_body=%s", recorder.Code, recorder.Body.String(), oauthCalls.Load(), oauthBody)
	}
	if got := oauthCalls.Load(); got != 0 {
		t.Fatalf("OAuth executor calls = %d, want 0 before late CYB reroute", got)
	}
	if got := relayCalls.Load(); got != 1 {
		t.Fatalf("Relay upstream calls = %d, want 1", got)
	}
	if strings.Contains(string(relayBody), "trigger cyb route") {
		t.Fatalf("OAuth account-gated rule leaked into Relay body: %s", relayBody)
	}
	if got := gjson.GetBytes(relayBody, "instructions").String(); got != "base-safe" {
		t.Fatalf("Relay instructions = %q, want original base-safe; body=%s", got, relayBody)
	}
}

// A retry must rebuild the attempt from the frozen canonical request with the
// newly-selected account identity. It must not reuse the prior account's gated
// body or requested service tier.
func TestResponsesRetryRebuildsAccountPayloadRulesAndTierForActualOAuthAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withPayloadRules(t, `{
		"override":[
			{"account_plans":["plus"],"params":{"instructions":"oauth-plus-body","service_tier":"priority"}},
			{"account_plans":["pro"],"params":{"instructions":"oauth-pro-body","service_tier":"default"}}
		]
	}`)

	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	ApplyRuntimeSettings(nextSettings)

	type seenAttempt struct {
		accountID int64
		body      []byte
	}
	var attemptsMu sync.Mutex
	var attempts []seenAttempt
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, requestBody []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		attemptsMu.Lock()
		attempts = append(attempts, seenAttempt{accountID: account.ID(), body: append([]byte(nil), requestBody...)})
		attemptsMu.Unlock()

		if account.ID() == 301 {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"error":{"message":"The 'gpt-5.4' model is not supported when using Codex with a ChatGPT account."}}`,
				)),
			}, nil
		}

		sse := `data: {"type":"response.output_text.delta","delta":"oauth-pro-success"}` + "\n\n" +
			`data: {"type":"response.completed","response":{"id":"resp_account_rule_retry","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}` + "\n\n"
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse)),
		}, nil
	}

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          1,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	store.AddAccount(&auth.Account{
		DBID:              301,
		Name:              "oauth-plus-first",
		AccessToken:       "at-plus-first",
		AccountID:         "acct-plus-first",
		PlanType:          "plus",
		SchedulerPriority: 100,
	})
	store.AddAccount(&auth.Account{
		DBID:              302,
		Name:              "oauth-pro-second",
		AccessToken:       "at-pro-second",
		AccountID:         "acct-pro-second",
		PlanType:          "pro",
		SchedulerPriority: 0,
	})

	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	body := []byte(`{"model":"gpt-5.4","instructions":"base-safe","input":"safe request","stream":true}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set(contextAPIKeyRow, &database.APIKeyRow{ID: 9002, Name: "payload-rule-retry-e2e"})

	handler.Responses(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "oauth-pro-success") {
		t.Fatalf("account retry response = status %d body %s", recorder.Code, recorder.Body.String())
	}
	attemptsMu.Lock()
	gotAttempts := append([]seenAttempt(nil), attempts...)
	attemptsMu.Unlock()
	if len(gotAttempts) != 2 {
		t.Fatalf("attempts = %d, want 2: %+v", len(gotAttempts), gotAttempts)
	}
	if gotAttempts[0].accountID != 301 || gotAttempts[1].accountID != 302 {
		t.Fatalf("attempt account order = [%d %d], want [301 302]", gotAttempts[0].accountID, gotAttempts[1].accountID)
	}
	if got := gjson.GetBytes(gotAttempts[0].body, "instructions").String(); got != "oauth-plus-body" {
		t.Fatalf("first attempt instructions = %q, want oauth-plus-body; body=%s", got, gotAttempts[0].body)
	}
	if got := gjson.GetBytes(gotAttempts[0].body, "service_tier").String(); got != "priority" {
		t.Fatalf("first attempt tier = %q, want priority; body=%s", got, gotAttempts[0].body)
	}
	if got := gjson.GetBytes(gotAttempts[1].body, "instructions").String(); got != "oauth-pro-body" {
		t.Fatalf("second attempt instructions = %q, want oauth-pro-body; body=%s", got, gotAttempts[1].body)
	}
	// The upstream sanitizer represents default tier by omitting the field.
	// The important retry invariant is that the first account's priority tier
	// is gone, not carried into the second attempt.
	if tier := gjson.GetBytes(gotAttempts[1].body, "service_tier"); tier.Exists() {
		t.Fatalf("second attempt tier = %q, want upstream default (field absent); body=%s", tier.String(), gotAttempts[1].body)
	}
	if strings.Contains(string(gotAttempts[1].body), "oauth-plus-body") || strings.Contains(string(gotAttempts[0].body), "oauth-pro-body") {
		t.Fatalf("account-gated attempt bodies leaked across retry: first=%s second=%s", gotAttempts[0].body, gotAttempts[1].body)
	}
}
