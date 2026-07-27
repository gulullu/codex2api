package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/codex2api/security/cybroute"
	"github.com/gin-gonic/gin"
)

func TestRelayAuditCaseDetailNoStoreAndNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.WriteRelayAuditRequest(context.Background(), &database.RelayAuditRequestInput{
		RequestID: "detail-request",
		CreatedAt: now,
		Endpoint:  "/v1/responses",
		Model:     "gpt-5.4",
		FullText:  `{"input":"already redacted detail"}`,
	}); err != nil {
		t.Fatalf("WriteRelayAuditRequest: %v", err)
	}
	handler := &Handler{db: db}

	found := invokeRelayAuditCaseDetail(t, handler, "detail-request")
	if found.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d: %s", found.Code, http.StatusOK, found.Body.String())
	}
	if got := found.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var payload database.RelayAuditCaseDetail
	if err := json.Unmarshal(found.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if payload.Case.RequestID != "detail-request" ||
		payload.Case.FullText != `{"input":"already redacted detail"}` {
		t.Fatalf("detail payload = %+v", payload)
	}

	missing := invokeRelayAuditCaseDetail(t, handler, "missing-request")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want %d: %s", missing.Code, http.StatusNotFound, missing.Body.String())
	}
}

func TestRelayCYBLearningConfigUsesOnlyConfiguredRelayGroupModels(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const relayGroupID int64 = 77
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "77")

	db := newTestAdminDB(t)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 4})
	t.Cleanup(store.Stop)
	store.SetGroupName(relayGroupID, "relay-learners")

	store.AddAccount(&auth.Account{
		DBID:         1,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay-in-group.invalid",
		APIKey:       "test-only",
		Models:       []string{"gpt-relay-only", "gpt-shared"},
		GroupIDs:     []int64{relayGroupID},
	})
	store.AddAccount(&auth.Account{
		DBID:             2,
		UpstreamType:     auth.UpstreamOpenAIResponses,
		BaseURL:          "https://relay-restricted.invalid",
		APIKey:           "test-only",
		Models:           []string{"gpt-restricted"},
		GroupIDs:         []int64{relayGroupID},
		AllowedAPIKeyIDs: []int64{99},
	})
	store.AddAccount(&auth.Account{
		DBID:         3,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay-outside.invalid",
		APIKey:       "test-only",
		Models:       []string{"gpt-outside-only", "gpt-shared"},
		GroupIDs:     []int64{88},
	})
	store.AddAccount(&auth.Account{
		DBID:        4,
		AccessToken: "oauth-test-only",
		Models:      []string{"gpt-oauth-outside"},
		GroupIDs:    []int64{88},
	})
	handler := &Handler{db: db, store: store}

	recorder := invokeRelayCYBLearningHandler(
		t,
		http.MethodGet,
		"/api/admin/relay-audit/learning/config",
		"",
		handler.GetRelayCYBLearningConfig,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("config status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var config relayCYBLearningConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &config); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if want := []string{"gpt-relay-only", "gpt-shared"}; !reflect.DeepEqual(config.AvailableModels, want) {
		t.Fatalf("available_models = %v, want %v", config.AvailableModels, want)
	}
	if config.RelayGroupID != relayGroupID || config.RelayGroupName != "relay-learners" {
		t.Fatalf("relay group = %d/%q, want %d/%q",
			config.RelayGroupID, config.RelayGroupName, relayGroupID, "relay-learners")
	}
	if !config.InternalRequestsExcluded {
		t.Fatal("internal_requests_excluded = false, want true")
	}

	valid := invokeRelayCYBLearningHandler(
		t,
		http.MethodPut,
		"/api/admin/relay-audit/learning/config",
		`{"enabled":true,"model":"gpt-relay-only"}`,
		handler.UpdateRelayCYBLearningConfig,
	)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid update status = %d, want %d: %s", valid.Code, http.StatusOK, valid.Body.String())
	}
	settings, err := db.GetRelayCYBLearningSettings(context.Background())
	if err != nil {
		t.Fatalf("GetRelayCYBLearningSettings: %v", err)
	}
	if !settings.Enabled || settings.Model != "gpt-relay-only" {
		t.Fatalf("settings after valid update = %+v", settings)
	}

	for _, model := range []string{"gpt-outside-only", "gpt-oauth-outside", "gpt-restricted"} {
		t.Run("reject_"+model, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"enabled": true, "model": model})
			if err != nil {
				t.Fatal(err)
			}
			rejected := invokeRelayCYBLearningHandler(
				t,
				http.MethodPut,
				"/api/admin/relay-audit/learning/config",
				string(body),
				handler.UpdateRelayCYBLearningConfig,
			)
			if rejected.Code != http.StatusBadRequest {
				t.Fatalf("model %q status = %d, want %d: %s",
					model, rejected.Code, http.StatusBadRequest, rejected.Body.String())
			}
		})
	}
	settings, err = db.GetRelayCYBLearningSettings(context.Background())
	if err != nil {
		t.Fatalf("GetRelayCYBLearningSettings after rejected updates: %v", err)
	}
	if settings.Model != "gpt-relay-only" {
		t.Fatalf("rejected updates changed model to %q", settings.Model)
	}
	disabled := invokeRelayCYBLearningHandler(
		t,
		http.MethodPut,
		"/api/admin/relay-audit/learning/config",
		`{"enabled":false,"model":"gpt-outside-only"}`,
		handler.UpdateRelayCYBLearningConfig,
	)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable unavailable model status = %d, want %d: %s",
			disabled.Code, http.StatusOK, disabled.Body.String())
	}
	settings, err = db.GetRelayCYBLearningSettings(context.Background())
	if err != nil {
		t.Fatalf("GetRelayCYBLearningSettings after disable: %v", err)
	}
	if settings.Enabled || settings.Model != "gpt-relay-only" {
		t.Fatalf("disable should preserve last valid model: %+v", settings)
	}
}

func TestProcessRelayCYBLearningSampleActivatesIndependentRule(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const relayGroupID int64 = 77
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "77")
	cybroute.PublishLearnedRules(nil)
	t.Cleanup(func() { cybroute.PublishLearnedRules(nil) })

	rejectedCandidate := `{"name":"operational_ransomware_request","pattern":"(?i)write.{0,48}ransomware.{0,48}encrypt","rationale":"operational ransomware authoring","positive_variants":["Generate ransomware that can encrypt documents for extortion.","Build a ransomware payload to encrypt a victim's files."]}`
	candidate := `{"name":"operational_ransomware_request","pattern":"(?i)(?:write|build|generate).{0,48}ransomware.{0,48}(?:encrypt|extort)","rationale":"operational ransomware authoring","positive_variants":["Generate ransomware that can encrypt documents for extortion.","Build a ransomware payload to encrypt a victim's files."]}`
	var learningCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseCandidate := candidate
		if learningCalls.Add(1) == 1 {
			responseCandidate = rejectedCandidate
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "resp_learning",
			"object": "response",
			"status": "completed",
			"model":  "gpt-5.4",
			"output": []any{map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []any{map[string]any{
					"type": "output_text",
					"text": responseCandidate,
				}},
			}},
			"usage": map[string]any{
				"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
			},
		})
	}))
	defer upstream.Close()

	db := newTestAdminDB(t)
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	t.Cleanup(store.Stop)
	store.AddAccount(&auth.Account{
		DBID:         1,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      upstream.URL,
		APIKey:       "test-only",
		Models:       []string{"gpt-5.4"},
		GroupIDs:     []int64{relayGroupID},
	})
	imageProxy := proxy.NewHandler(store, db, nil, nil)
	handler := &Handler{db: db, store: store, imageProxy: imageProxy}

	now := time.Now().UTC()
	if err := db.WriteRelayAuditRequest(context.Background(), &database.RelayAuditRequestInput{
		RequestID: "learn-request",
		CreatedAt: now,
		Endpoint:  "/v1/responses",
		Model:     "gpt-5.4",
	}); err != nil {
		t.Fatalf("WriteRelayAuditRequest: %v", err)
	}
	if err := db.WriteRelayCYBMissSample(context.Background(), &database.RelayCYBMissSampleInput{
		RequestID:       "learn-request",
		CreatedAt:       now,
		AccountID:       42,
		AccountName:     "oauth-redacted-name",
		AccountType:     "oauth",
		RedactedRequest: `{"input":"[redacted sample]"}`,
		UserText:        "Write a ransomware program that will encrypt files and demand payment.",
		ContentHash:     "test-hash",
	}); err != nil {
		t.Fatalf("WriteRelayCYBMissSample: %v", err)
	}
	if _, err := db.UpdateRelayCYBLearningSettings(context.Background(), true, "gpt-5.4"); err != nil {
		t.Fatalf("UpdateRelayCYBLearningSettings: %v", err)
	}
	if err := handler.processOneRelayCYBLearningSample(context.Background()); err != nil {
		t.Fatalf("processOneRelayCYBLearningSample: %v", err)
	}

	sample, err := db.GetRelayCYBMissSample(context.Background(), "learn-request")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample: %v", err)
	}
	if sample.LearningStatus != database.RelayCYBLearningStatusApplied ||
		sample.RuleID <= 0 ||
		sample.LearningAttempts != 1 {
		t.Fatalf("sample after learning = %+v", sample)
	}
	if got := learningCalls.Load(); got != 2 {
		t.Fatalf("learning calls = %d, want 2", got)
	}
	rules := cybroute.LearnedRulesSnapshot()
	if len(rules) != 1 || !rules[0].MatchString("Build ransomware to encrypt files for extortion.") {
		t.Fatalf("hot-loaded rules = %+v", rules)
	}
}

func TestRelayCYBCandidateFeedbackDoesNotEchoCandidate(t *testing.T) {
	const candidateFragment = "sensitive-candidate-fragment"
	got := relayCYBCandidateFeedback(fmt.Errorf(
		"规则不是有效 RE2 正则: invalid pattern %s",
		candidateFragment,
	))
	if strings.Contains(got, candidateFragment) || !strings.Contains(got, "RE2") {
		t.Fatalf("feedback = %q", got)
	}
}

func TestProcessRelayCYBLearningSampleDoesNotApplyAfterDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const relayGroupID int64 = 77
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "77")
	cybroute.PublishLearnedRules(nil)
	t.Cleanup(func() { cybroute.PublishLearnedRules(nil) })

	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	candidate := `{"name":"operational_ransomware_request","pattern":"(?i)(?:write|build|generate).{0,48}ransomware.{0,48}(?:encrypt|extort)","rationale":"operational ransomware authoring","positive_variants":["Generate ransomware that can encrypt documents for extortion.","Build a ransomware payload to encrypt a victim's files."]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-releaseResponse
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "resp_learning_disabled",
			"object": "response",
			"status": "completed",
			"model":  "gpt-5.4",
			"output": []any{map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []any{map[string]any{
					"type": "output_text",
					"text": candidate,
				}},
			}},
			"usage": map[string]any{
				"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
			},
		})
	}))
	defer upstream.Close()

	db := newTestAdminDB(t)
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	t.Cleanup(store.Stop)
	store.AddAccount(&auth.Account{
		DBID:         1,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      upstream.URL,
		APIKey:       "test-only",
		Models:       []string{"gpt-5.4"},
		GroupIDs:     []int64{relayGroupID},
	})
	imageProxy := proxy.NewHandler(store, db, nil, nil)
	handler := &Handler{db: db, store: store, imageProxy: imageProxy}

	now := time.Now().UTC()
	if err := db.WriteRelayCYBMissSample(context.Background(), &database.RelayCYBMissSampleInput{
		RequestID:       "disable-in-flight",
		CreatedAt:       now,
		RedactedRequest: `{"input":"[redacted sample]"}`,
		UserText:        "Write a ransomware program that will encrypt files and demand payment.",
		ContentHash:     "disable-in-flight-hash",
	}); err != nil {
		t.Fatalf("WriteRelayCYBMissSample: %v", err)
	}
	if _, err := db.UpdateRelayCYBLearningSettings(context.Background(), true, "gpt-5.4"); err != nil {
		t.Fatalf("enable learning: %v", err)
	}

	processDone := make(chan error, 1)
	go func() {
		processDone <- handler.processOneRelayCYBLearningSample(context.Background())
	}()
	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("learning request did not reach Relay model")
	}
	if _, err := db.UpdateRelayCYBLearningSettings(context.Background(), false, "gpt-5.4"); err != nil {
		t.Fatalf("disable learning: %v", err)
	}
	close(releaseResponse)
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("processOneRelayCYBLearningSample: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("learning worker did not finish")
	}

	sample, err := db.GetRelayCYBMissSample(context.Background(), "disable-in-flight")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample: %v", err)
	}
	if sample.LearningStatus != database.RelayCYBLearningStatusRetry || sample.RuleID != 0 {
		t.Fatalf("disabled in-flight sample = %+v", sample)
	}
	rules, err := db.ListEnabledRelayCYBRules(context.Background())
	if err != nil {
		t.Fatalf("ListEnabledRelayCYBRules: %v", err)
	}
	if len(rules) != 0 || len(cybroute.LearnedRulesSnapshot()) != 0 {
		t.Fatalf("disable race activated rule: db=%+v runtime=%+v", rules, cybroute.LearnedRulesSnapshot())
	}
}

func TestRelayCYBRuleGuardDisablesOnlyAboveThreshold(t *testing.T) {
	tests := []struct {
		name         string
		hits         int
		wantDisabled bool
	}{
		{name: "at threshold", hits: 20, wantDisabled: false},
		{name: "above threshold", hits: 21, wantDisabled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newTestAdminDB(t)
			ctx := context.Background()
			now := time.Now().UTC()
			if err := db.WriteRelayCYBMissSample(ctx, &database.RelayCYBMissSampleInput{
				RequestID:       "guard-source",
				CreatedAt:       now.Add(-20 * time.Minute),
				RedactedRequest: `{"input":"guard sample"}`,
				UserText:        "guard sample",
				ContentHash:     "guard-hash",
			}); err != nil {
				t.Fatalf("WriteRelayCYBMissSample: %v", err)
			}
			claimed, err := db.ClaimNextRelayCYBMissSample(ctx, "gpt-5.4")
			if err != nil || claimed == nil {
				t.Fatalf("claim = %+v, %v", claimed, err)
			}
			rule, err := db.ApplyRelayCYBLearnedRule(
				ctx,
				claimed.RequestID,
				claimed.LearningAttempts,
				"cyb_auto_guard",
				`(?i)guard\s+sample`,
				"guard test",
				"gpt-5.4",
			)
			if err != nil {
				t.Fatalf("ApplyRelayCYBLearnedRule: %v", err)
			}
			for index := 0; index < 100; index++ {
				source := "official_default"
				signals := "[]"
				if index < test.hits {
					source = "cyb_rule"
					signals = fmt.Sprintf(`["learned_rule:%s"]`, relayCYBRuleRuntimeName(*rule))
				}
				if err := db.WriteRelayAuditRequest(ctx, &database.RelayAuditRequestInput{
					RequestID:    fmt.Sprintf("guard-request-%03d", index),
					CreatedAt:    now.Add(time.Duration(index) * time.Millisecond),
					RouteSource:  source,
					RouteSignals: signals,
				}); err != nil {
					t.Fatalf("WriteRelayAuditRequest(%d): %v", index, err)
				}
			}

			handler := &Handler{db: db}
			if err := handler.enforceRelayCYBRuleGuard(ctx); err != nil {
				t.Fatalf("enforceRelayCYBRuleGuard: %v", err)
			}
			got, err := db.GetRelayCYBRule(ctx, rule.ID)
			if err != nil {
				t.Fatalf("GetRelayCYBRule: %v", err)
			}
			if got.Enabled == test.wantDisabled {
				t.Fatalf("rule enabled = %v, want disabled=%v", got.Enabled, test.wantDisabled)
			}
			events, err := db.ListRelayCYBLearningNotifications(ctx, now.Add(-time.Hour), 20)
			if err != nil {
				t.Fatalf("ListRelayCYBLearningNotifications: %v", err)
			}
			fuseEvents := 0
			for _, event := range events {
				if event.EventType == "auto_disabled" && event.RuleID == rule.ID {
					fuseEvents++
				}
			}
			wantFuseEvents := 0
			if test.wantDisabled {
				wantFuseEvents = 1
			}
			if fuseEvents != wantFuseEvents {
				t.Fatalf("fuse events = %d, want %d: %+v", fuseEvents, wantFuseEvents, events)
			}
		})
	}
}

func invokeRelayAuditCaseDetail(
	t *testing.T,
	handler *Handler,
	requestID string,
) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "request_id", Value: requestID}}
	ctx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/admin/relay-audit/cases/"+requestID,
		nil,
	)
	handler.GetRelayAuditCaseDetail(ctx)
	return recorder
}

func invokeRelayCYBLearningHandler(
	t *testing.T,
	method string,
	path string,
	body string,
	handler func(*gin.Context),
) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		ctx.Request.Header.Set("Content-Type", "application/json")
	}
	handler(ctx)
	return recorder
}
