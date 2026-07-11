package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/gin-gonic/gin"
)

func TestMergeAdminSemanticReviewProvidersPreservesBlankAPIKeyByID(t *testing.T) {
	existing := []proxy.SemanticReviewProvider{{
		ID:             "provider-a",
		Name:           "Provider A",
		Enabled:        true,
		BaseURL:        "https://semantic-a.example.com/v1",
		Model:          "review-model-a",
		APIKey:         "stored-secret-key",
		TimeoutMS:      1200,
		MaxConcurrency: 3,
	}}
	incoming := []proxy.SemanticReviewProvider{{
		ID:               "provider-a",
		Name:             "Provider A renamed",
		Enabled:          true,
		BaseURL:          "https://semantic-a.example.com/v1",
		Model:            "review-model-a",
		APIKeyConfigured: true,
		TimeoutMS:        1500,
		MaxConcurrency:   4,
	}}

	merged, err := mergeAdminSemanticReviewProviders(existing, incoming, 2500, 4)
	if err != nil {
		t.Fatalf("mergeAdminSemanticReviewProviders: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("provider count = %d, want 1", len(merged))
	}
	if merged[0].APIKey != "stored-secret-key" {
		t.Fatalf("api key was not preserved by provider id")
	}
	if merged[0].Name != "Provider A renamed" {
		t.Fatalf("name = %q, want updated name", merged[0].Name)
	}
}

func TestSemanticReviewProviderResponsesNeverExposeAPIKeys(t *testing.T) {
	providers := []proxy.SemanticReviewProvider{{
		ID:             "provider-a",
		Name:           "Provider A",
		Enabled:        true,
		BaseURL:        "https://semantic-a.example.com/v1",
		Model:          "review-model-a",
		APIKey:         "stored-secret-key",
		TimeoutMS:      1200,
		MaxConcurrency: 3,
	}}

	responses := semanticReviewProviderResponses(providers)
	if len(responses) != 1 || !responses[0].APIKeyConfigured {
		t.Fatalf("sanitized provider did not report configured key: %+v", responses)
	}
	if responses[0].APIKey != "" {
		t.Fatal("sanitized provider retained api key")
	}
	encoded, err := json.Marshal(responses)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "stored-secret-key") {
		t.Fatalf("serialized response leaked api key: %s", encoded)
	}
}

func TestResolvePromptFilterSemanticReviewUsesPoolPrimaryProvider(t *testing.T) {
	pool := proxy.SemanticReviewProviderPool{
		Strategy: "round_robin",
		Providers: []proxy.SemanticReviewProvider{
			{
				ID:             "provider-a",
				Name:           "Provider A",
				Enabled:        true,
				BaseURL:        "https://semantic-a.example.com/v1",
				Model:          "review-model-a",
				APIKey:         "provider-a-key",
				TimeoutMS:      1300,
				MaxConcurrency: 3,
			},
			{
				ID:             "provider-b",
				Name:           "Provider B",
				Enabled:        true,
				BaseURL:        "https://semantic-b.example.com/v1",
				Model:          "review-model-b",
				APIKey:         "provider-b-key",
				TimeoutMS:      1700,
				MaxConcurrency: 5,
			},
		},
	}
	rawPool, err := proxy.MarshalSemanticReviewProviderPool(pool)
	if err != nil {
		t.Fatalf("MarshalSemanticReviewProviderPool: %v", err)
	}

	resolved := resolvePromptFilterSemanticReview(&database.SystemSettings{
		PromptFilterSemanticReviewEnabled:      true,
		PromptFilterSemanticReviewProviderPool: rawPool,
	})
	if resolved.Strategy != "round_robin" || len(resolved.Providers) != 2 {
		t.Fatalf("resolved pool = strategy %q providers %d", resolved.Strategy, len(resolved.Providers))
	}
	if resolved.APIKey != "provider-a-key" || resolved.BaseURL != "https://semantic-a.example.com/v1" || resolved.Model != "review-model-a" {
		t.Fatalf("legacy response fields did not mirror primary provider: %+v", resolved)
	}
	if resolved.TimeoutMS != 1300 || resolved.MaxConcurrency != 3 {
		t.Fatalf("primary limits = timeout %d concurrency %d", resolved.TimeoutMS, resolved.MaxConcurrency)
	}
}

func TestUpdateSettingsProviderPoolPreservesSecretAndRedactsResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	tokenCache := cache.NewMemory(4)
	defer tokenCache.Close()

	initialPool := proxy.SemanticReviewProviderPool{
		Strategy: "round_robin",
		Providers: []proxy.SemanticReviewProvider{{
			ID:             "provider-a",
			Name:           "Provider A",
			Enabled:        true,
			BaseURL:        "https://semantic-a.example.com/v1",
			Model:          "review-model-a",
			APIKey:         "stored-secret-key",
			TimeoutMS:      1200,
			MaxConcurrency: 3,
		}},
	}
	rawPool, err := proxy.MarshalSemanticReviewProviderPool(initialPool)
	if err != nil {
		t.Fatalf("MarshalSemanticReviewProviderPool: %v", err)
	}
	initialSettings := &database.SystemSettings{
		SiteName:                                   "CodexProxy",
		MaxConcurrency:                             2,
		TestModel:                                  "gpt-5.4",
		TestContent:                                "hi",
		TestConcurrency:                            1,
		PromptFilterMode:                           "monitor",
		PromptFilterThreshold:                      50,
		PromptFilterStrictThreshold:                90,
		PromptFilterMaxTextLength:                  81920,
		PromptFilterCustomPatterns:                 "[]",
		PromptFilterDisabledPatterns:               "[]",
		PromptFilterSemanticReviewEnabled:          true,
		PromptFilterSemanticReviewAPIKey:           "stored-secret-key",
		PromptFilterSemanticReviewBaseURL:          "https://semantic-a.example.com/v1",
		PromptFilterSemanticReviewModel:            "review-model-a",
		PromptFilterSemanticReviewTimeoutMS:        1200,
		PromptFilterSemanticReviewMaxConcurrency:   3,
		PromptFilterSemanticReviewFailurePolicy:    "block",
		PromptFilterSemanticReviewLogRetentionDays: 7,
		PromptFilterSemanticReviewProviderPool:     rawPool,
	}
	if err := db.UpdateSystemSettings(context.Background(), initialSettings); err != nil {
		t.Fatalf("UpdateSystemSettings: %v", err)
	}
	store := auth.NewStore(db, tokenCache, initialSettings)
	handler := NewHandler(store, db, tokenCache, proxy.NewRateLimiter(0), "admin-secret")

	body := []byte(`{"prompt_filter_semantic_review_strategy":"random","prompt_filter_semantic_review_providers":[{"id":"provider-a","name":"Provider A renamed","enabled":true,"base_url":"https://semantic-a.example.com/v1","model":"review-model-a","api_key_configured":true,"timeout_ms":1500,"max_concurrency":4}]}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler.UpdateSettings(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "stored-secret-key") {
		t.Fatalf("settings response leaked provider secret: %s", recorder.Body.String())
	}
	var response settingsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.PromptFilterSemanticReviewStrategy != "random" || len(response.PromptFilterSemanticReviewProviders) != 1 {
		t.Fatalf("response pool = strategy %q providers %d", response.PromptFilterSemanticReviewStrategy, len(response.PromptFilterSemanticReviewProviders))
	}
	if !response.PromptFilterSemanticReviewProviders[0].APIKeyConfigured || response.PromptFilterSemanticReviewProviders[0].APIKey != "" {
		t.Fatalf("response provider secret metadata is unsafe: %+v", response.PromptFilterSemanticReviewProviders[0])
	}

	persisted, err := db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings: %v", err)
	}
	persistedPool, err := proxy.ParseSemanticReviewProviderPool(persisted.PromptFilterSemanticReviewProviderPool)
	if err != nil {
		t.Fatalf("ParseSemanticReviewProviderPool: %v", err)
	}
	if persistedPool.Strategy != "random" || len(persistedPool.Providers) != 1 {
		t.Fatalf("persisted pool = strategy %q providers %d", persistedPool.Strategy, len(persistedPool.Providers))
	}
	if persistedPool.Providers[0].APIKey != "stored-secret-key" {
		t.Fatal("persisted provider api key was not preserved")
	}
	if persisted.PromptFilterSemanticReviewAPIKey != "stored-secret-key" || persisted.PromptFilterSemanticReviewTimeoutMS != 1500 || persisted.PromptFilterSemanticReviewMaxConcurrency != 4 {
		t.Fatalf("legacy fields were not synchronized to primary provider")
	}

	emptyRecorder := httptest.NewRecorder()
	emptyCtx, _ := gin.CreateTestContext(emptyRecorder)
	emptyCtx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", strings.NewReader(`{"prompt_filter_semantic_review_providers":[]}`))
	emptyCtx.Request.Header.Set("Content-Type", "application/json")
	handler.UpdateSettings(emptyCtx)
	if emptyRecorder.Code != http.StatusOK {
		t.Fatalf("empty pool status = %d, want 200 body=%s", emptyRecorder.Code, emptyRecorder.Body.String())
	}
	var emptyResponse settingsResponse
	if err := json.Unmarshal(emptyRecorder.Body.Bytes(), &emptyResponse); err != nil {
		t.Fatalf("decode empty pool response: %v", err)
	}
	if len(emptyResponse.PromptFilterSemanticReviewProviders) != 0 {
		t.Fatalf("empty pool response providers = %d, want 0", len(emptyResponse.PromptFilterSemanticReviewProviders))
	}
	persisted, err = db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings after empty pool: %v", err)
	}
	if strings.TrimSpace(persisted.PromptFilterSemanticReviewProviderPool) == "" {
		t.Fatal("explicit empty provider pool was collapsed to legacy fallback")
	}
	if persisted.PromptFilterSemanticReviewAPIKey != "" {
		t.Fatal("deleting the final provider retained the legacy api key")
	}
	emptyPool, err := proxy.ParseSemanticReviewProviderPool(persisted.PromptFilterSemanticReviewProviderPool)
	if err != nil || len(emptyPool.Providers) != 0 {
		t.Fatalf("persisted explicit empty pool = %+v, err=%v", emptyPool, err)
	}
	legacyTestRecorder := httptest.NewRecorder()
	legacyTestCtx, _ := gin.CreateTestContext(legacyTestRecorder)
	legacyTestCtx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/prompt-filter/semantic-review/test", strings.NewReader(`{}`))
	legacyTestCtx.Request.Header.Set("Content-Type", "application/json")
	handler.TestPromptFilterSemanticReview(legacyTestCtx)
	if legacyTestRecorder.Code != http.StatusBadRequest {
		t.Fatalf("empty pool legacy test status = %d, want 400 body=%s", legacyTestRecorder.Code, legacyTestRecorder.Body.String())
	}
}

func TestSemanticReviewConnectionTestUsesDraftProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer draft-key" {
			t.Errorf("authorization = %q, want draft key", got)
		}
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode semantic review request: %v", err)
		}
		if request.Model != "draft-model" {
			t.Errorf("model = %q, want draft-model", request.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"draft-model","choices":[{"message":{"content":"{\"block\":false,\"confidence\":0.1,\"category\":\"benign\",\"reason\":\"ok\"}"}}]}`))
	}))
	defer server.Close()

	db := newTestAdminDB(t)
	handler := &Handler{db: db}
	body, err := json.Marshal(map[string]any{
		"endpoint":      "/v1/responses",
		"request_model": "gpt-5.4",
		"provider": proxy.SemanticReviewProvider{
			ID: "draft", Name: "Draft provider", Enabled: true, BaseURL: server.URL,
			Model: "draft-model", APIKey: "draft-key", TimeoutMS: 2000, MaxConcurrency: 1,
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/admin/prompt-filter/semantic-review/test", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.TestPromptFilterSemanticReview(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	var result proxy.SemanticReviewConnectionTestResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.OK || result.ProviderID != "draft" || result.ProviderName != "Draft provider" {
		t.Fatalf("draft provider result = %+v", result)
	}
}
