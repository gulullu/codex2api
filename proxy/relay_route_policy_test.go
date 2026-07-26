package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

type relayRouteFailingRuntimeCache struct {
	cache.TokenCache
	getErr error
	setErr error
}

func (c *relayRouteFailingRuntimeCache) GetRuntime(
	context.Context,
	string,
	string,
) (json.RawMessage, bool, error) {
	return nil, false, c.getErr
}

func (c *relayRouteFailingRuntimeCache) SetRuntime(
	context.Context,
	string,
	string,
	json.RawMessage,
	time.Duration,
) error {
	return c.setErr
}

func TestLoadRelayRouteConfig(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_PIN_TTL_SECONDS", "900")

	cfg := loadRelayRouteConfig()
	if !cfg.Enabled || cfg.GroupID != 3 || cfg.PinTTL != 15*time.Minute {
		t.Fatalf("loadRelayRouteConfig() = %+v", cfg)
	}

	t.Setenv("CODEX_CYB_RELAY_ENABLED", "false")
	if loadRelayRouteConfig().Enabled {
		t.Fatal("explicit disable must win over a configured group")
	}
}

func TestRequireRelayGroupFilterOnlyChecksGroup(t *testing.T) {
	inGroup := &auth.Account{DBID: 1, GroupIDs: []int64{3}}
	outside := &auth.Account{DBID: 2, GroupIDs: []int64{4}}
	filter := requireRelayGroupFilter(nil, 3)

	if !filter(inGroup) {
		t.Fatal("account in the required group was rejected")
	}
	if filter(outside) {
		t.Fatal("account outside the required group was accepted")
	}
}

func TestRelayRoutePinCandidatesSeparateTrustedAffinitiesOnSharedKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	makeContext := func(affinity string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		req.Header.Set(downstreamAffinityHeader, affinity)
		c.Request = req
		return c
	}

	a := relayRoutePinCandidates(makeContext("user-a:conversation-1"), []byte(`{"model":"gpt-5.5"}`), 9)
	b := relayRoutePinCandidates(makeContext("user-b:conversation-1"), []byte(`{"model":"gpt-5.5"}`), 9)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("candidate counts = %d/%d, want 1/1", len(a), len(b))
	}
	if a[0].Key == b[0].Key {
		t.Fatal("different trusted affinities sharing one API key produced the same pin key")
	}
}

func TestRelayRoutePinCandidatesTrustGatewayAffinityExclusively(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	req.Header.Set("Session-Id", "client-controlled-session")
	c.Request = req

	candidates := relayRoutePinCandidates(
		c,
		[]byte(`{"prompt_cache_key":"client-cache","previous_response_id":"resp_client"}`),
		9,
	)
	if len(candidates) != 1 || candidates[0].Kind != "trusted_affinity" {
		t.Fatalf("candidates = %+v, want only trusted_affinity", candidates)
	}
}

func TestRelayRoutePinCandidatesUseOfficialExplicitSessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set("Idempotency-Key", "request-123")
	c.Request = req

	candidates := relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 9)
	if len(candidates) != 1 || candidates[0].Kind != "explicit_session" {
		t.Fatalf("candidates = %+v, want Idempotency-Key explicit session", candidates)
	}
	want := relayRoutePinCacheKey(9, "explicit_session", ResolveExplicitSessionID(req.Header, nil))
	if candidates[0].Key != want {
		t.Fatalf("candidate key = %q, want %q", candidates[0].Key, want)
	}
}

func TestOrdinaryRequestWithoutStableScopeStaysOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("ordinary request returned an error: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.StateFallbackLogged {
		t.Fatalf("ordinary route plan = %+v", plan)
	}
}

func TestOrdinaryRequestWithPinMissStaysOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("ordinary pin miss returned an error: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.StateFallbackLogged {
		t.Fatalf("ordinary pin-miss plan = %+v", plan)
	}
}

func TestProbeWithoutStableScopeRoutesRelayWithoutError(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"ping"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("probe without stable scope returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 || plan.Source != relayRouteSourceProbe {
		t.Fatalf("probe route plan = %+v", plan)
	}
	if !plan.SkipPinPersistence || plan.StateFallbackReason != "missing_scope" {
		t.Fatalf("probe fallback state = %+v", plan)
	}
}

func TestObserveRelayRouteSelectionLocksOverflowToGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	plan.PinCandidates = relayRoutePinCandidates(c, nil, 11)
	account := &auth.Account{DBID: 7, GroupIDs: []int64{3}}

	becameOverflow, err := handler.observeRelayRouteSelection(c, &plan, account)
	if err != nil {
		t.Fatalf("observeRelayRouteSelection() error = %v", err)
	}
	if !becameOverflow || !plan.Required() || plan.Source != relayRouteSourceOverflow {
		t.Fatalf("overflow plan = %+v", plan)
	}
	if !plan.composeFilter(nil)(account) {
		t.Fatal("locked overflow filter rejected the selected group")
	}
	if plan.composeFilter(nil)(&auth.Account{DBID: 8, GroupIDs: []int64{4}}) {
		t.Fatal("locked overflow filter allowed a different group")
	}
}

func TestOverflowWithoutStableScopeKeepsRelaySelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("overflow without stable scope returned an error: %v", err)
	}
	if !becameOverflow || !plan.Required() || plan.Source != relayRouteSourceOverflow {
		t.Fatalf("overflow plan = %+v", plan)
	}
	if !plan.SkipPinPersistence || plan.StateFallbackReason != "missing_scope" {
		t.Fatalf("overflow fallback state = %+v", plan)
	}
}

func TestRequiredRelayRouteWithoutStableScopeSkipsPin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("required Relay route failed without a stable conversation scope: %v", err)
	}
	if becameOverflow {
		t.Fatal("already-required Relay route was marked as overflow")
	}
	if !plan.SkipPinPersistence {
		t.Fatal("missing stable scope did not disable pin persistence")
	}
	if plan.StateFallbackReason != "missing_scope" || !plan.StateFallbackLogged {
		t.Fatalf("missing-scope fallback state = %+v", plan)
	}
}

func TestRelayRoutePinRoundTripStoresGroupNotAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceRule
	plan.Origin = relayRouteSourceRule
	plan.PinCandidates = relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 11)
	if err := handler.writeRelayRoutePins(c.Request.Context(), &plan); err != nil {
		t.Fatalf("writeRelayRoutePins() error = %v", err)
	}

	pin, found, err := handler.readRelayRoutePin(c.Request.Context(), plan.PinCandidates)
	if err != nil || !found {
		t.Fatalf("readRelayRoutePin() found=%t err=%v", found, err)
	}
	if pin.GroupID != 3 || pin.Source != relayRouteSourceRule {
		t.Fatalf("pin = %+v", pin)
	}
}

func TestRelayFeedbackRouteDoesNotPersistConversationPin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceFeedback
	plan.Origin = relayRouteSourceFeedback
	plan.SkipPinPersistence = true
	plan.PinCandidates = relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 11)
	if err := handler.writeRelayRoutePins(c.Request.Context(), &plan); err != nil {
		t.Fatalf("writeRelayRoutePins() error = %v", err)
	}

	if _, found, err := handler.readRelayRoutePin(c.Request.Context(), plan.PinCandidates); err != nil || found {
		t.Fatalf("feedback-only pin found=%t err=%v, want no persisted pin", found, err)
	}
}

func TestRelayRoutePinRejectsCorruptCachedState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(candidates))
	}
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		json.RawMessage(`{"group_id":0}`),
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}
	if _, _, err := handler.readRelayRoutePin(c.Request.Context(), candidates); err == nil {
		t.Fatal("corrupt pin state was silently treated as a cache miss")
	}
}

func TestRelayContinuationWithoutStableScopeFallsBackToRelay(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_without_scope","input":"continue"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("continuation without stable scope returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 {
		t.Fatalf("continuation fallback plan = %+v", plan)
	}
	if plan.Source != relayRouteSourceContinuation {
		t.Fatalf("continuation fallback source = %q", plan.Source)
	}
	if plan.Reason != "missing_scope" || plan.StateFallbackReason != "missing_scope" {
		t.Fatalf("continuation fallback reason = %q", plan.Reason)
	}
}

func TestRelayContinuationWithPinMissFallsBackToRelay(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_without_pin","input":"continue"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("continuation pin miss returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceContinuation ||
		plan.Reason != "pin_miss_continuation" ||
		plan.StateFallbackReason != "pin_miss_continuation" {
		t.Fatalf("continuation pin-miss plan = %+v", plan)
	}
}

func TestRelayRoutePinReadFailureFallsBackToRelay(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		getErr:     errors.New("redis unavailable"),
	})

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("pin read failure returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceDefault ||
		plan.Reason != "pin_read_error" ||
		plan.StateFallbackReason != "pin_read_error" {
		t.Fatalf("pin read fallback plan = %+v", plan)
	}
}

func TestRelayRouteCorruptPinFallsBackToRelay(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		json.RawMessage(`{"group_id":0}`),
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("corrupt pin returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Reason != "pin_invalid" ||
		plan.StateFallbackReason != "pin_invalid" {
		t.Fatalf("corrupt pin fallback plan = %+v", plan)
	}
}

func TestRelayRouteStalePinFallsBackToConfiguredGroup(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	raw, err := json.Marshal(relayRoutePinValue{GroupID: 8, Source: relayRouteSourceRule})
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		raw,
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("stale pin returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Reason != "pin_invalid" ||
		plan.StateFallbackReason != "pin_invalid" {
		t.Fatalf("stale pin fallback plan = %+v", plan)
	}
}

func TestRelayRoutePinWriteFailureKeepsRelaySelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	handler := &Handler{}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		setErr:     errors.New("redis unavailable"),
	})
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceRule
	plan.Origin = relayRouteSourceRule
	plan.PinCandidates = relayRoutePinCandidates(c, nil, 11)

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("pin write failure returned an error: %v", err)
	}
	if becameOverflow {
		t.Fatal("already-required Relay route was marked as overflow")
	}
	if !plan.SkipPinPersistence || plan.SelectionCount != 1 {
		t.Fatalf("pin write fallback plan = %+v", plan)
	}
	if plan.StateFallbackReason != "pin_write_error" || !plan.StateFallbackLogged {
		t.Fatalf("pin write fallback state = %+v", plan)
	}
}

func TestRelayRouteStateFallbackMetricPersistsOncePerRequest(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("database.New(sqlite): %v", err)
	}
	defer db.Close()

	handler := &Handler{db: db}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		getErr:     errors.New("redis read unavailable"),
		setErr:     errors.New("redis write unavailable"),
	})
	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepareRelayRoutePlan() error = %v", err)
	}
	if _, err := handler.observeRelayRouteSelection(
		c,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observeRelayRouteSelection() error = %v", err)
	}
	if !db.WaitPromptFilterAuditIdle(t.Context()) {
		t.Fatal("prompt-filter audit queue did not become idle")
	}
	stats, err := db.GetRelayRouteStats(t.Context(), 24*time.Hour)
	if err != nil {
		t.Fatalf("GetRelayRouteStats() error = %v", err)
	}
	if stats.StateFallbacks != 1 {
		t.Fatalf("state_fallbacks = %d, want 1", stats.StateFallbacks)
	}
	if stats.RouteAttempts != 1 || stats.LogicalRoutes != 1 {
		t.Fatalf(
			"fallback route totals = attempts:%d logical:%d, want 1/1",
			stats.RouteAttempts,
			stats.LogicalRoutes,
		)
	}
}
