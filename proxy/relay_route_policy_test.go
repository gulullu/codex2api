package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/gin-gonic/gin"
)

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

func TestRequiredRelayRouteRejectsMissingStableScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3

	if _, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err == nil {
		t.Fatal("required Relay route proceeded without a stable conversation scope")
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

func TestRelayContinuationRejectsMissingStableScope(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	if _, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_without_scope","input":"continue"}`),
		"/v1/responses",
	); err == nil {
		t.Fatal("continuation without a stable conversation scope was accepted")
	}
}
