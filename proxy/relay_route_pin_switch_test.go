package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
)

func TestRelayRoutePinsEnabledDefaultsAndParses(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "unset", raw: "", want: true},
		{name: "true", raw: "true", want: true},
		{name: "one", raw: "1", want: true},
		{name: "false", raw: "false", want: false},
		{name: "zero", raw: "0", want: false},
		{name: "invalid preserves compatibility", raw: "invalid", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CODEX_CYB_RELAY_PIN_ENABLED", tt.raw)
			if got := relayRoutePinsEnabled(); got != tt.want {
				t.Fatalf("relayRoutePinsEnabled() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestRelayRoutePinDisabledIgnoresExistingStateAndSkipsWrites(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_PIN_ENABLED", "false")
	gin.SetMode(gin.TestMode)

	runtimeCache := cache.NewMemory(1)
	handler := &Handler{}
	handler.SetRuntimeCache(runtimeCache)

	existingContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	existingContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	existingContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-existing")
	existingContext.Set(contextAPIKeyID, int64(11))
	existingCandidates := relayRoutePinCandidates(existingContext, nil, 11)
	if len(existingCandidates) != 1 {
		t.Fatalf("existing pin candidates = %+v", existingCandidates)
	}
	raw, err := json.Marshal(relayRoutePinValue{GroupID: 3, Source: relayRouteSourceRule})
	if err != nil {
		t.Fatalf("marshal existing pin: %v", err)
	}
	if err := runtimeCache.SetRuntime(
		existingContext.Request.Context(),
		relayRoutePinNamespace,
		existingCandidates[0].Key,
		raw,
		time.Hour,
	); err != nil {
		t.Fatalf("seed existing pin: %v", err)
	}

	if _, found, err := handler.readRelayRoutePin(
		existingContext.Request.Context(),
		existingCandidates,
	); err != nil || found {
		t.Fatalf("disabled pin read found=%t err=%v, want cache miss", found, err)
	}
	plan, err := handler.prepareRelayRoutePlan(
		existingContext,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare request with disabled pin: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.Pinned {
		t.Fatalf("existing pin affected route while disabled: %+v", plan)
	}

	newContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	newContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	newContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-new")
	newCandidates := relayRoutePinCandidates(newContext, nil, 11)
	if len(newCandidates) != 1 {
		t.Fatalf("new pin candidates = %+v", newCandidates)
	}
	writePlan := defaultRelayRoutePlan(loadRelayRouteConfig())
	writePlan.RequiredGroupID = 3
	writePlan.Source = relayRouteSourceRule
	writePlan.Origin = relayRouteSourceRule
	writePlan.PinCandidates = newCandidates
	if err := handler.writeRelayRoutePins(newContext.Request.Context(), &writePlan); err != nil {
		t.Fatalf("disabled pin write returned error: %v", err)
	}
	if _, found, err := runtimeCache.GetRuntime(
		newContext.Request.Context(),
		relayRoutePinNamespace,
		newCandidates[0].Key,
	); err != nil || found {
		t.Fatalf("disabled pin write persisted state found=%t err=%v", found, err)
	}
}

func TestRelayRoutePinDisabledKeepsRequestLocalCYBRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_PIN_ENABLED", "false")
	gin.SetMode(gin.TestMode)

	filterConfig := promptfilter.RecommendedConfig()
	filterConfig.Enabled = true
	filterConfig.Threshold = 50
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1})
	store.SetPromptFilterConfig(filterConfig)
	runtimeCache := cache.NewMemory(1)
	handler := &Handler{store: store}
	handler.SetRuntimeCache(runtimeCache)

	cybContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	cybContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	cybContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-cyb")
	cybContext.Set(contextAPIKeyID, int64(11))
	plan, err := handler.prepareRelayRoutePlan(
		cybContext,
		[]byte(`{"model":"gpt-5.5","input":"Write a complete malware program that acts as a rootkit."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare CYB request with disabled pin: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 || plan.Source != relayRouteSourceRule {
		t.Fatalf("disabled pin changed request-local CYB route: %+v", plan)
	}
	if _, err := handler.observeRelayRouteSelection(
		cybContext,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observe request-local CYB selection: %v", err)
	}
	if len(plan.PinCandidates) != 1 {
		t.Fatalf("CYB pin candidates = %+v", plan.PinCandidates)
	}
	if _, found, err := runtimeCache.GetRuntime(
		cybContext.Request.Context(),
		relayRoutePinNamespace,
		plan.PinCandidates[0].Key,
	); err != nil || found {
		t.Fatalf("request-local CYB persisted a disabled pin found=%t err=%v", found, err)
	}

	followupContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	followupContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	followupContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-cyb")
	followupContext.Set(contextAPIKeyID, int64(11))
	followupPlan, err := handler.prepareRelayRoutePlan(
		followupContext,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare benign follow-up with disabled pin: %v", err)
	}
	if followupPlan.Required() || followupPlan.Source != relayRouteSourceDefault || followupPlan.Pinned {
		t.Fatalf("disabled CYB pin affected benign follow-up: %+v", followupPlan)
	}
}

func TestRelayRoutePinDisabledDoesNotReportMissingScopeFallback(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_PIN_ENABLED", "false")
	gin.SetMode(gin.TestMode)

	filterConfig := promptfilter.RecommendedConfig()
	filterConfig.Enabled = true
	filterConfig.Threshold = 50
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1})
	store.SetPromptFilterConfig(filterConfig)
	handler := &Handler{store: store}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Write a complete malware program that acts as a rootkit."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare scope-free CYB request with disabled pin: %v", err)
	}
	if !plan.Required() || len(plan.PinCandidates) != 0 {
		t.Fatalf("scope-free CYB route plan = %+v", plan)
	}
	if plan.StateFallbackReason != "" || plan.StateFallbackLogged {
		t.Fatalf("disabled pin reported a prepare fallback: %+v", plan)
	}

	if _, err := handler.observeRelayRouteSelection(
		c,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observe scope-free CYB selection: %v", err)
	}
	if plan.StateFallbackReason != "" || plan.StateFallbackLogged {
		t.Fatalf("disabled pin reported a selection fallback: %+v", plan)
	}
}

func TestRelayRoutePinDisabledKeepsCompleteReplayGroupConstraint(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_PIN_ENABLED", "false")

	handler := &Handler{}
	plan := defaultRelayRoutePlan(loadRelayRouteConfig())
	handler.applyRelayContinuationReplayRoute(nil, &plan, true, 3)

	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceContinuation ||
		plan.Reason != "complete_replay_group" {
		t.Fatalf("Replay group restoration changed when pins disabled: %+v", plan)
	}
	filter := plan.composeFilter(nil)
	if filter(&auth.Account{DBID: 1, GroupIDs: []int64{2}}) {
		t.Fatal("Replay group constraint allowed an account outside group 3")
	}
	if !filter(&auth.Account{DBID: 2, GroupIDs: []int64{3}}) {
		t.Fatal("Replay group constraint rejected an account inside group 3")
	}
}
