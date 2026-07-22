package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/proxy"
	"github.com/gin-gonic/gin"
)

func TestUpdateSettingsWSIdleReclaimHotPersistsAndNormalizes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousRuntime := proxy.CurrentRuntimeSettings()
	t.Cleanup(func() { proxy.ApplyRuntimeSettings(previousRuntime) })

	db := newTestAdminDB(t)
	tokenCache := cache.NewMemory(4)
	t.Cleanup(func() { _ = tokenCache.Close() })
	settings := defaultBootstrapSettings()
	settings.CodexWSIdleReclaimIdleSec = 600
	if err := db.UpdateSystemSettings(context.Background(), settings); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	store := auth.NewStore(db, tokenCache, settings)
	t.Cleanup(store.Stop)
	proxy.ApplyRuntimeSettingsFromSystem(settings)
	handler := NewHandler(store, db, tokenCache, proxy.NewRateLimiter(settings.GlobalRPM), "admin-secret")

	update := func(body string) settingsResponse {
		t.Helper()
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		handler.UpdateSettings(ctx)
		if recorder.Code != http.StatusOK {
			t.Fatalf("PUT status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
		}
		var response settingsResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode PUT response: %v", err)
		}
		return response
	}

	valid := update(`{"codex_ws_idle_reclaim_enabled":true,"codex_ws_idle_reclaim_percent":5,"codex_ws_idle_reclaim_idle_sec":900}`)
	assertWSIdleReclaimSettings(t, valid, true, 5, 900)
	if !store.CodexWSIdleReclaimEnabled() || store.CodexWSIdleReclaimPercent() != 5 || store.CodexWSIdleReclaimIdleSec() != 900 {
		t.Fatalf("store idle reclaim = enabled:%v percent:%d idle:%d, want true/5/900", store.CodexWSIdleReclaimEnabled(), store.CodexWSIdleReclaimPercent(), store.CodexWSIdleReclaimIdleSec())
	}
	runtime := proxy.CurrentRuntimeSettings()
	if !runtime.CodexWSIdleReclaimEnabled || runtime.CodexWSIdleReclaimPercent != 5 || runtime.CodexWSIdleReclaimIdleSec != 900 {
		t.Fatalf("runtime idle reclaim = enabled:%v percent:%d idle:%d, want true/5/900", runtime.CodexWSIdleReclaimEnabled, runtime.CodexWSIdleReclaimPercent, runtime.CodexWSIdleReclaimIdleSec)
	}
	persisted, err := db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings(valid): %v", err)
	}
	if !persisted.CodexWSIdleReclaimEnabled || persisted.CodexWSIdleReclaimPercent != 5 || persisted.CodexWSIdleReclaimIdleSec != 900 {
		t.Fatalf("persisted idle reclaim = enabled:%v percent:%d idle:%d, want true/5/900", persisted.CodexWSIdleReclaimEnabled, persisted.CodexWSIdleReclaimPercent, persisted.CodexWSIdleReclaimIdleSec)
	}

	invalid := update(`{"codex_ws_idle_reclaim_percent":17,"codex_ws_idle_reclaim_idle_sec":60}`)
	assertWSIdleReclaimSettings(t, invalid, true, 0, 600)
	runtime = proxy.CurrentRuntimeSettings()
	if !runtime.CodexWSIdleReclaimEnabled || runtime.CodexWSIdleReclaimPercent != 0 || runtime.CodexWSIdleReclaimIdleSec != 600 {
		t.Fatalf("normalized runtime idle reclaim = enabled:%v percent:%d idle:%d, want true/0/600", runtime.CodexWSIdleReclaimEnabled, runtime.CodexWSIdleReclaimPercent, runtime.CodexWSIdleReclaimIdleSec)
	}

	partial := update(`{"site_name":"Idle Reclaim Test"}`)
	assertWSIdleReclaimSettings(t, partial, true, 0, 600)
	persisted, err = db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings(partial): %v", err)
	}
	if !persisted.CodexWSIdleReclaimEnabled || persisted.CodexWSIdleReclaimPercent != 0 || persisted.CodexWSIdleReclaimIdleSec != 600 {
		t.Fatalf("partial update changed idle reclaim = enabled:%v percent:%d idle:%d", persisted.CodexWSIdleReclaimEnabled, persisted.CodexWSIdleReclaimPercent, persisted.CodexWSIdleReclaimIdleSec)
	}

	getRecorder := httptest.NewRecorder()
	getCtx, _ := gin.CreateTestContext(getRecorder)
	getCtx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	handler.GetSettings(getCtx)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 body=%s", getRecorder.Code, getRecorder.Body.String())
	}
	var getResponse settingsResponse
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &getResponse); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	assertWSIdleReclaimSettings(t, getResponse, true, 0, 600)
}

func assertWSIdleReclaimSettings(t *testing.T, response settingsResponse, enabled bool, percent, idleSec int) {
	t.Helper()
	if response.CodexWSIdleReclaimEnabled != enabled || response.CodexWSIdleReclaimPercent != percent || response.CodexWSIdleReclaimIdleSec != idleSec {
		t.Fatalf("response idle reclaim = enabled:%v percent:%d idle:%d, want %v/%d/%d", response.CodexWSIdleReclaimEnabled, response.CodexWSIdleReclaimPercent, response.CodexWSIdleReclaimIdleSec, enabled, percent, idleSec)
	}
}
