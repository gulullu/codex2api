package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/gin-gonic/gin"
)

func TestUpdateSettingsCybRelayPersistsNormalizedConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	tokenCache := cache.NewMemory(4)
	defer tokenCache.Close()

	groupID, err := db.CreateAccountGroup(context.Background(), "cyb-relay", "", "#ef4444", 0, 0, sql.NullInt64{})
	if err != nil {
		t.Fatalf("CreateAccountGroup: %v", err)
	}
	initialSettings := testCybRelaySystemSettings()
	if err := db.UpdateSystemSettings(context.Background(), initialSettings); err != nil {
		t.Fatalf("UpdateSystemSettings: %v", err)
	}
	store := auth.NewStore(db, tokenCache, initialSettings)
	handler := NewHandler(store, db, tokenCache, proxy.NewRateLimiter(0), "admin-secret")

	body := fmt.Sprintf(`{"prompt_filter_cyb_relay_enabled":true,"prompt_filter_cyb_relay_group_id":%d,"prompt_filter_cyb_relay_session_pin_enabled":true,"prompt_filter_cyb_relay_session_pin_ttl_seconds":5}`, groupID)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", bytes.NewBufferString(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.UpdateSettings(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	var response settingsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assertCybRelaySettingsResponse(t, response, groupID, auth.MinCybRelaySessionPinTTLSeconds)

	runtimeCfg := store.GetCybRelayConfig()
	if !runtimeCfg.Enabled || runtimeCfg.GroupID != groupID || !runtimeCfg.SessionPinEnabled || runtimeCfg.SessionPinTTLSeconds != auth.MinCybRelaySessionPinTTLSeconds {
		t.Fatalf("runtime config = %+v", runtimeCfg)
	}
	persisted, err := db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings: %v", err)
	}
	if !persisted.PromptFilterCybRelayEnabled || persisted.PromptFilterCybRelayGroupID != groupID || !persisted.PromptFilterCybRelaySessionPinEnabled || persisted.PromptFilterCybRelaySessionPinTTLSeconds != auth.MinCybRelaySessionPinTTLSeconds {
		t.Fatalf("persisted config = %+v", persisted)
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
	assertCybRelaySettingsResponse(t, getResponse, groupID, auth.MinCybRelaySessionPinTTLSeconds)
}

func TestUpdateSettingsCybRelayRejectsMissingGroupBeforeRuntimeMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	tokenCache := cache.NewMemory(4)
	defer tokenCache.Close()

	initialSettings := testCybRelaySystemSettings()
	if err := db.UpdateSystemSettings(context.Background(), initialSettings); err != nil {
		t.Fatalf("UpdateSystemSettings: %v", err)
	}
	store := auth.NewStore(db, tokenCache, initialSettings)
	handler := NewHandler(store, db, tokenCache, proxy.NewRateLimiter(0), "admin-secret")

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", strings.NewReader(`{"max_concurrency":10,"prompt_filter_cyb_relay_enabled":true,"prompt_filter_cyb_relay_group_id":999999}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.UpdateSettings(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg := store.GetCybRelayConfig(); cfg.Enabled || cfg.GroupID != 0 {
		t.Fatalf("invalid update changed runtime config: %+v", cfg)
	}
	if got := store.GetMaxConcurrency(); got != initialSettings.MaxConcurrency {
		t.Fatalf("invalid update changed max concurrency to %d", got)
	}
	persisted, err := db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings: %v", err)
	}
	if persisted.PromptFilterCybRelayEnabled || persisted.PromptFilterCybRelayGroupID != 0 {
		t.Fatalf("invalid update changed persisted config: %+v", persisted)
	}
}

func TestDeleteAccountGroupRejectsEnabledCybRelayGroupEvenWithForce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	tokenCache := cache.NewMemory(4)
	defer tokenCache.Close()

	groupID, err := db.CreateAccountGroup(context.Background(), "cyb-relay", "", "#ef4444", 0, 0, sql.NullInt64{})
	if err != nil {
		t.Fatalf("CreateAccountGroup: %v", err)
	}
	settings := testCybRelaySystemSettings()
	settings.PromptFilterCybRelayEnabled = true
	settings.PromptFilterCybRelayGroupID = groupID
	settings.PromptFilterCybRelaySessionPinEnabled = true
	settings.PromptFilterCybRelaySessionPinTTLSeconds = auth.DefaultCybRelaySessionPinTTLSeconds
	if err := db.UpdateSystemSettings(context.Background(), settings); err != nil {
		t.Fatalf("UpdateSystemSettings: %v", err)
	}
	store := auth.NewStore(db, tokenCache, settings)
	handler := NewHandler(store, db, tokenCache, proxy.NewRateLimiter(0), "admin-secret")

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatInt(groupID, 10)}}
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/account-groups/"+strconv.FormatInt(groupID, 10)+"?force=true", nil)
	handler.DeleteAccountGroup(ctx)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CYB relay") {
		t.Fatalf("unexpected response body: %s", recorder.Body.String())
	}
	missing, err := db.VerifyAccountGroupIDs(context.Background(), []int64{groupID})
	if err != nil {
		t.Fatalf("VerifyAccountGroupIDs: %v", err)
	}
	if len(missing) != 0 {
		t.Fatal("enabled CYB relay group was deleted")
	}
}

func testCybRelaySystemSettings() *database.SystemSettings {
	return &database.SystemSettings{
		SiteName:                     "CodexProxy",
		MaxConcurrency:               2,
		TestModel:                    "gpt-5.4",
		TestContent:                  "hi",
		TestConcurrency:              1,
		PromptFilterMode:             "monitor",
		PromptFilterThreshold:        50,
		PromptFilterStrictThreshold:  90,
		PromptFilterMaxTextLength:    81920,
		PromptFilterCustomPatterns:   "[]",
		PromptFilterDisabledPatterns: "[]",
	}
}

func assertCybRelaySettingsResponse(t *testing.T, response settingsResponse, groupID int64, ttl int) {
	t.Helper()
	if !response.PromptFilterCybRelayEnabled || response.PromptFilterCybRelayGroupID != groupID || !response.PromptFilterCybRelaySessionPinEnabled || response.PromptFilterCybRelaySessionPinTTLSeconds != ttl {
		t.Fatalf("CYB relay response = %+v", response)
	}
}
