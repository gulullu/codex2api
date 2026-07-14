package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/gin-gonic/gin"
)

func guardianAdminTestStore(t *testing.T) (*auth.Store, cache.TokenCache) {
	t.Helper()
	tokenCache := cache.NewMemory(4)
	store := auth.NewStore(nil, tokenCache, &database.SystemSettings{MaxConcurrency: 100, TestConcurrency: 1, TestModel: "gpt-5.4", RelayGuardianMode: "enforce", PromptFilterCybRelayEnabled: true, PromptFilterCybRelayGroupID: 7})
	for _, id := range []int64{51, 50} {
		store.AddAccount(&auth.Account{DBID: id, UpstreamType: auth.UpstreamOpenAIResponses, BaseURL: "https://relay.example/v1", APIKey: "key", Status: auth.StatusReady, HealthTier: auth.HealthTierHealthy, GroupIDs: []int64{7}, Email: "relay"})
	}
	return store, tokenCache
}

func guardianSettingsTestHandler(t *testing.T, db *database.DB) (*Handler, *auth.Store, cache.TokenCache) {
	t.Helper()
	settings := testCybRelaySystemSettings()
	settings.RelayGuardianMode = "enforce"
	if err := db.UpdateSystemSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateRelayGuardianMode(context.Background(), "enforce"); err != nil {
		t.Fatal(err)
	}
	tokenCache := cache.NewMemory(4)
	store := auth.NewStore(db, tokenCache, settings)
	return NewHandler(store, db, tokenCache, proxy.NewRateLimiter(0), "admin-secret"), store, tokenCache
}

func TestGetHealthIncludesRelayGuardianAggregation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store, tokenCache := guardianAdminTestStore(t)
	defer tokenCache.Close()
	wantGuardian, wantRelay := store.RelayGuardianHealth()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/admin/health", nil)
	(&Handler{store: store}).GetHealth(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response healthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	// The handler boundary strips time.Time's process-local monotonic component.
	// Normalize the direct Store result through the same JSON representation.
	wantGuardianJSON, _ := json.Marshal(wantGuardian)
	var normalizedWantGuardian auth.RelayGuardianHealthSummary
	if err := json.Unmarshal(wantGuardianJSON, &normalizedWantGuardian); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(response.Guardian, normalizedWantGuardian) {
		t.Fatalf("guardian=%+v, want %+v", response.Guardian, normalizedWantGuardian)
	}
	if !reflect.DeepEqual(response.Relay, wantRelay) {
		t.Fatalf("relay=%+v, want %+v", response.Relay, wantRelay)
	}
}

func invokeGuardianModeUpdate(handler *Handler, mode string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"relay_guardian_mode": mode})
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/admin/settings", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.UpdateSettings(ctx)
	return recorder
}

type relayGuardianReleaseStub struct {
	status     auth.RelayGuardianAccountSnapshot
	accountID  int64
	generation uint64
	err        error
}

func (s *relayGuardianReleaseStub) ReleaseRelayGuardian(accountID int64, generation uint64) error {
	s.accountID = accountID
	s.generation = generation
	if s.err != nil {
		return s.err
	}
	s.status.State = auth.RelayGuardianHalfOpen
	s.status.Generation++
	return nil
}

func (s *relayGuardianReleaseStub) RelayGuardianAccountStatus(accountID int64) (auth.RelayGuardianAccountSnapshot, bool) {
	return s.status, s.status.AccountID == accountID
}

func TestRelayGuardianReleaseReturnsSingleAccountSnapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	before := auth.RelayGuardianAccountSnapshot{AccountID: 51, AccountName: "relay-51", State: auth.RelayGuardianQuarantined, Generation: 2}
	ops := &relayGuardianReleaseStub{status: before}
	body, _ := json.Marshal(map[string]any{"generation": before.Generation})
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "51"}}
	(&Handler{relayGuardianReleaseOps: ops}).ReleaseRelayGuardian(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response["account_id"]; !ok {
		t.Fatalf("single account snapshot missing: %v", response)
	}
	if _, ok := response["accounts"]; ok {
		t.Fatalf("endpoint returned full status: %v", response)
	}
	if generation, _ := response["generation"].(float64); uint64(generation) == before.Generation {
		t.Fatalf("generation was not refreshed: %v", response)
	}
	if ops.accountID != 51 || ops.generation != before.Generation {
		t.Fatalf("release args account=%d generation=%d", ops.accountID, ops.generation)
	}
}

func TestRelayGuardianModeUpdateReturns500WhenSettingsSaveFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	handler, store, tokenCache := guardianSettingsTestHandler(t, db)
	defer tokenCache.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := invokeGuardianModeUpdate(handler, "monitor")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.GetRelayGuardianMode() != auth.RelayGuardianEnforce {
		t.Fatalf("failed save mutated runtime mode=%s", store.GetRelayGuardianMode())
	}
}

func TestRelayGuardianModeUpdateReturns500WhenModeWriteFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "mode-trigger.db")
	db, err := database.New("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler, store, tokenCache := guardianSettingsTestHandler(t, db)
	defer tokenCache.Close()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_relay_guardian_mode BEFORE UPDATE OF relay_guardian_mode ON system_settings BEGIN SELECT RAISE(FAIL, 'forced mode write failure'); END`); err != nil {
		t.Fatal(err)
	}
	recorder := invokeGuardianModeUpdate(handler, "monitor")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.GetRelayGuardianMode() != auth.RelayGuardianEnforce {
		t.Fatalf("failed mode write mutated runtime mode=%s", store.GetRelayGuardianMode())
	}
	persisted, err := db.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.RelayGuardianMode != "enforce" {
		t.Fatalf("failed mode write persisted=%s", persisted.RelayGuardianMode)
	}
}
