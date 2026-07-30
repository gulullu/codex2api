package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type relayReplayProviderFunc func(
	context.Context,
	RelayContinuationReplayQuery,
) (RelayContinuationReplaySnapshot, error)

func (f relayReplayProviderFunc) ResolveRelayContinuation(
	ctx context.Context,
	query RelayContinuationReplayQuery,
) (RelayContinuationReplaySnapshot, error) {
	return f(ctx, query)
}

func setRelayReplayProviderForTest(t *testing.T, provider RelayContinuationReplayProvider) {
	t.Helper()
	relayContinuationReplayProviderState.mu.Lock()
	previous := relayContinuationReplayProviderState.provider
	relayContinuationReplayProviderState.provider = provider
	relayContinuationReplayProviderState.mu.Unlock()
	t.Cleanup(func() {
		relayContinuationReplayProviderState.mu.Lock()
		relayContinuationReplayProviderState.provider = previous
		relayContinuationReplayProviderState.mu.Unlock()
	})
}

func setRelayReplayStoreForTest(t *testing.T, store *relayContinuationReplayStore) {
	t.Helper()
	previous := relayReplayStore
	relayReplayStore = store
	setRelayReplayProviderForTest(t, nil)
	t.Cleanup(func() {
		relayReplayStore = previous
	})
}

func testRelayReplayStore() *relayContinuationReplayStore {
	return newRelayContinuationReplayStore(defaultRelayReplayLimits)
}

func TestPrepareRelayContinuationHTTPFallbackNoContinuation(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	original := []byte(`{"model":"gpt-5.4","input":"hello"}`)
	body, replayed, source, groupID, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:1",
		original,
	)
	if err != nil {
		t.Fatalf("PrepareRelayContinuationHTTPFallback: %v", err)
	}
	if replayed || source != "" || groupID != 0 || string(body) != string(original) {
		t.Fatalf("ordinary request changed: replayed=%v source=%q group=%d body=%s", replayed, source, groupID, body)
	}
}

func TestRelayContinuationReplayBuildsCumulativeStandaloneHistory(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	initial := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}]
	}`)
	completed := []byte(`{
		"type":"response.completed",
		"response":{
			"id":"resp_1",
			"output":[
				{"type":"reasoning","id":"rs_1","encrypted_content":"secret"},
				{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer","annotations":[]}]}
			]
		}
	}`)
	cacheRelayContinuationReplay("key:1", initial, true, 3, completed, nil)

	current := []byte(`{
		"model":"gpt-5.5",
		"stream":true,
		"previous_response_id":"resp_1",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]
	}`)
	body, replayed, source, groupID, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:1",
		current,
	)
	if err != nil {
		t.Fatalf("PrepareRelayContinuationHTTPFallback: %v", err)
	}
	if !replayed || source != "memory" {
		t.Fatalf("replayed=%v source=%q", replayed, source)
	}
	if groupID != 3 {
		t.Fatalf("relay group=%d want=3", groupID)
	}
	if gjson.GetBytes(body, "previous_response_id").Exists() {
		t.Fatalf("standalone body retained previous_response_id: %s", body)
	}
	if got := gjson.GetBytes(body, "model").String(); got != "gpt-5.5" {
		t.Fatalf("current model was not preserved: %q", got)
	}
	input := gjson.GetBytes(body, "input").Array()
	if len(input) != 3 {
		t.Fatalf("input count=%d want=3 body=%s", len(input), body)
	}
	if got := input[0].Get("content.0.text").String(); got != "first" {
		t.Fatalf("first turn=%q", got)
	}
	if got := input[1].Get("content.0.text").String(); got != "answer" {
		t.Fatalf("assistant turn=%q", got)
	}
	if got := input[2].Get("content.0.text").String(); got != "continue" {
		t.Fatalf("current turn=%q", got)
	}
	if strings.Contains(string(body), "encrypted_content") ||
		strings.Contains(string(body), `"id"`) ||
		strings.Contains(string(body), `"status"`) ||
		strings.Contains(string(body), `"type":"reasoning"`) {
		t.Fatalf("provider-specific state leaked into standalone replay: %s", body)
	}
}

func TestRelayContinuationReplayPreservesToolCallPair(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	initial := []byte(`{"model":"gpt-5.4","input":[{"role":"user","content":"run it"}]}`)
	completed := []byte(`{
		"type":"response.completed",
		"response":{
			"id":"resp_tool",
			"output":[
				{"type":"function_call","id":"fc_provider","status":"completed","call_id":"call_1","name":"lookup","arguments":{"q":"x"}}
			]
		}
	}`)
	cacheRelayContinuationReplay("key:1", initial, true, 0, completed, nil)

	current := []byte(`{
		"model":"gpt-5.4",
		"previous_response_id":"resp_tool",
		"input":[{"type":"function_call_output","id":"out_provider","status":"completed","call_id":"call_1","output":"ok","encrypted_content":"drop"}]
	}`)
	body, replayed, _, _, err := PrepareRelayContinuationHTTPFallback(context.Background(), "key:1", current)
	if err != nil || !replayed {
		t.Fatalf("prepare replayed=%v err=%v", replayed, err)
	}
	input := gjson.GetBytes(body, "input").Array()
	if len(input) != 3 {
		t.Fatalf("input count=%d want=3 body=%s", len(input), body)
	}
	call := input[1]
	output := input[2]
	if call.Get("type").String() != "function_call" ||
		call.Get("call_id").String() != "call_1" ||
		output.Get("type").String() != "function_call_output" ||
		output.Get("call_id").String() != "call_1" {
		t.Fatalf("tool pair not preserved: %s", body)
	}
	if call.Get("arguments").Type != gjson.String {
		t.Fatalf("function_call arguments were not normalized to string: %s", call.Raw)
	}
	if strings.Contains(string(body), `"id"`) ||
		strings.Contains(string(body), `"status"`) ||
		strings.Contains(string(body), "encrypted_content") {
		t.Fatalf("provider state leaked: %s", body)
	}
}

func TestRelayContinuationReplayIsIsolatedByAPIKeyOwner(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	cacheRelayContinuationReplay(
		"key:1",
		[]byte(`{"model":"gpt-5.4","input":"secret"}`),
		true,
		0,
		[]byte(`{"id":"resp_owner","output":[{"type":"message","role":"assistant","content":"answer"}]}`),
		nil,
	)
	_, _, _, _, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:2",
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_owner","input":"continue"}`),
	)
	var replayErr *RelayContinuationReplayError
	if !errors.As(err, &replayErr) ||
		replayErr.Reason != RelayReplayCacheMiss ||
		!errors.Is(err, ErrRelayContinuationReplayUnavailable) {
		t.Fatalf("cross-owner error=%#v", err)
	}
}

func TestRelayContinuationReplayUsesStableScopeWhenAvailable(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	ownerA := relayContinuationReplayOwner("key:1", "conversation-a")
	ownerB := relayContinuationReplayOwner("key:1", "conversation-b")
	if ownerA == ownerB || strings.Contains(ownerA, "conversation-a") {
		t.Fatalf("scoped owners are not isolated and opaque: %q %q", ownerA, ownerB)
	}
	cacheRelayContinuationReplay(
		ownerA,
		[]byte(`{"model":"gpt-5.4","input":"secret"}`),
		true,
		0,
		[]byte(`{"id":"resp_scoped","output":[{"type":"message","role":"assistant","content":"answer"}]}`),
		nil,
	)
	_, _, _, _, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		ownerB,
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_scoped","input":"continue"}`),
	)
	var replayErr *RelayContinuationReplayError
	if !errors.As(err, &replayErr) || replayErr.Reason != RelayReplayCacheMiss {
		t.Fatalf("cross-scope error=%#v", err)
	}
}

func TestRelayContinuationStableScopeIgnoresPerRequestIdempotencyKey(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", "per-request-value")
	if scope := relayContinuationStableScope(headers, nil); scope != "" {
		t.Fatalf("idempotency key became a continuation scope: %q", scope)
	}
	headers.Set("Conversation-Id", "conversation-1")
	if scope := relayContinuationStableScope(headers, nil); scope != "conversation-1" {
		t.Fatalf("conversation scope=%q", scope)
	}
}

func TestRelayContinuationReplayDoesNotPromoteIncompleteChild(t *testing.T) {
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	cacheRelayContinuationReplay(
		"key:1",
		[]byte(`{"model":"gpt-5.4","previous_response_id":"missing","input":"continue"}`),
		false,
		0,
		[]byte(`{"id":"resp_partial","output":[{"type":"message","role":"assistant","content":"partial"}]}`),
		nil,
	)
	_, _, _, _, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:1",
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_partial","input":"again"}`),
	)
	var replayErr *RelayContinuationReplayError
	if !errors.As(err, &replayErr) || replayErr.Reason != RelayReplayCacheMiss {
		t.Fatalf("partial child lookup error=%#v", err)
	}
}

func TestRelayContinuationReplayTTLAndLRUBounds(t *testing.T) {
	limits := defaultRelayReplayLimits
	limits.ttl = time.Minute
	limits.maxEntries = 2
	limits.maxTotalBytes = 8 << 10
	store := newRelayContinuationReplayStore(limits)
	now := time.Unix(1000, 0)
	store.now = func() time.Time { return now }

	record := func(text string) relayReplayRecord {
		return relayReplayRecord{
			Version: relayReplayRecordVersion,
			Model:   "gpt-5.4",
			Items: []json.RawMessage{
				json.RawMessage(`{"type":"message","role":"user","content":"` + text + `"}`),
			},
		}
	}
	if err := store.put("key:1", "resp_1", record("one")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := store.put("key:1", "resp_2", record("two")); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.get(context.Background(), "key:1", "resp_1"); !ok {
		t.Fatal("expected resp_1 hit before LRU eviction")
	}
	now = now.Add(time.Second)
	if err := store.put("key:1", "resp_3", record("three")); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.get(context.Background(), "key:1", "resp_2"); ok {
		t.Fatal("least recently used resp_2 was not evicted")
	}
	if _, _, ok := store.get(context.Background(), "key:1", "resp_1"); !ok {
		t.Fatal("recently used resp_1 was evicted")
	}
	now = now.Add(2 * time.Minute)
	if _, _, ok := store.get(context.Background(), "key:1", "resp_1"); ok {
		t.Fatal("expired replay remained available")
	}
}

func TestRelayContinuationReplayRejectsOversizedEntryWithoutTruncation(t *testing.T) {
	limits := defaultRelayReplayLimits
	limits.maxItems = 2
	limits.maxItemBytes = 64
	limits.maxEntryBytes = 128
	store := newRelayContinuationReplayStore(limits)
	record := relayReplayRecord{
		Version: relayReplayRecordVersion,
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"message","role":"user","content":"` + strings.Repeat("x", 80) + `"}`),
		},
	}
	err := store.put("key:1", "resp_large", record)
	if !errors.Is(err, ErrRelayContinuationReplayUnavailable) {
		t.Fatalf("oversized put error=%v", err)
	}
	if _, _, ok := store.get(context.Background(), "key:1", "resp_large"); ok {
		t.Fatal("oversized replay was truncated and stored")
	}
}

func TestRelayContinuationReplayRoundTripsThroughRuntimeCache(t *testing.T) {
	runtimeCache := cache.NewMemory(1)
	t.Cleanup(func() { _ = runtimeCache.Close() })

	writer := testRelayReplayStore()
	writer.runtimeCache = runtimeCache
	record := relayReplayRecord{
		Version: relayReplayRecordVersion,
		Model:   "gpt-5.4",
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"message","role":"user","content":"first"}`),
		},
	}
	if err := writer.put("key:1", "resp_runtime", record); err != nil {
		t.Fatal(err)
	}

	reader := testRelayReplayStore()
	reader.runtimeCache = runtimeCache
	got, source, ok := reader.get(context.Background(), "key:1", "resp_runtime")
	if !ok || source != "runtime-cache" {
		t.Fatalf("runtime lookup ok=%v source=%q", ok, source)
	}
	if len(got.Items) != 1 || gjson.GetBytes(got.Items[0], "content").String() != "first" {
		t.Fatalf("runtime record=%+v", got)
	}
}

type recordingRelayReplayRuntimeCache struct {
	cache.TokenCache
	setKey string
}

func (r *recordingRelayReplayRuntimeCache) SetRuntime(
	ctx context.Context,
	namespace string,
	key string,
	value json.RawMessage,
	ttl time.Duration,
) error {
	r.setKey = key
	return r.TokenCache.SetRuntime(ctx, namespace, key, value, ttl)
}

func TestRelayContinuationReplayRuntimeKeyHashesResponseID(t *testing.T) {
	base := cache.NewMemory(1)
	t.Cleanup(func() { _ = base.Close() })
	runtimeCache := &recordingRelayReplayRuntimeCache{TokenCache: base}
	store := testRelayReplayStore()
	store.runtimeCache = runtimeCache

	const responseID = "resp_sensitive_physical_key"
	record := relayReplayRecord{
		Version: relayReplayRecordVersion,
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"message","role":"user","content":"first"}`),
		},
	}
	if err := store.put("key:123", responseID, record); err != nil {
		t.Fatal(err)
	}
	if len(runtimeCache.setKey) != 64 {
		t.Fatalf("runtime key length=%d want SHA-256 hex; key=%q", len(runtimeCache.setKey), runtimeCache.setKey)
	}
	if strings.Contains(runtimeCache.setKey, responseID) ||
		strings.Contains(runtimeCache.setKey, "key:123") {
		t.Fatalf("runtime physical key leaked owner/response id: %q", runtimeCache.setKey)
	}
}

type failingRelayReplayRuntimeCache struct {
	cache.TokenCache
}

func (f failingRelayReplayRuntimeCache) SetRuntime(
	context.Context,
	string,
	string,
	json.RawMessage,
	time.Duration,
) error {
	return errors.New("runtime unavailable")
}

func TestRelayContinuationReplayRuntimeFailureKeepsLocalSafePath(t *testing.T) {
	store := testRelayReplayStore()
	base := cache.NewMemory(1)
	t.Cleanup(func() { _ = base.Close() })
	store.runtimeCache = failingRelayReplayRuntimeCache{TokenCache: base}
	record := relayReplayRecord{
		Version: relayReplayRecordVersion,
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"message","role":"user","content":"first"}`),
		},
	}
	if err := store.put("key:1", "resp_local", record); err != nil {
		t.Fatalf("runtime failure affected local commit: %v", err)
	}
	if _, source, ok := store.get(context.Background(), "key:1", "resp_local"); !ok || source != "memory" {
		t.Fatalf("local lookup ok=%v source=%q", ok, source)
	}
}

func TestPrepareRelayContinuationHTTPFallbackRejectsPartialProvider(t *testing.T) {
	setRelayReplayProviderForTest(t, relayReplayProviderFunc(func(
		context.Context,
		RelayContinuationReplayQuery,
	) (RelayContinuationReplaySnapshot, error) {
		return RelayContinuationReplaySnapshot{
			StandaloneRequestBody: []byte(`{"model":"gpt-5.4","input":"partial"}`),
			Source:                "partial",
		}, nil
	}))
	_, _, _, _, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:1",
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_1","input":"continue"}`),
	)
	var replayErr *RelayContinuationReplayError
	if !errors.As(err, &replayErr) || replayErr.Reason != RelayReplayIncomplete {
		t.Fatalf("partial provider error=%#v", err)
	}
}

func TestResponsesRelayContinuationReplayUnavailableUsesNativeFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "false")

	tests := []struct {
		name            string
		setReplay       func(*testing.T)
		assertChildMiss bool
	}{
		{
			name:            "cache miss",
			assertChildMiss: true,
			setReplay: func(t *testing.T) {
				setRelayReplayStoreForTest(t, testRelayReplayStore())
			},
		},
		{
			name: "incomplete replay",
			setReplay: func(t *testing.T) {
				setRelayReplayProviderForTest(t, relayReplayProviderFunc(func(
					context.Context,
					RelayContinuationReplayQuery,
				) (RelayContinuationReplaySnapshot, error) {
					return RelayContinuationReplaySnapshot{
						StandaloneRequestBody: []byte(`{"model":"gpt-4.1-direct","input":"partial"}`),
						Source:                "partial",
					}, nil
				}))
			},
		},
		{
			name: "invalid replay",
			setReplay: func(t *testing.T) {
				setRelayReplayProviderForTest(t, relayReplayProviderFunc(func(
					context.Context,
					RelayContinuationReplayQuery,
				) (RelayContinuationReplaySnapshot, error) {
					return RelayContinuationReplaySnapshot{
						StandaloneRequestBody: []byte(`{`),
						Completeness:          RelayContinuationReplayComplete,
						Source:                "invalid",
					}, nil
				}))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetResponseCacheStateForTest(testResponseCacheConfig())
			t.Cleanup(func() { resetResponseCacheStateForTest(defaultResponseCacheConfig()) })
			tt.setReplay(t)

			var upstreamCalls atomic.Int32
			var seenBody []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				seenBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{
					"id":"resp_native_child",
					"status":"completed",
					"model":"gpt-4.1-direct",
					"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"child"}]}],
					"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}
				}`)
			}))
			defer upstream.Close()

			handler := NewHandler(newOpenAIResponsesRelayStore(upstream.URL), nil, &config.Config{
				AllowAnonymousV1:       true,
				CodexUpstreamTransport: "http",
			}, nil)
			body := []byte(`{
				"model":"gpt-4.1-direct",
				"previous_response_id":"resp_missing",
				"input":"continue"
			}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = req

			handler.Responses(ctx)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
			}
			if upstreamCalls.Load() != 1 {
				t.Fatalf("Relay upstream calls=%d want=1", upstreamCalls.Load())
			}
			if previous := gjson.GetBytes(seenBody, "previous_response_id").String(); previous != "resp_missing" {
				t.Fatalf("native fallback previous_response_id=%q want=resp_missing body=%s", previous, seenBody)
			}
			if tt.assertChildMiss {
				_, _, _, _, err := PrepareRelayContinuationHTTPFallback(
					context.Background(),
					"anon",
					[]byte(`{"model":"gpt-4.1-direct","previous_response_id":"resp_native_child","input":"again"}`),
				)
				var replayErr *RelayContinuationReplayError
				if !errors.As(err, &replayErr) || replayErr.Reason != RelayReplayCacheMiss {
					t.Fatalf("native fallback child was promoted to complete replay: %v", err)
				}
			}
		})
	}
}

func TestResponsesRelayNativeFallbackKeepsRequiredGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "7")
	resetResponseCacheStateForTest(testResponseCacheConfig())
	t.Cleanup(func() { resetResponseCacheStateForTest(defaultResponseCacheConfig()) })
	setRelayReplayStoreForTest(t, testRelayReplayStore())

	var group7Calls atomic.Int32
	group7 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		group7Calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"resp_group_7",
			"status":"completed",
			"model":"gpt-4.1-direct",
			"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],
			"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}
		}`)
	}))
	defer group7.Close()
	var group8Calls atomic.Int32
	group8 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		group8Calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer group8.Close()

	newStore := func(includeRequiredGroup bool) *auth.Store {
		store := newOpenAIResponsesRelayStore(group8.URL)
		outOfGroup := store.FindByID(1)
		outOfGroup.Mu().Lock()
		outOfGroup.GroupIDs = []int64{8}
		outOfGroup.Mu().Unlock()
		if includeRequiredGroup {
			store.AddAccount(&auth.Account{
				DBID:         2,
				UpstreamType: auth.UpstreamOpenAIResponses,
				BaseURL:      group7.URL,
				APIKey:       "group-7",
				Models:       []string{"gpt-4.1-direct"},
				PlanType:     "api",
				GroupIDs:     []int64{7},
			})
		}
		return store
	}
	invoke := func(store *auth.Store) *httptest.ResponseRecorder {
		handler := NewHandler(store, nil, &config.Config{
			AllowAnonymousV1:       true,
			CodexUpstreamTransport: "http",
		}, nil)
		body := []byte(`{
			"model":"gpt-4.1-direct",
			"previous_response_id":"resp_missing_group",
			"input":"ping"
		}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = req
		handler.Responses(ctx)
		return recorder
	}

	t.Run("selects only the required group", func(t *testing.T) {
		recorder := invoke(newStore(true))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
		}
		if group7Calls.Load() != 1 || group8Calls.Load() != 0 {
			t.Fatalf("group calls: required=%d outside=%d", group7Calls.Load(), group8Calls.Load())
		}
	})

	t.Run("does not escape when the required group is exhausted", func(t *testing.T) {
		beforeRequired := group7Calls.Load()
		beforeOutside := group8Calls.Load()
		recorder := invoke(newStore(false))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want=503 body=%s", recorder.Code, recorder.Body.String())
		}
		if group7Calls.Load() != beforeRequired || group8Calls.Load() != beforeOutside {
			t.Fatalf("group-exhausted request reached upstream: required=%d outside=%d", group7Calls.Load(), group8Calls.Load())
		}
	})
}

func TestResponsesRelayContinuationReplayHitSendsStandaloneHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "false")
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	seedRelayReplayForHandlerTest(t, "resp_replay_relay")

	var seenBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"resp_relay_child",
			"status":"completed",
			"model":"gpt-4.1-direct",
			"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"child"}]}],
			"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}
		}`)
	}))
	defer upstream.Close()

	handler := NewHandler(newOpenAIResponsesRelayStore(upstream.URL), nil, &config.Config{
		AllowAnonymousV1:       true,
		CodexUpstreamTransport: "http",
	}, nil)
	recorder := executeReplayHandlerRequest(t, handler, "gpt-4.1-direct", "resp_replay_relay")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
	}
	assertStandaloneReplayUpstreamBody(t, seenBody)
}

func TestResponsesRelayReplayHitWinsOverOfficialCacheMissForRequiredGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "7")
	resetResponseCacheStateForTest(testResponseCacheConfig())
	t.Cleanup(func() { resetResponseCacheStateForTest(defaultResponseCacheConfig()) })
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	cacheRelayContinuationReplay(
		"anon",
		[]byte(`{"model":"gpt-4.1-direct","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"look this up"}]}]}`),
		true,
		7,
		[]byte(`{
			"id":"resp_replay_tool",
			"output":[{"type":"function_call","id":"fc_1","status":"completed","call_id":"call_1","name":"lookup","arguments":"{}"}]
		}`),
		nil,
	)

	var upstreamCalls atomic.Int32
	var seenBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"resp_relay_child",
			"status":"completed",
			"model":"gpt-4.1-direct",
			"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}],
			"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}
		}`)
	}))
	defer upstream.Close()

	invoke := func(accountGroupID int64) *httptest.ResponseRecorder {
		t.Helper()
		store := newOpenAIResponsesRelayStore(upstream.URL)
		account := store.FindByID(1)
		if account == nil {
			t.Fatal("relay account missing from test store")
		}
		account.Mu().Lock()
		account.GroupIDs = []int64{accountGroupID}
		account.Mu().Unlock()
		handler := NewHandler(store, nil, &config.Config{
			AllowAnonymousV1:       true,
			CodexUpstreamTransport: "http",
		}, nil)
		body := []byte(`{
			"model":"gpt-4.1-direct",
			"stream":false,
			"previous_response_id":"resp_replay_tool",
			"input":[{"type":"function_call_output","call_id":"call_1","output":"ok"}]
		}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = req
		handler.Responses(ctx)
		return recorder
	}

	t.Run("complete replay reaches another account in the same group", func(t *testing.T) {
		recorder := invoke(7)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
		}
		if upstreamCalls.Load() != 1 {
			t.Fatalf("Relay upstream calls=%d want=1", upstreamCalls.Load())
		}
		if gjson.GetBytes(seenBody, "previous_response_id").Exists() {
			t.Fatalf("upstream received raw previous_response_id: %s", seenBody)
		}
		if !strings.Contains(string(seenBody), `"type":"function_call"`) ||
			!strings.Contains(string(seenBody), `"type":"function_call_output"`) {
			t.Fatalf("standalone replay did not contain the complete tool chain: %s", seenBody)
		}
	})

	t.Run("group exhaustion remains a 503 instead of a cache 409", func(t *testing.T) {
		before := upstreamCalls.Load()
		recorder := invoke(8)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want=503 body=%s", recorder.Code, recorder.Body.String())
		}
		if upstreamCalls.Load() != before {
			t.Fatalf("out-of-group Relay received the continuation, calls=%d want=%d", upstreamCalls.Load(), before)
		}
		if code := gjson.GetBytes(recorder.Body.Bytes(), "error.code").String(); code == string(api.ErrCodeResponseContextUnavailable) {
			t.Fatalf("group exhaustion was masked as response-cache unavailability: %s", recorder.Body.String())
		}
	})
}

func TestResponsesOAuthContinuationReplayHitKeepsOfficialRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "false")
	resetResponseCacheForTest()
	t.Cleanup(resetResponseCacheForTest)
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	seedRelayReplayForHandlerTest(t, "resp_replay_oauth")

	previousResin := resinCfg.Load()
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		resinCfg.Store(previousResin)
		ApplyRuntimeSettings(previousSettings)
	})
	settings := previousSettings
	settings.CodexForceWebsocket = false
	ApplyRuntimeSettings(settings)

	var seenBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.output_item.done","item":{"type":"message","id":"msg_child","status":"completed","role":"assistant","content":[{"type":"output_text","text":"child"}]}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_item.done","item":{"type":"function_call","id":"fc_provider","status":"completed","call_id":"call_1","name":"lookup","arguments":"{}","encrypted_content":"official-context"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.completed","response":{"id":"resp_oauth_child","status":"completed","usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}`+"\n\n")
	}))
	defer upstream.Close()
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      1,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	store.AddAccount(&auth.Account{
		DBID:        1,
		AccessToken: "at-oauth",
		PlanType:    "pro",
		AccountID:   "acct-oauth",
	})
	handler := NewHandler(store, nil, &config.Config{
		AllowAnonymousV1:       true,
		CodexUpstreamTransport: "http",
	}, nil)
	recorder := executeReplayHandlerRequest(t, handler, "gpt-5.4", "resp_replay_oauth")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
	}
	if gjson.GetBytes(seenBody, "previous_response_id").Exists() {
		t.Fatalf("official HTTP body unexpectedly retained previous_response_id: %s", seenBody)
	}
	input := gjson.GetBytes(seenBody, "input").Array()
	if len(input) != 1 || input[0].Get("content.0.text").String() != "continue" {
		t.Fatalf("Relay replay leaked into official OAuth body: %s", seenBody)
	}
	if strings.Contains(string(seenBody), `"text":"first"`) ||
		strings.Contains(string(seenBody), `"text":"answer"`) {
		t.Fatalf("Relay replay history changed official OAuth body: %s", seenBody)
	}
	officialCached := getResponseCache("anon", "resp_oauth_child")
	if len(officialCached) == 0 {
		t.Fatal("official OAuth tool-call cache was not populated")
	}
	cachedTool := gjson.ParseBytes(officialCached[len(officialCached)-1])
	if cachedTool.Get("type").String() != "function_call" ||
		cachedTool.Get("status").String() != "completed" ||
		cachedTool.Get("encrypted_content").String() != "official-context" {
		t.Fatalf("official OAuth cache was sanitized by Relay replay: %s", cachedTool.Raw)
	}
}

func seedRelayReplayForHandlerTest(t *testing.T, responseID string) {
	t.Helper()
	cacheRelayContinuationReplay(
		"anon",
		[]byte(`{"model":"gpt-5.4","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}]}`),
		true,
		0,
		[]byte(`{
			"id":"`+responseID+`",
			"output":[{"type":"message","id":"msg_seed","status":"completed","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]
		}`),
		nil,
	)
}

func executeReplayHandlerRequest(
	t *testing.T,
	handler *Handler,
	model string,
	previousResponseID string,
) *httptest.ResponseRecorder {
	t.Helper()
	body := []byte(`{
		"model":"` + model + `",
		"stream":false,
		"previous_response_id":"` + previousResponseID + `",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req
	handler.Responses(ctx)
	return recorder
}

func assertStandaloneReplayUpstreamBody(t *testing.T, body []byte) {
	t.Helper()
	if len(body) == 0 {
		t.Fatal("upstream request body was not captured")
	}
	if gjson.GetBytes(body, "previous_response_id").Exists() {
		t.Fatalf("upstream received raw previous_response_id: %s", body)
	}
	input := gjson.GetBytes(body, "input").Array()
	if len(input) != 3 {
		t.Fatalf("upstream input count=%d want=3 body=%s", len(input), body)
	}
	if got := input[0].Get("content.0.text").String(); got != "first" {
		t.Fatalf("first history item=%q body=%s", got, body)
	}
	if got := input[1].Get("content.0.text").String(); got != "answer" {
		t.Fatalf("assistant history item=%q body=%s", got, body)
	}
	if got := input[2].Get("content.0.text").String(); got != "continue" {
		t.Fatalf("current item=%q body=%s", got, body)
	}
}
