package wsrelay

import (
	"net/http"
	"testing"

	"github.com/codex2api/auth"
)

func TestSafePoolPolicyFailsClosedAndKillSwitchWins(t *testing.T) {
	account := &auth.Account{DBID: 7001, Tags: []string{safePoolAccountTag}}

	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	t.Setenv(safePoolScopeEnv, "all")
	if got := resolveStatelessPoolPolicy(account, nil).mode; got != statelessPoolOneShot {
		t.Fatalf("kill switch mode = %v, want oneshot", got)
	}

	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "")
	if got := resolveStatelessPoolPolicy(account, nil).mode; got != statelessPoolDefault {
		t.Fatalf("missing scope mode = %v, want unchanged baseline", got)
	}

	t.Setenv(safePoolScopeEnv, "unexpected")
	if got := resolveStatelessPoolPolicy(account, nil).mode; got != statelessPoolDefault {
		t.Fatalf("invalid scope mode = %v, want unchanged baseline", got)
	}
}

func TestSafePoolPolicyUsesDynamicTagsWithoutAccountIDs(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "tagged")

	first := &auth.Account{DBID: 41, Name: "renamable", Tags: []string{safePoolAccountTag, safePoolSlotsTag + "17"}}
	second := &auth.Account{DBID: 987654, Name: "another"}
	if policy := resolveStatelessPoolPolicy(first, nil); policy.mode != statelessPoolSafe || policy.slots != 17 {
		t.Fatalf("tagged account policy = %#v, want safe/17", policy)
	}
	if policy := resolveStatelessPoolPolicy(second, nil); policy.mode != statelessPoolDefault {
		t.Fatalf("untagged dynamic account policy = %#v, want unchanged baseline", policy)
	}

	first.Mu().Lock()
	first.Name = "renamed-live"
	first.Tags = []string{oneShotAccountTag}
	first.Mu().Unlock()
	if policy := resolveStatelessPoolPolicy(first, nil); policy.mode != statelessPoolOneShot {
		t.Fatalf("hot tag removal policy = %#v, want oneshot", policy)
	}
}

func TestSafePoolOwnerRequiresExplicitClientMetadata(t *testing.T) {
	if _, ok := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1","thread_id":"t-1"}}`), ""); ok {
		t.Fatal("owner without a downstream API key was admitted to safe pool")
	}
	if _, ok := safePoolOwnerKey([]byte(`{"model":"gpt-5.6"}`), "shared-key"); ok {
		t.Fatal("ownerless request was admitted to safe pool")
	}
	if _, ok := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1"}}`), "shared-key"); ok {
		t.Fatal("session without thread was admitted to safe pool")
	}
	if _, ok := safePoolOwnerKey([]byte(`{"client_metadata":{"thread_id":"t-1"}}`), "shared-key"); ok {
		t.Fatal("thread without session was admitted to safe pool")
	}

	first, ok := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1","thread_id":"t-1","turn_id":"turn-a"}}`), "key-a")
	if !ok {
		t.Fatal("explicit client metadata was not recognized")
	}
	second, ok := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1","thread_id":"t-1","turn_id":"turn-b"}}`), "key-a")
	if !ok || second != first {
		t.Fatalf("turn change altered owner: first=%q second=%q", first, second)
	}
	differentThread, _ := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1","thread_id":"t-2"}}`), "key-a")
	if differentThread == first {
		t.Fatal("different thread shared the same owner key")
	}
	differentAPIKey, _ := safePoolOwnerKey([]byte(`{"client_metadata":{"session_id":"s-1","thread_id":"t-1"}}`), "key-b")
	if differentAPIKey == first {
		t.Fatal("different downstream API key shared the same owner key")
	}
}

func TestSafePoolHandshakeIgnoresPerTurnHeaders(t *testing.T) {
	first := http.Header{
		"Authorization":         {"Bearer stable"},
		"X-Client-Request-Id":   {"thread-A"},
		"X-Codex-Turn-State":    {"turn-A"},
		"X-Codex-Turn-Metadata": {"metadata-A"},
		"Traceparent":           {"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"},
		"Tracestate":            {"vendor=turn-A"},
	}
	second := first.Clone()
	second.Set("X-Codex-Turn-State", "turn-B")
	second.Set("X-Codex-Turn-Metadata", "metadata-B")
	second.Set("Traceparent", "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01")
	second.Set("Tracestate", "vendor=turn-B")
	if safePoolHeaderFingerprint(safePoolHandshakeHeaders(first)) != safePoolHeaderFingerprint(safePoolHandshakeHeaders(second)) {
		t.Fatal("turn-scoped headers fragmented the stable handshake identity")
	}
	second.Set("X-Client-Request-Id", "thread-B")
	if safePoolHeaderFingerprint(safePoolHandshakeHeaders(first)) == safePoolHeaderFingerprint(safePoolHandshakeHeaders(second)) {
		t.Fatal("connection-scoped request identity change reused the same handshake")
	}
}

func TestSafePoolOwnerHandshakeMatchesOfficialStableIdentity(t *testing.T) {
	body := []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-window-id":"window-A"}}`)
	headers := http.Header{
		"Authorization":         {"Bearer stable"},
		"Session_id":            {"legacy-cache-key"},
		"Conversation_id":       {"legacy-cache-key"},
		"X-Client-Request-Id":   {"thread-A"},
		"X-Codex-Turn-State":    {"turn-A"},
		"X-Codex-Turn-Metadata": {"metadata-A"},
		"Traceparent":           {"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"},
		"Tracestate":            {"vendor=turn-A"},
	}
	stable, ok := safePoolOwnerHandshakeHeaders(headers, body)
	if !ok {
		t.Fatal("official owner metadata was rejected")
	}
	for name, want := range map[string]string{
		"Session-Id":          "session-A",
		"Thread-Id":           "thread-A",
		"X-Client-Request-Id": "thread-A",
		"X-Codex-Window-Id":   "window-A",
	} {
		if got := stable.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if stable.Get("X-Codex-Turn-State") != "" || stable.Get("X-Codex-Turn-Metadata") != "" || stable.Get("Traceparent") != "" || stable.Get("Tracestate") != "" {
		t.Fatal("turn-scoped headers remained frozen in the reusable handshake")
	}
	if stable.Get("Session_id") != "" || stable.Get("Conversation_id") != "" {
		t.Fatal("legacy cache-derived session headers remained beside the canonical owner identity")
	}

	conflict := headers.Clone()
	conflict.Set("X-Client-Request-Id", "different-thread")
	if _, ok := safePoolOwnerHandshakeHeaders(conflict, body); ok {
		t.Fatal("conflicting connection-scoped thread identity was admitted")
	}
}

func TestSafePoolWindowChangeKeepsOwnerIdentityButUpdatesNewHandshake(t *testing.T) {
	headers := http.Header{
		"Authorization":       {"Bearer stable"},
		"X-Client-Request-Id": {"thread-A"},
	}
	first, ok := safePoolOwnerHandshakeHeaders(headers, []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-window-id":"window-A"}}`))
	if !ok {
		t.Fatal("first window handshake rejected")
	}
	second, ok := safePoolOwnerHandshakeHeaders(headers, []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-window-id":"window-B"}}`))
	if !ok {
		t.Fatal("compacted window handshake rejected")
	}
	if first.Get("X-Codex-Window-Id") != "window-A" || second.Get("X-Codex-Window-Id") != "window-B" {
		t.Fatalf("new handshakes did not preserve current compatibility window: first=%q second=%q", first.Get("X-Codex-Window-Id"), second.Get("X-Codex-Window-Id"))
	}
	if safePoolHeaderFingerprint(first) != safePoolHeaderFingerprint(second) {
		t.Fatal("auto-compaction window change fragmented the physical connection identity")
	}
}

func TestSafePoolRequestEligibilityRejectsAudioModes(t *testing.T) {
	for _, body := range []string{
		`{"modalities":["text","audio"]}`,
		`{"output_modalities":"audio"}`,
		`{"audio":{"voice":"alloy"}}`,
		`{"output_audio":{}}`,
	} {
		if safePoolRequestEligible([]byte(body)) {
			t.Fatalf("audio-capable request was admitted: %s", body)
		}
	}
	if !safePoolRequestEligible([]byte(`{"modalities":["text"],"client_metadata":{"session_id":"s","thread_id":"t"}}`)) {
		t.Fatal("ordinary text request was rejected")
	}
}

func TestSafePoolHeaderFingerprintIsStableButIdentitySensitive(t *testing.T) {
	first := http.Header{
		"X-Codex-Turn-State":  {"turn-a"},
		"X-Client-Request-Id": {"request-a"},
	}
	reordered := http.Header{
		"X-Client-Request-Id": {"request-a"},
		"X-Codex-Turn-State":  {"turn-a"},
	}
	changed := reordered.Clone()
	changed.Set("X-Client-Request-Id", "request-b")

	if safePoolHeaderFingerprint(first) != safePoolHeaderFingerprint(reordered) {
		t.Fatal("header map iteration order changed the fingerprint")
	}
	if safePoolHeaderFingerprint(first) == safePoolHeaderFingerprint(changed) {
		t.Fatal("per-request handshake identity change reused the fingerprint")
	}
}

func TestSafePoolFuseOverridesTaggedPolicyOnlyInMemory(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "tagged")
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 77, Tags: []string{safePoolAccountTag}}
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolSafe {
		t.Fatalf("pre-fuse mode = %v, want safe", got)
	}
	manager.TripSafePoolFuse(account.ID(), errSafePoolIsolationViolation)
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolHTTPFallback {
		t.Fatalf("post-fuse mode = %v, want same-account HTTP fallback", got)
	}
	account.Mu().Lock()
	account.Tags = nil
	account.Mu().Unlock()
	t.Setenv(safePoolScopeEnv, "disabled")
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolHTTPFallback {
		t.Fatalf("post-fuse disabled-scope mode = %v, want persistent HTTP fallback", got)
	}
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolOneShot {
		t.Fatalf("hard kill switch mode = %v, want explicit oneshot", got)
	}
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	manager.resetSafePoolFuseForTest(account.ID())
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolDefault {
		t.Fatalf("reset disabled-scope mode = %v, want unchanged baseline", got)
	}
	account.Mu().Lock()
	account.Tags = []string{safePoolAccountTag}
	account.Mu().Unlock()
	t.Setenv(safePoolScopeEnv, "tagged")
	if got := resolveStatelessPoolPolicy(account, manager).mode; got != statelessPoolSafe {
		t.Fatalf("test reset mode = %v, want safe", got)
	}
}
