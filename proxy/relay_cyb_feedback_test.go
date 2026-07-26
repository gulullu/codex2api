package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/codex2api/auth"
)

func TestRelayCybFeedbackDigestUsesNormalizedLatestUserText(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	firstBody := []byte(`{"model":"gpt-5.6-sol","input":"Please build the security verifier.\nReturn reproducible evidence.","stream":false}`)
	secondBody := []byte(`{"metadata":{"trace":"other"},"instructions":"different","input":[{"role":"user","content":[{"type":"input_text","text":"older user turn"}]},{"role":"assistant","content":[{"type":"output_text","text":"older answer"}]},{"role":"user","content":[{"type":"input_text","text":"  Ｐlease build the security verifier.\r\nReturn reproducible evidence.  "}]}],"stream":true}`)

	first, ok := cache.digest("/v1/responses", firstBody)
	if !ok {
		t.Fatal("eligible request did not produce a digest")
	}
	second, ok := cache.digest("/v1/responses", secondBody)
	if !ok {
		t.Fatal("equivalent request did not produce a digest")
	}
	if first != second {
		t.Fatal("equivalent normalized latest user text produced different digests")
	}
}

func TestRelayCybFeedbackDigestShortTextUsesExactRawBody(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	firstBody := []byte(`{"model":"gpt-5.6-sol","input":"short","stream":false}`)
	secondBody := []byte(`{"model":"gpt-5.4","input":" short ","stream":true}`)

	first, ok := cache.digest("/v1/responses", firstBody)
	if !ok {
		t.Fatal("short request did not produce a digest")
	}
	same, _ := cache.digest("/v1/responses", append([]byte(nil), firstBody...))
	different, _ := cache.digest("/v1/responses", secondBody)
	if first != same {
		t.Fatal("identical short raw bodies produced different digests")
	}
	if first == different {
		t.Fatal("different short raw bodies unexpectedly shared a digest")
	}
	if _, ok := cache.digest("/v1/images/generations", firstBody); ok {
		t.Fatal("non-text endpoint produced a feedback digest")
	}
}

func TestRelayCybFeedbackExpiryAndLRUEviction(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	expiring, _ := cache.digest("/v1/responses", []byte(`{"input":"expires"}`))
	cache.learn(expiring)
	cache.mu.Lock()
	cache.items[expiring].Value.(*relayCybFeedbackEntry).expiresAt = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if cache.contains(expiring) {
		t.Fatal("expired feedback digest remained available")
	}

	var first relayCybFeedbackDigest
	for index := 0; index <= relayCybFeedbackMaxEntries; index++ {
		digest, _ := cache.digest(
			"/v1/responses",
			[]byte(fmt.Sprintf(`{"input":"entry-%d"}`, index)),
		)
		if index == 0 {
			first = digest
		}
		cache.learn(digest)
	}
	if cache.contains(first) {
		t.Fatal("least-recently-used feedback digest was not evicted")
	}
	if cache.order.Len() != relayCybFeedbackMaxEntries {
		t.Fatalf("cache size = %d, want %d", cache.order.Len(), relayCybFeedbackMaxEntries)
	}
}

func TestRelayCybFeedbackLearnsOnlyDefaultOAuthRoute(t *testing.T) {
	base := &relayRoutePlan{
		Config:              relayRouteConfig{Enabled: true, GroupID: 3},
		Source:              relayRouteSourceDefault,
		FeedbackDigestValid: true,
	}
	oauth := &auth.Account{DBID: 1}
	if !relayCybFeedbackLearnEligible(base, oauth) {
		t.Fatal("default OAuth cyber_policy route was not eligible")
	}

	relay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example",
		APIKey:       "test-only",
	}
	if relayCybFeedbackLearnEligible(base, relay) {
		t.Fatal("RelayStyle account was eligible for feedback learning")
	}
	required := *base
	required.RequiredGroupID = 3
	if relayCybFeedbackLearnEligible(&required, oauth) {
		t.Fatal("already-routed request was eligible for feedback learning")
	}
	disabled := *base
	disabled.Config.Enabled = false
	if relayCybFeedbackLearnEligible(&disabled, oauth) {
		t.Fatal("disabled Relay routing learned feedback")
	}
}
