package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
)

type encryptedContextCountingCache struct {
	cache.TokenCache
	runtimeReads atomic.Int64
}

func (c *encryptedContextCountingCache) GetRuntime(context.Context, string, string) (json.RawMessage, bool, error) {
	c.runtimeReads.Add(1)
	return nil, false, nil
}

func containsEncryptedContextSignal(signals []string, want string) bool {
	for _, signal := range signals {
		if signal == want {
			return true
		}
	}
	return false
}

func enableEncryptedContextAffinity(t *testing.T) {
	t.Helper()
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_ENABLED", "true")
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_TTL", "24h")
}

func TestEncryptedContextOwnerKeyIsIsolatedAndOpaque(t *testing.T) {
	enableEncryptedContextAffinity(t)
	const ciphertext = "opaque-secret-ciphertext"
	keyOne := encryptedContextOwnerKey(101, ciphertext)
	keyTwo := encryptedContextOwnerKey(202, ciphertext)
	if keyOne == "" || keyTwo == "" || keyOne == keyTwo {
		t.Fatalf("owner keys must be non-empty and API-key isolated: %q %q", keyOne, keyTwo)
	}
	if bytes.Contains([]byte(keyOne), []byte(ciphertext)) || bytes.Contains([]byte(keyTwo), []byte(ciphertext)) {
		t.Fatalf("runtime keys must not contain raw ciphertext")
	}

	payload := []byte(`{
		"output":[
			{"type":"reasoning","encrypted_content":"reasoning-cipher"},
			{"type":"context_compaction","encrypted_content":"context-cipher"},
			{"type":"message","content":[{"type":"input_text","encrypted_content":"unrelated"}]}
		]
	}`)
	keys := encryptedContextOwnerKeys(101, payload)
	if len(keys) != 2 {
		t.Fatalf("expected two recognized encrypted-history keys, got %d: %#v", len(keys), keys)
	}
	doneKeys := encryptedContextOwnerKeys(101, []byte(`{"type":"response.reasoning.encrypted_content.done","encrypted_content":"done-cipher"}`))
	if len(doneKeys) != 1 {
		t.Fatalf("reasoning encrypted-content done event was not captured: %#v", doneKeys)
	}
	requestKeys := encryptedContextInputOwnerKeys(101, []byte(`{
		"input":[{"type":"message","role":"user","content":"hello"}],
		"tools":[{"type":"reasoning","encrypted_content":"not-input-history"}]
	}`))
	if len(requestKeys) != 0 {
		t.Fatalf("request affinity must inspect only input history, got %#v", requestKeys)
	}
}

func TestEncryptedContextOrdinaryRequestSkipsRuntimeCache(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, _, _ := newRelayOverflowTestHandler()
	countingCache := &encryptedContextCountingCache{}
	handler.SetRuntimeCache(countingCache)
	ctx := newRouteTestContext()
	ctx.Set(contextAPIKeyID, int64(101))

	handler.loadEncryptedContextAffinity(ctx, []byte(`{"model":"gpt-5.4","input":[{"type":"message","role":"user","content":"hello"}]}`))
	if got := countingCache.runtimeReads.Load(); got != 0 {
		t.Fatalf("ordinary request performed %d encrypted-owner cache reads", got)
	}
	if _, ok := encryptedContextStateFromContext(ctx); ok {
		t.Fatalf("ordinary request should not create encrypted affinity state")
	}

	payload := []byte(`{"model":"gpt-5.4","input":"hello"}`)
	if allocs := testing.AllocsPerRun(1000, func() { _ = encryptedContextInputOwnerKeys(101, payload) }); allocs != 0 {
		t.Fatalf("ordinary encrypted-affinity fast path allocated %.2f objects", allocs)
	}
}

func TestEncryptedContextCaptureLoadAndAPIKeyIsolation(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, _ := newRelayOverflowTestHandler()
	runtimeCache := cache.NewMemory(16)
	handler.SetRuntimeCache(runtimeCache)

	capture := newEncryptedContextCapture(101)
	capture.Observe([]byte(`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"cipher-a"}}`))
	handler.commitEncryptedContextCapture(oauth, capture)

	ctx := newRouteTestContext()
	ctx.Set(contextAPIKeyID, int64(101))
	handler.loadEncryptedContextAffinity(ctx, []byte(`{"input":[{"type":"reasoning","encrypted_content":"cipher-a"}]}`))
	owner, ok := encryptedContextOwnerFromContext(ctx)
	if !ok || owner.AccountID != oauth.ID() {
		t.Fatalf("owner = %+v ok=%v, want account %d", owner, ok, oauth.ID())
	}

	otherCtx := newRouteTestContext()
	otherCtx.Set(contextAPIKeyID, int64(202))
	handler.loadEncryptedContextAffinity(otherCtx, []byte(`{"input":[{"type":"reasoning","encrypted_content":"cipher-a"}]}`))
	if _, ok := encryptedContextOwnerFromContext(otherCtx); ok {
		t.Fatalf("encrypted owner must not cross API-key namespaces")
	}
	state, ok := encryptedContextStateFromContext(otherCtx)
	if !ok || !containsEncryptedContextSignal(state.Signals, encryptedOwnerMissSignal) {
		t.Fatalf("other API key should record a miss, got %+v", state)
	}

	key := encryptedContextOwnerKey(101, "cipher-a")
	stored, exists, err := runtimeCache.GetRuntime(context.Background(), encryptedContextOwnerNamespace, key)
	if err != nil || !exists {
		t.Fatalf("stored owner missing: exists=%v err=%v", exists, err)
	}
	if bytes.Contains(stored, []byte("cipher-a")) {
		t.Fatalf("runtime value leaked raw ciphertext: %s", stored)
	}
	var record responseRouteOwner
	if json.Unmarshal(stored, &record) != nil || record.AccountID != oauth.ID() {
		t.Fatalf("unexpected owner record: %s", stored)
	}
}

func TestEncryptedContextConcurrentFirstOwnerClaimDoesNotOverwrite(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	runtimeCache := cache.NewMemory(16)
	handler.SetRuntimeCache(runtimeCache)

	makeCapture := func() *encryptedContextCapture {
		capture := newEncryptedContextCapture(101)
		capture.Observe([]byte(`{"type":"reasoning","encrypted_content":"shared-cipher"}`))
		return capture
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, account := range []*auth.Account{oauth, relay} {
		wg.Add(1)
		go func(account *auth.Account) {
			defer wg.Done()
			<-start
			handler.commitEncryptedContextCapture(account, makeCapture())
		}(account)
	}
	close(start)
	wg.Wait()

	key := encryptedContextOwnerKey(101, "shared-cipher")
	payload, ok, err := runtimeCache.GetRuntime(context.Background(), encryptedContextOwnerNamespace, key)
	if err != nil || !ok {
		t.Fatalf("owner claim missing: ok=%v err=%v", ok, err)
	}
	var owner responseRouteOwner
	if json.Unmarshal(payload, &owner) != nil || (owner.AccountID != oauth.ID() && owner.AccountID != relay.ID()) {
		t.Fatalf("unexpected claimed owner: %s", payload)
	}
}

func TestEncryptedContextMixedOwnersRequireSafeDowngrade(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	handler.SetRuntimeCache(cache.NewMemory(16))

	first := newEncryptedContextCapture(101)
	first.Observe([]byte(`{"type":"reasoning","encrypted_content":"cipher-a"}`))
	handler.commitEncryptedContextCapture(oauth, first)
	second := newEncryptedContextCapture(101)
	second.Observe([]byte(`{"type":"compaction","encrypted_content":"cipher-b"}`))
	handler.commitEncryptedContextCapture(relay, second)

	ctx := newRouteTestContext()
	ctx.Set(contextAPIKeyID, int64(101))
	raw := []byte(`{
		"input":[
			{"type":"message","role":"user","content":"continue"},
			{"type":"reasoning","encrypted_content":"cipher-a"},
			{"type":"compaction","encrypted_content":"cipher-b","summary":"safe summary"}
		]
	}`)
	handler.loadEncryptedContextAffinity(ctx, raw)
	state, ok := encryptedContextStateFromContext(ctx)
	if !ok || !state.NeedsDowngrade || !containsEncryptedContextSignal(state.Signals, encryptedOwnerConflictSignal) {
		t.Fatalf("mixed owners should require downgrade, got %+v", state)
	}
	repaired, repair, err := handler.repairEncryptedContextForAccountSwitch(ctx, raw)
	if err != nil || !repair.Changed || repair.InputEmpty || repair.Dropped != 1 || repair.Converted != 1 {
		t.Fatalf("unexpected downgrade result: repair=%+v err=%v body=%s", repair, err, repaired)
	}
	if bytes.Contains(repaired, []byte("encrypted_content")) {
		t.Fatalf("downgraded request retained encrypted history: %s", repaired)
	}
}

func TestEncryptedContextAffinitySelectsExactOwnerWhenSessionAffinityOff(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	handler.store.SetAffinityMode(auth.AffinityModeOff)

	for _, test := range []struct {
		name  string
		owner responseRouteOwner
		want  *auth.Account
		relay bool
	}{
		{name: "oauth", owner: encryptedContextOwnerForAccount(oauth), want: oauth},
		{name: "relay", owner: encryptedContextOwnerForAccount(relay), want: relay, relay: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newRouteTestContext()
			setEncryptedContextState(ctx, encryptedContextAffinityState{
				Keys:     []string{"opaque-key"},
				Owner:    test.owner,
				HasOwner: true,
				Signals:  []string{encryptedOwnerHitSignal},
			})
			account, _, decision := handler.nextRoutedAccountForSession(
				ctx,
				context.Background(),
				"",
				101,
				newRetryAccountExclusions(),
				nil,
				defaultPromptRiskDecision(),
			)
			if account == nil || account.ID() != test.want.ID() {
				t.Fatalf("selected account=%#v, want %d", account, test.want.ID())
			}
			if decision.PinKind != encryptedContextPinKind || decision.RoutePinned != true || decision.routesToCybRelay() != test.relay {
				t.Fatalf("unexpected decision: %+v", decision)
			}
			handler.store.Release(account)
		})
	}
}

func TestEncryptedContextUnavailableOwnerFallsBackOnlyAfterDowngrade(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:     []string{"opaque-key"},
		Owner:    encryptedContextOwnerForAccount(oauth),
		HasOwner: true,
		Signals:  []string{encryptedOwnerHitSignal},
	})

	// Make the exact OAuth owner unavailable. Ordinary routing may choose Relay,
	// but only after the caller is told to remove owner-bound encrypted history.
	oauth.Disabled = 1
	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		101,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		t.Fatalf("fallback account=%#v, want relay %d", account, relay.ID())
	}
	if !encryptedContextNeedsDowngrade(ctx) || !containsEncryptedContextSignal(decision.Signals, encryptedOwnerUnavailableSignal) {
		t.Fatalf("owner fallback must require downgrade, decision=%+v", decision)
	}
	handler.store.Release(account)
	oauth.Disabled = 0
}

func TestEncryptedContextOAuthOwnerNeverOverridesRequiredRelayRoute(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:     []string{"opaque-key"},
		Owner:    encryptedContextOwnerForAccount(oauth),
		HasOwner: true,
		Signals:  []string{encryptedOwnerHitSignal},
	})
	required := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		RouteSource: cybRelayRouteSourceDirect,
		Signals:     []string{"technical_cyber_intent"},
	}

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		101,
		newRetryAccountExclusions(),
		nil,
		required,
	)
	if account == nil || account.ID() != relay.ID() || !decision.routesToCybRelay() {
		t.Fatalf("required Relay route selected %#v decision=%+v", account, decision)
	}
	if !encryptedContextNeedsDowngrade(ctx) || !containsEncryptedContextSignal(decision.Signals, encryptedOwnerConflictSignal) {
		t.Fatalf("OAuth owner conflict must downgrade before Relay: %+v", decision)
	}
	handler.store.Release(account)
}

func TestPreviousResponseOwnerWinsEncryptedOwnerConflict(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	ctx.Set(contextResponseRouteOwner, encryptedContextOwnerForAccount(relay))
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:     []string{"opaque-key"},
		Owner:    encryptedContextOwnerForAccount(oauth),
		HasOwner: true,
		Signals:  []string{encryptedOwnerHitSignal},
	})

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		101,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		t.Fatalf("previous_response owner account=%#v, want relay %d", account, relay.ID())
	}
	if !encryptedContextNeedsDowngrade(ctx) || !containsEncryptedContextSignal(decision.Signals, encryptedOwnerConflictSignal) {
		t.Fatalf("encrypted owner conflict should downgrade while previous owner wins: %+v", decision)
	}
	handler.store.Release(account)
}

func TestEncryptedContextProactiveDowngradeRejectsEmptyInput(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, _, _ := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:           []string{"opaque-key"},
		NeedsDowngrade: true,
		Signals:        []string{encryptedOwnerConflictSignal, encryptedContextDowngradeSignal},
	})
	raw := []byte(`{"input":[{"type":"context_compaction","encrypted_content":"only-history"}]}`)
	_, repair, err := handler.repairEncryptedContextForAccountSwitch(ctx, raw)
	if !errors.Is(err, errEncryptedContextNoReplayableInput) || !repair.Changed || !repair.InputEmpty {
		t.Fatalf("expected explicit empty-input rejection, repair=%+v err=%v", repair, err)
	}
}

func TestEncryptedContextTTLBounds(t *testing.T) {
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_TTL", "999h")
	if got := encryptedContextAffinityTTL(); got != encryptedContextMaxTTL {
		t.Fatalf("ttl=%s, want max %s", got, encryptedContextMaxTTL)
	}
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_TTL", "invalid")
	if got := encryptedContextAffinityTTL(); got != encryptedContextDefaultTTL {
		t.Fatalf("invalid ttl=%s, want default %s", got, encryptedContextDefaultTTL)
	}
	t.Setenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_TTL", "90m")
	if got := encryptedContextAffinityTTL(); got != 90*time.Minute {
		t.Fatalf("ttl=%s, want 90m", got)
	}
}
