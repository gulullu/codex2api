package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
)

func TestRequestStickyRetryStatePreferenceIsConsumedBeforeSelection(t *testing.T) {
	first := &auth.Account{DBID: 1}
	second := &auth.Account{DBID: 2}
	var state requestStickyRetryState

	state.Retain(first, "http://proxy-one.example")
	filter, retainedProxy, ok := state.TakeAccountFilter(nil)
	if !ok || retainedProxy != "http://proxy-one.example" {
		t.Fatalf("preference = (%v, %q), want retained proxy", ok, retainedProxy)
	}
	if !filter(first) || filter(second) {
		t.Fatal("retry filter did not select only the retained account")
	}
	if _, _, ok := state.TakeAccountFilter(nil); ok {
		t.Fatal("consumed retry state remained active")
	}
}

func TestRequestStickyRetryStateRespectsBaseFilter(t *testing.T) {
	account := &auth.Account{DBID: 1}
	var state requestStickyRetryState
	state.Retain(account, "")
	filter, _, ok := state.TakeAccountFilter(func(*auth.Account) bool { return false })
	if !ok {
		t.Fatal("retained preference was not returned")
	}
	if filter(account) {
		t.Fatal("retry filter bypassed the route/model base filter")
	}
}

func TestRequestStickyRetryEligibilityRejectsOnlyConfiguredRelayFrontDoors(t *testing.T) {
	handler, oauth, relay := newRelayOverflowTestHandler()
	ordinaryAPIKey := &auth.Account{DBID: 51, UpstreamType: auth.UpstreamOpenAIResponses}
	if handler.requestStickyRetryAccountEligible(relay) {
		t.Fatal("configured Relay front door was eligible for request-local sticky retry")
	}
	if !handler.requestStickyRetryAccountEligible(oauth) {
		t.Fatal("ordinary OAuth account lost request-local sticky retry")
	}
	if !handler.requestStickyRetryAccountEligible(ordinaryAPIKey) {
		t.Fatal("non-Relay Responses API account lost official sticky retry semantics")
	}
}

func TestRequestStickyRetrySpeculativeMissPreservesBoundOwners(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newHandlerWithOtherOAuth := func() (*Handler, *auth.Account, *auth.Account) {
		handler, owner, _ := newRelayOverflowTestHandler()
		other := &auth.Account{
			DBID:                    3,
			AccessToken:             "other-oauth",
			PlanType:                "pro",
			Status:                  auth.StatusReady,
			BaseConcurrencyOverride: int64Pointer(1),
		}
		handler.store.AddAccount(other)
		return handler, owner, other
	}

	t.Run("previous response owner", func(t *testing.T) {
		handler, owner, other := newHandlerWithOtherOAuth()
		ctx := newRouteTestContext()
		ctx.Set(contextResponseRouteOwner, responseRouteOwner{
			AccountID: owner.ID(), AccountType: "oauth",
		})
		var state requestStickyRetryState
		state.Retain(other, "")

		account, _, _, attempt := handler.nextCircuitPermittedRoutedAccountForSessionWithStickyFallback(
			ctx, "", 0, newRetryAccountExclusions(), nil, defaultPromptRiskDecision(), &state,
		)
		if account == nil || account.ID() != owner.ID() {
			t.Fatalf("selected account=%v, want previous_response_id owner %d", account, owner.ID())
		}
		if routeErr, ok := routeSelectionErrorFromContext(ctx); ok {
			t.Fatalf("speculative sticky miss left route error: %+v", routeErr)
		}
		attempt.Release(handler.store, account)
	})

	t.Run("encrypted content owner", func(t *testing.T) {
		enableEncryptedContextAffinity(t)
		handler, owner, other := newHandlerWithOtherOAuth()
		ctx := newRouteTestContext()
		setEncryptedContextState(ctx, encryptedContextAffinityState{
			Keys: []string{"opaque-key"}, Owner: encryptedContextOwnerForAccount(owner), HasOwner: true,
			Signals: []string{encryptedOwnerHitSignal},
		})
		var state requestStickyRetryState
		state.Retain(other, "")

		account, _, _, attempt := handler.nextCircuitPermittedRoutedAccountForSessionWithStickyFallback(
			ctx, "", 0, newRetryAccountExclusions(), nil, defaultPromptRiskDecision(), &state,
		)
		if account == nil || account.ID() != owner.ID() {
			t.Fatalf("selected account=%v, want encrypted_content owner %d", account, owner.ID())
		}
		if encryptedContextNeedsDowngrade(ctx) {
			t.Fatal("speculative sticky miss incorrectly marked encrypted_content for downgrade")
		}
		attempt.Release(handler.store, account)
	})
}

func TestImmediateRelayPreferenceDoesNotHideHealthyPeerFromCircuit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newRelayFailoverStore("https://primary.example", "https://peer.example")
	primary := store.FindByID(101)
	if primary == nil {
		t.Fatal("primary Relay account is missing")
	}
	handler := NewHandler(store, nil, nil, nil)
	ctx := newRouteTestContext()
	primaryOnly := func(account *auth.Account) bool { return account != nil && account.ID() == primary.ID() }
	required := promptRiskDecision{Disposition: promptRiskDispositionRelay}

	for i := 0; i < 3; i++ {
		beginLogicalRequest(ctx)
		account, _, _, attempt := handler.nextCircuitPermittedRoutedAccountForSessionWithMode(
			ctx, "", 0, newRetryAccountExclusions(), primaryOnly, nil, required, false,
		)
		if account == nil || account.ID() != primary.ID() {
			t.Fatalf("attempt %d selected account=%v, want primary %d", i+1, account, primary.ID())
		}
		attempt.Failure(http.StatusBadGateway)
		attempt.Release(store, account)
	}

	snapshot := store.RelayCircuitSnapshot(primary.ID())
	if snapshot.State != auth.RelayCircuitOpen || snapshot.LastResort {
		t.Fatalf("retained-ID selection hid healthy peer from circuit: %+v", snapshot)
	}
}

func TestRequestStickyRetryPrefersRetainedAccountWithoutBlockingPoolFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("retained account immediately available", func(t *testing.T) {
		handler, oauth, _ := newRelayOverflowTestHandler()
		var state requestStickyRetryState
		state.Retain(oauth, "http://retained-proxy.example")
		ctx := newRouteTestContext()

		account, proxyURL, decision, attempt := handler.nextCircuitPermittedRoutedAccountForSessionWithStickyFallback(
			ctx, "", 0, newRetryAccountExclusions(), nil, defaultPromptRiskDecision(), &state,
		)
		if account == nil || account.ID() != oauth.ID() || proxyURL != "http://retained-proxy.example" {
			t.Fatalf("selection = account %#v proxy %q, want retained OAuth %d and proxy", account, proxyURL, oauth.ID())
		}
		if decision.routesToCybRelay() {
			t.Fatalf("retained OAuth selection changed route: %+v", decision)
		}
		attempt.Release(handler.store, account)
	})

	t.Run("full retained account falls through immediately", func(t *testing.T) {
		handler, oauth, relay := newRelayOverflowTestHandler()
		atomic.StoreInt64(&oauth.ActiveRequests, 1)
		var state requestStickyRetryState
		state.Retain(oauth, "http://retained-proxy.example")
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		requestContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(requestContext)

		started := time.Now()
		account, _, decision, attempt := handler.nextCircuitPermittedRoutedAccountForSessionWithStickyFallback(
			ctx, "", 0, newRetryAccountExclusions(), nil, defaultPromptRiskDecision(), &state,
		)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("sticky fallback waited %s; want immediate full-pool reselection", elapsed)
		}
		if account == nil || account.ID() != relay.ID() {
			t.Fatalf("account = %#v, want healthy Relay %d", account, relay.ID())
		}
		if !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceOverflow {
			t.Fatalf("decision = %+v, want OAuth-capacity overflow", decision)
		}
		attempt.Release(handler.store, account)
		atomic.StoreInt64(&oauth.ActiveRequests, 0)
	})
}
