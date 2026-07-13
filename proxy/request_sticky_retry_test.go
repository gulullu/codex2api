package proxy

import (
	"testing"

	"github.com/codex2api/auth"
)

func TestRequestStickyRetryStatePinsOnlyTheNextAttempt(t *testing.T) {
	first := &auth.Account{DBID: 1}
	second := &auth.Account{DBID: 2}
	var state requestStickyRetryState

	state.Retain(first, "http://proxy-one.example")
	filter := state.AccountFilter(nil)
	if !filter(first) || filter(second) {
		t.Fatal("retry filter did not select only the retained account")
	}

	proxyURL := "http://new-proxy.example"
	if state.Apply(second, &proxyURL) {
		t.Fatal("different account unexpectedly consumed retained retry state")
	}
	if proxyURL != "http://new-proxy.example" {
		t.Fatalf("different account changed proxy to %q", proxyURL)
	}
	if !state.Apply(first, &proxyURL) {
		t.Fatal("retained account did not consume retry state")
	}
	if proxyURL != "http://proxy-one.example" {
		t.Fatalf("proxy = %q, want retained proxy", proxyURL)
	}
	if got := state.AccountFilter(nil); got != nil {
		t.Fatal("consumed retry state still restricts later attempts")
	}
}

func TestRequestStickyRetryStateRespectsBaseFilter(t *testing.T) {
	account := &auth.Account{DBID: 1}
	var state requestStickyRetryState
	state.Retain(account, "")
	filter := state.AccountFilter(func(*auth.Account) bool { return false })
	if filter(account) {
		t.Fatal("retry filter bypassed the route/model base filter")
	}
}
