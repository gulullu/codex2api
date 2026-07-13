package proxy

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestRetryAccountExclusionsSoftResetPreservesHard(t *testing.T) {
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(1)
	exclusions.MarkHard(2)

	selection := exclusions.ForSelection()
	if !selection[1] || !selection[2] {
		t.Fatalf("selection excludes = %#v, want soft and hard accounts", selection)
	}

	if !exclusions.ResetSoft() {
		t.Fatal("ResetSoft() = false, want true")
	}
	selection = exclusions.ForSelection()
	if selection[1] {
		t.Fatalf("soft account still excluded after reset: %#v", selection)
	}
	if !selection[2] {
		t.Fatalf("hard account was cleared by soft reset: %#v", selection)
	}
}

func TestRetryAccountExclusionsHardOverridesSoft(t *testing.T) {
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(1)
	exclusions.MarkHard(1)

	if exclusions.ResetSoft() {
		t.Fatal("ResetSoft() cleared a hard-only account")
	}
	selection := exclusions.ForSelection()
	if !selection[1] {
		t.Fatalf("hard account missing from selection excludes: %#v", selection)
	}
}

func TestIsFirstTokenTimeoutOutcome(t *testing.T) {
	if !isFirstTokenTimeoutOutcome(firstTokenTimeoutOutcome(10)) {
		t.Fatal("first-token timeout outcome should be classified as timeout")
	}
	if isFirstTokenTimeoutOutcome(streamOutcome{failureKind: "transport"}) {
		t.Fatal("transport outcome should not be classified as first-token timeout")
	}
}

func TestWebsocketHTTPFallbackStateRetainsLeaseOnce(t *testing.T) {
	account := &auth.Account{DBID: 7}
	var state websocketHTTPFallbackState
	state.Retain(account, "http://proxy.example", 1500*time.Millisecond, "local_read_limit")

	if !state.ForceHTTP() {
		t.Fatal("ForceHTTP() = false after retaining a WebSocket 1009 fallback")
	}
	if state.ID() == "" {
		t.Fatal("fallback correlation ID is empty")
	}
	if state.Source() != "local_read_limit" {
		t.Fatalf("source = %q, want local_read_limit", state.Source())
	}
	gotAccount, gotProxy, ok := state.Take()
	if !ok || gotAccount != account || gotProxy != "http://proxy.example" {
		t.Fatalf("Take() = (%p, %q, %v), want retained account/proxy", gotAccount, gotProxy, ok)
	}
	if _, _, ok := state.Take(); ok {
		t.Fatal("second Take() reused the retained account lease")
	}
	if !state.ForceHTTP() {
		t.Fatal("ForceHTTP() reset after consuming the retained lease")
	}
}

func TestWebsocketHTTPFallbackStateRetainsRoutedOwnershipOnce(t *testing.T) {
	account := &auth.Account{DBID: 7}
	circuitAttempt := inactiveRelayCircuitAttempt()
	decision := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		RouteSource: cybRelayRouteSourceDirect,
		Reason:      "test-route",
	}
	var state websocketHTTPFallbackState
	state.RetainRouted(account, "http://proxy.example", time.Second, "peer_close", circuitAttempt, decision)

	gotAccount, gotProxy, gotCircuit, gotDecision, ok := state.TakeRouted()
	if !ok || gotAccount != account || gotProxy != "http://proxy.example" {
		t.Fatalf("TakeRouted account/proxy = (%p, %q, %v)", gotAccount, gotProxy, ok)
	}
	if gotCircuit != circuitAttempt {
		t.Fatal("TakeRouted replaced the retained circuit attempt")
	}
	if gotDecision.Disposition != decision.Disposition || gotDecision.RouteSource != decision.RouteSource || gotDecision.Reason != decision.Reason {
		t.Fatalf("TakeRouted route decision = %+v, want %+v", gotDecision, decision)
	}
	if _, _, _, _, ok := state.TakeRouted(); ok {
		t.Fatal("second TakeRouted reused retained ownership")
	}
}

func TestWebsocketHTTPFallbackStateCumulativeMetrics(t *testing.T) {
	var state websocketHTTPFallbackState
	state.Retain(&auth.Account{DBID: 7}, "", 1500*time.Millisecond, "peer_close")
	state.startedAt = time.Time{}

	totalElapsed, totalFirstEvent := state.CumulativeHTTPMetrics(500, 100)
	if totalElapsed != 2000 || totalFirstEvent != 1600 {
		t.Fatalf("cumulative metrics = elapsed:%d first:%d, want 2000/1600", totalElapsed, totalFirstEvent)
	}
	if elapsed, first := state.CumulativeHTTPMetrics(500, 0); elapsed != 2000 || first != 0 {
		t.Fatalf("no-event metrics = elapsed:%d first:%d, want 2000/0", elapsed, first)
	}
}

func TestApplyWebsocketHTTPFallbackAuditMetricsCanonicalOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	var state websocketHTTPFallbackState
	state.Retain(&auth.Account{DBID: 7}, "", 1500*time.Millisecond, "peer_close")
	state.startedAt = time.Time{}
	registerWebsocketHTTPFallbackAuditState(c, &state)

	canonical := &database.UsageLogInput{DurationMs: 500, FirstTokenMs: 100}
	applyWebsocketHTTPFallbackAuditMetrics(c, canonical)
	if canonical.DurationMs != 2000 || canonical.FirstTokenMs != 1600 {
		t.Fatalf("canonical metrics = elapsed:%d first:%d, want cumulative 2000/1600", canonical.DurationMs, canonical.FirstTokenMs)
	}

	hidden := &database.UsageLogInput{DurationMs: 500, FirstTokenMs: 100, GuardianAttemptOnly: true}
	applyWebsocketHTTPFallbackAuditMetrics(c, hidden)
	if hidden.DurationMs != 500 || hidden.FirstTokenMs != 100 {
		t.Fatalf("hidden retry metrics changed to elapsed:%d first:%d", hidden.DurationMs, hidden.FirstTokenMs)
	}

	websocket := &database.UsageLogInput{DurationMs: 1500, ViaWebsocket: true}
	applyWebsocketHTTPFallbackAuditMetrics(c, websocket)
	if websocket.DurationMs != 1500 || websocket.FirstTokenMs != 0 {
		t.Fatalf("WebSocket diagnostic metrics changed to elapsed:%d first:%d", websocket.DurationMs, websocket.FirstTokenMs)
	}
}

func TestWebsocketHTTPFallbackStateLogsAttemptsWithoutInventingFirstEvent(t *testing.T) {
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	account := &auth.Account{DBID: 7}
	var state websocketHTTPFallbackState
	state.Retain(account, "", 1500*time.Millisecond, "peer_close")
	fallbackID := state.ID()
	state.LogHTTPAttemptCompletion("/v1/responses", account.ID(), 2, 500, 0, logStatusUpstreamStreamBreak)

	firstAttempt := logs.String()
	for _, want := range []string{
		"fallback_id=" + fallbackID,
		"attempt=2",
		"http_first_event_ms=0",
		"total_first_event_ms=0",
	} {
		if !strings.Contains(firstAttempt, want) {
			t.Fatalf("first attempt log missing %q: %s", want, firstAttempt)
		}
	}

	logs.Reset()
	state.LogHTTPAttemptCompletion("/v1/responses", account.ID(), 3, 500, 100, 200)
	secondAttempt := logs.String()
	if !strings.Contains(secondAttempt, "fallback_id="+fallbackID) || !strings.Contains(secondAttempt, "attempt=3") {
		t.Fatalf("subsequent attempt lost fallback correlation: %s", secondAttempt)
	}
	if strings.Contains(secondAttempt, "total_first_event_ms=0") {
		t.Fatalf("observed first event was not included in cumulative timing: %s", secondAttempt)
	}
}
