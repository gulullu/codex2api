package proxy

import (
	"context"
	"log"
	"time"

	"github.com/codex2api/auth"
	"github.com/google/uuid"
)

type retryAccountExclusions struct {
	hard map[int64]bool
	soft map[int64]bool
}

// websocketHTTPFallbackState carries the already-acquired account lease across
// a one-time WebSocket -> HTTP transport downgrade. A close 1009 is a transport
// limitation, not a reason to release the account and run the scheduler again.
type websocketHTTPFallbackState struct {
	forcedHTTP       bool
	account          *auth.Account
	proxyURL         string
	wsElapsed        time.Duration
	source           string
	fallbackID       string
	startedAt        time.Time
	circuitAttempt   *relayCircuitAttempt
	routeDecision    promptRiskDecision
	hasRouteDecision bool
}

func (s *websocketHTTPFallbackState) Retain(account *auth.Account, proxyURL string, wsElapsed time.Duration, source string) {
	if s == nil || account == nil {
		return
	}
	s.forcedHTTP = true
	s.account = account
	s.proxyURL = proxyURL
	s.circuitAttempt = nil
	s.routeDecision = promptRiskDecision{}
	s.hasRouteDecision = false
	s.wsElapsed = wsElapsed
	s.source = source
	if s.startedAt.IsZero() {
		s.startedAt = time.Now().Add(-wsElapsed)
	}
	if s.fallbackID == "" {
		s.fallbackID = uuid.NewString()
	}
}

// RetainRouted keeps both scheduler ownership and the already-acquired Relay
// breaker permit across a one-time WebSocket -> HTTP downgrade. The HTTP
// attempt must not run account selection or acquire a second permit.
func (s *websocketHTTPFallbackState) RetainRouted(account *auth.Account, proxyURL string, wsElapsed time.Duration, source string, circuitAttempt *relayCircuitAttempt, routeDecision promptRiskDecision) {
	s.Retain(account, proxyURL, wsElapsed, source)
	if s == nil || account == nil {
		return
	}
	s.circuitAttempt = circuitAttempt
	s.routeDecision = routeDecision
	s.hasRouteDecision = true
}

func (s *websocketHTTPFallbackState) Take() (*auth.Account, string, bool) {
	if s == nil || s.account == nil {
		return nil, "", false
	}
	account := s.account
	proxyURL := s.proxyURL
	s.account = nil
	s.proxyURL = ""
	s.circuitAttempt = nil
	s.routeDecision = promptRiskDecision{}
	s.hasRouteDecision = false
	return account, proxyURL, true
}

// TakeRouted transfers the retained account lease, Relay permit and route
// decision to the HTTP attempt. Ownership is cleared from the fallback state
// so the normal attempt cleanup remains the single release point.
func (s *websocketHTTPFallbackState) TakeRouted() (*auth.Account, string, *relayCircuitAttempt, promptRiskDecision, bool) {
	if s == nil || s.account == nil {
		return nil, "", inactiveRelayCircuitAttempt(), defaultPromptRiskDecision(), false
	}
	account := s.account
	proxyURL := s.proxyURL
	circuitAttempt := s.circuitAttempt
	if circuitAttempt == nil {
		circuitAttempt = inactiveRelayCircuitAttempt()
	}
	routeDecision := s.routeDecision
	if !s.hasRouteDecision {
		routeDecision = defaultPromptRiskDecision()
	}
	s.account = nil
	s.proxyURL = ""
	s.circuitAttempt = nil
	s.routeDecision = promptRiskDecision{}
	s.hasRouteDecision = false
	return account, proxyURL, circuitAttempt, routeDecision, true
}

func (s *websocketHTTPFallbackState) ForceHTTP() bool {
	return s != nil && s.forcedHTTP
}

func (s *websocketHTTPFallbackState) WSElapsed() time.Duration {
	if s == nil {
		return 0
	}
	return s.wsElapsed
}

func (s *websocketHTTPFallbackState) ID() string {
	if s == nil {
		return ""
	}
	return s.fallbackID
}

func (s *websocketHTTPFallbackState) Source() string {
	if s == nil || s.source == "" {
		return "peer_close"
	}
	return s.source
}

// CumulativeHTTPMetrics converts an HTTP fallback attempt's local timings into
// the user-visible timings measured from the beginning of the retained
// WebSocket attempt. This keeps canonical audit latency honest while the WS
// failure itself remains a hidden diagnostic attempt.
func (s *websocketHTTPFallbackState) CumulativeHTTPMetrics(httpElapsedMs, httpFirstEventMs int) (int, int) {
	if s == nil || !s.forcedHTTP {
		return httpElapsedMs, httpFirstEventMs
	}
	totalElapsedMs := s.wsElapsed.Milliseconds() + int64(httpElapsedMs)
	if !s.startedAt.IsZero() {
		totalElapsedMs = time.Since(s.startedAt).Milliseconds()
	}
	if totalElapsedMs < 0 {
		totalElapsedMs = 0
	}
	totalFirstEventMs := int64(0)
	if httpFirstEventMs > 0 {
		postFirstEventMs := int64(httpElapsedMs - httpFirstEventMs)
		if postFirstEventMs < 0 {
			postFirstEventMs = 0
		}
		totalFirstEventMs = totalElapsedMs - postFirstEventMs
		if totalFirstEventMs < 0 {
			totalFirstEventMs = 0
		}
	}
	return int(totalElapsedMs), int(totalFirstEventMs)
}

func (s *websocketHTTPFallbackState) LogHTTPAttemptCompletion(endpoint string, accountID int64, attemptIndex, httpElapsedMs, httpFirstEventMs, statusCode int) {
	if s == nil || !s.forcedHTTP {
		return
	}
	wsElapsedMs := s.wsElapsed.Milliseconds()
	totalElapsedMs, totalFirstEventMs := s.CumulativeHTTPMetrics(httpElapsedMs, httpFirstEventMs)
	log.Printf("WebSocket 1009 HTTP 降级尝试结束 (fallback_id=%s, source=%s, attempt=%d, account=%d, endpoint=%s, status=%d, ws_elapsed_ms=%d, http_elapsed_ms=%d, http_first_event_ms=%d, total_first_event_ms=%d, total_elapsed_ms=%d)",
		s.fallbackID, s.Source(), attemptIndex, accountID, endpoint, statusCode, wsElapsedMs, httpElapsedMs, httpFirstEventMs,
		totalFirstEventMs, totalElapsedMs)
}

func newRetryAccountExclusions() *retryAccountExclusions {
	return &retryAccountExclusions{
		hard: make(map[int64]bool),
		soft: make(map[int64]bool),
	}
}

func (r *retryAccountExclusions) MarkHard(accountID int64) {
	if r == nil || accountID == 0 {
		return
	}
	r.hard[accountID] = true
	delete(r.soft, accountID)
}

func (r *retryAccountExclusions) IsHard(accountID int64) bool {
	return r != nil && accountID != 0 && r.hard[accountID]
}

func (r *retryAccountExclusions) IsSoft(accountID int64) bool {
	return r != nil && accountID != 0 && r.soft[accountID]
}

func (r *retryAccountExclusions) MarkSoftFirstTokenTimeout(accountID int64) {
	if r == nil || accountID == 0 {
		return
	}
	if r.hard[accountID] {
		return
	}
	r.soft[accountID] = true
}

func (r *retryAccountExclusions) ResetSoft() bool {
	if r == nil || len(r.soft) == 0 {
		return false
	}
	r.soft = make(map[int64]bool)
	return true
}

func (r *retryAccountExclusions) ForSelection() map[int64]bool {
	if r == nil || (len(r.hard) == 0 && len(r.soft) == 0) {
		return nil
	}
	exclude := make(map[int64]bool, len(r.hard)+len(r.soft))
	for id := range r.hard {
		exclude[id] = true
	}
	for id := range r.soft {
		exclude[id] = true
	}
	return exclude
}

func (h *Handler) nextRetryAccountForSession(ctx context.Context, affinityKey string, apiKeyID int64, exclusions *retryAccountExclusions, filter auth.AccountFilter) (*auth.Account, string) {
	if h == nil || h.store == nil {
		return nil, ""
	}
	for {
		exclude := exclusions.ForSelection()
		account, stickyProxyURL := h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, filter)
		if account != nil {
			return account, stickyProxyURL
		}
		account, stickyProxyURL = h.store.WaitForSessionAvailableWithFilter(ctx, affinityKey, 30*time.Second, apiKeyID, exclude, filter)
		if account != nil {
			return account, stickyProxyURL
		}
		if !exclusions.ResetSoft() {
			return nil, ""
		}
		log.Printf("首字超时账号池已试完，清空本次请求软排除并进入下一轮重试")
	}
}

func isFirstTokenTimeoutOutcome(outcome streamOutcome) bool {
	return outcome.softFirstTokenTimeout
}
