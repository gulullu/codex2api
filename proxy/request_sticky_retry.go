package proxy

import "github.com/codex2api/auth"

// requestStickyRetryState keeps transport-policy stickiness local to one
// logical request. It deliberately does not create a session binding: an
// empty scheduler affinity key must stay empty across independent requests,
// while a retry inside the current request may still prefer the same account
// and proxy. The preference is consumed before selection so a temporarily
// full retained account can never turn the request into a 30-second wait and
// a synthetic no_available_account failure while healthy peers exist.
type requestStickyRetryState struct {
	accountID int64
	proxyURL  string
}

func (h *Handler) requestStickyRetryAccountEligible(account *auth.Account) bool {
	if account == nil {
		return false
	}
	cfg := h.cybRelayConfig()
	return !cfg.Enabled || cfg.GroupID <= 0 || !account.IsOpenAIResponsesAPI() || !account.HasGroupID(cfg.GroupID)
}

func (s *requestStickyRetryState) Retain(account *auth.Account, proxyURL string) {
	if s == nil || account == nil {
		return
	}
	s.accountID = account.ID()
	s.proxyURL = proxyURL
}

func (s *requestStickyRetryState) TakeAccountFilter(base auth.AccountFilter) (auth.AccountFilter, string, bool) {
	if s == nil || s.accountID == 0 {
		return nil, "", false
	}
	accountID := s.accountID
	proxyURL := s.proxyURL
	s.accountID = 0
	s.proxyURL = ""
	filter := accountFilterAnd(base, func(account *auth.Account) bool {
		return account != nil && account.ID() == accountID
	})
	return filter, proxyURL, true
}
