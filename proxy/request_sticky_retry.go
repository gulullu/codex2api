package proxy

import "github.com/codex2api/auth"

// requestStickyRetryState keeps transport-policy stickiness local to one
// logical request. It deliberately does not create a session binding: an
// empty scheduler affinity key must stay empty across independent requests,
// while a retry inside the current request may still reacquire the same
// account and proxy.
type requestStickyRetryState struct {
	accountID int64
	proxyURL  string
}

func (s *requestStickyRetryState) Retain(account *auth.Account, proxyURL string) {
	if s == nil || account == nil {
		return
	}
	s.accountID = account.ID()
	s.proxyURL = proxyURL
}

func (s *requestStickyRetryState) AccountFilter(base auth.AccountFilter) auth.AccountFilter {
	if s == nil || s.accountID == 0 {
		return base
	}
	accountID := s.accountID
	return accountFilterAnd(base, func(account *auth.Account) bool {
		return account != nil && account.ID() == accountID
	})
}

// Apply restores the retained proxy after the scheduler has reacquired the
// retained account, then consumes the one-attempt preference. Another
// transport failure may retain it again for the following attempt.
func (s *requestStickyRetryState) Apply(account *auth.Account, proxyURL *string) bool {
	if s == nil || s.accountID == 0 || account == nil || account.ID() != s.accountID {
		return false
	}
	if proxyURL != nil {
		*proxyURL = s.proxyURL
	}
	s.accountID = 0
	s.proxyURL = ""
	return true
}
