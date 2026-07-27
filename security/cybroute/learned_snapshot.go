package cybroute

import (
	"sync/atomic"

	"github.com/codex2api/security/cyblearn"
)

type learnedRuleSnapshot struct {
	rules []cyblearn.Rule
}

var runtimeLearnedRules atomic.Pointer[learnedRuleSnapshot]

// PublishLearnedRules atomically replaces the routing-only learned rule
// snapshot. The published slice is cloned so callers cannot mutate live
// routing state after publication.
func PublishLearnedRules(rules []cyblearn.Rule) {
	runtimeLearnedRules.Store(&learnedRuleSnapshot{
		rules: append([]cyblearn.Rule(nil), rules...),
	})
}

// LearnedRulesSnapshot returns an independent copy for administrative
// verification. Request routing uses the immutable snapshot directly.
func LearnedRulesSnapshot() []cyblearn.Rule {
	return append([]cyblearn.Rule(nil), currentLearnedRules()...)
}

func currentLearnedRules() []cyblearn.Rule {
	snapshot := runtimeLearnedRules.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot.rules
}
