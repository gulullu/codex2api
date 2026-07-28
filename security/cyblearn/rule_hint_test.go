package cyblearn

import (
	"strings"
	"testing"
)

func TestRuleMandatoryHintGatePreservesAlternatives(t *testing.T) {
	rule, err := CompileRule("candidate_gate", `(?i)(?:build.{0,20}malware|steal.{0,20}credentials)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"Please build working malware.",
		"Do not steal customer credentials.",
	} {
		lower := strings.ToLower(text)
		if !rule.MayMatchLowerText(lower) {
			t.Fatalf("candidate gate hid matching alternative %q", text)
		}
		if !rule.MatchString(text) {
			t.Fatalf("control rule did not match %q", text)
		}
	}
	if rule.MayMatchLowerText("ordinary pagination status") {
		t.Fatal("ordinary text unexpectedly passed learned-rule candidate gate")
	}
}

func TestRuleMandatoryHintGateKeepsUnhintedRule(t *testing.T) {
	rule, err := CompileRule("unhinted_gate", `[a-z]{7}[0-9]{3}`)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.MayMatchLowerText("ordinary pagination status") {
		t.Fatal("unhinted learned rule must remain conservatively eligible")
	}
}

func TestCompileRuleKeepsLegacyUnboundedExpressions(t *testing.T) {
	rule, err := CompileRule("legacy_spacing", `(?i)build\s+ransomware`)
	if err != nil {
		t.Fatalf("existing legacy rule was rejected: %v", err)
	}
	if !rule.MatchString("Build   ransomware") {
		t.Fatal("existing legacy rule no longer matches")
	}
}
