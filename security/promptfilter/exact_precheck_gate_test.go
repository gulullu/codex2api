package promptfilter

import "testing"

func TestExactPrecheckMayMatchSkipsOrdinaryText(t *testing.T) {
	cfg := RecommendedConfig()
	cfg.Enabled = true
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if engine.ExactPrecheckMayMatch("ordinary application status and pagination context") {
		t.Fatal("ordinary text unexpectedly passed the exact precheck hint gate")
	}
}

func TestExactPrecheckMayMatchKeepsConfiguredRuleCandidate(t *testing.T) {
	cfg := RecommendedConfig()
	cfg.Enabled = true
	cfg.CustomPatterns = append(cfg.CustomPatterns, PatternConfig{
		Name:     "gate_candidate",
		Pattern:  `(?i)\buniquely dangerous operation\b`,
		Weight:   100,
		Category: "cyber",
		Strict:   true,
	})
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := "please perform the uniquely dangerous operation now"
	if !engine.ExactPrecheckMayMatch(text) {
		t.Fatal("configured rule candidate was hidden by the exact precheck hint gate")
	}
	verdict := engine.InspectTextWithExactPrecheck(text, cfg.Advanced.Guard.Performance)
	if !hasMatchNamed(verdict.Matched, "gate_candidate") {
		t.Fatalf("configured rule was not preserved by exact precheck: %+v", verdict)
	}
}

func TestExactPrecheckMayMatchKeepsDerivedAndUnhintedCandidates(t *testing.T) {
	t.Run("derived normalization", func(t *testing.T) {
		cfg := RecommendedConfig()
		cfg.Enabled = true
		engine, err := NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !engine.ExactPrecheckMayMatch(`ordinary\u0020text`) {
			t.Fatal("escape-bearing text must reach exact normalization precheck")
		}
	})

	t.Run("unhinted custom pattern", func(t *testing.T) {
		cfg := RecommendedConfig()
		cfg.Enabled = true
		cfg.CustomPatterns = append(cfg.CustomPatterns, PatternConfig{
			Name:     "unhinted_candidate",
			Pattern:  `(?i)\b[a-z]{7}[0-9]{3}\b`,
			Weight:   100,
			Category: "cyber",
			Strict:   true,
		})
		engine, err := NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !engine.ExactPrecheckMayMatch("ordinary text without the expression") {
			t.Fatal("unhinted custom pattern must conservatively keep every chunk")
		}
	})

}

func TestNormalizedASCIIHintGateMatchesCanonicalNormalization(t *testing.T) {
	cfg := RecommendedConfig()
	cfg.Enabled = true
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	scanner := engine.exactPrecheckScanner
	for _, source := range []string{
		"WRITE   MALWARE",
		"write\tmalware",
		"write```ignored fence separator```malware",
		"write\x00malware",
		"ordinary application status",
	} {
		got, gotUnhinted := decodedSafetyPriorityMatchedHintsSource(source, scanner)
		want, wantUnhinted := decodedSafetyPriorityMatchedHints(normalizeForScan(source), scanner)
		if gotUnhinted != wantUnhinted || !sameHintSet(got, want) {
			t.Fatalf("ASCII source gate drift for %q: got=%v/%v want=%v/%v", source, got, gotUnhinted, want, wantUnhinted)
		}
	}
}

func TestNormalizedASCIIROT13HintGateMatchesCanonicalNormalization(t *testing.T) {
	cfg := RecommendedConfig()
	cfg.Enabled = true
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	automaton := engine.exactPrecheckScanner.hintIndex.automaton
	for _, source := range []string{
		"JEVGR   ZNYJNER",
		"jevgṛ znyjner",
		"jevgr```separator```znyjner",
		"ordinary application status",
	} {
		got := automaton.matchNormalizedROT13Source(source)
		want := automaton.matchNormalizedSourceWithTransform(source, func(value rune) rune {
			switch {
			case value >= 'a' && value <= 'z':
				return 'a' + (value-'a'+13)%26
			case value >= 'A' && value <= 'Z':
				return 'A' + (value-'A'+13)%26
			default:
				return value
			}
		})
		if !sameHintSet(got, want) {
			t.Fatalf("ASCII ROT13 source gate drift for %q: got=%v want=%v", source, got, want)
		}
	}
}

func sameHintSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for hint := range left {
		if _, exists := right[hint]; !exists {
			return false
		}
	}
	return true
}

func hasMatchNamed(matches []Match, name string) bool {
	for _, match := range matches {
		if match.Name == name {
			return true
		}
	}
	return false
}
