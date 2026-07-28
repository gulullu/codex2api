package cybroute

import (
	"strings"
	"unicode"

	"github.com/codex2api/security/cybtext"
)

// DetectProbe extracts only the latest official current-user envelope
// partition. Historical, system and tool text cannot turn a request into a
// probe.
func DetectProbe(body []byte, endpoint string) (signature string, matched bool) {
	current, _ := cybtext.ExtractUserWindows(body, endpoint, 1024)
	if len(current) != 1 {
		return "", false
	}
	signature = ProbeSignature(current[0])
	return signature, signature != ""
}

// ProbeSignature recognizes the production probe corpus: nineteen normalized
// exact phrases plus two deliberately narrow readiness heuristics.
func ProbeSignature(text string) string {
	normalized := normalizeProbeText(text)
	if normalized == "" || len([]rune(normalized)) > 160 {
		return ""
	}
	exact := map[string]string{
		"hi":                           "hello",
		"hello":                        "hello",
		"ping":                         "ping",
		"pong":                         "ping",
		"test":                         "test",
		"ok":                           "ok",
		"hello world":                  "hello_world",
		"count to seven":               "count_to_seven",
		"count to 7":                   "count_to_seven",
		"whats the opposite of dark":   "opposite_dark",
		"what is the opposite of dark": "opposite_dark",
		"2 乘 2 等于几":                    "two_times_two",
		"2乘2等于几":                       "two_times_two",
		"2*2等于几":                       "two_times_two",
		"2×2等于几":                       "two_times_two",
		"2 x 2 equals what":            "two_times_two",
		"what is 2+2":                  "two_plus_two",
		"what is two plus two":         "two_plus_two",
		"call the probe_ping function with ok=true to acknowledge readiness you must use the tool": "probe_ping",
	}
	if signature, ok := exact[normalized]; ok {
		return signature
	}
	if strings.Contains(normalized, "probe_ping") && strings.Contains(normalized, "ok=true") {
		return "probe_ping"
	}
	if len([]rune(normalized)) <= 80 &&
		strings.Contains(normalized, "acknowledge readiness") &&
		strings.Contains(normalized, "probe") {
		return "probe_readiness"
	}
	return ""
}

func normalizeProbeText(text string) string {
	text = strings.TrimSpace(strings.ToLower(text))
	text = strings.ReplaceAll(text, "’", "'")
	text = strings.ReplaceAll(text, "？", "?")
	text = strings.ReplaceAll(text, "＝", "=")
	text = strings.ReplaceAll(text, "，", ",")
	text = strings.TrimFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("\"'`.,!?;:。！？；：", r)
	})
	var builder strings.Builder
	space := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !space {
				builder.WriteRune(' ')
				space = true
			}
			continue
		}
		if r == '\'' {
			continue
		}
		builder.WriteRune(r)
		space = false
	}
	return strings.TrimSpace(builder.String())
}
