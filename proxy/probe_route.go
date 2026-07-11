package proxy

import "strings"

const probeRouteSignal = "probe_request"

func detectProbeRoute(rawBody []byte, endpoint, fallbackText string) bool {
	text := strings.TrimSpace(fallbackText)
	if len(rawBody) > 0 {
		if candidate := strings.TrimSpace(requestProbeCandidateText(rawBody, endpoint)); candidate != "" {
			text = candidate
		}
	}
	_, ok := probeSignature(text)
	return ok
}

func appendUniqueRouteSignal(signals []string, signal string) []string {
	signal = strings.TrimSpace(signal)
	if signal == "" {
		return signals
	}
	for _, current := range signals {
		if current == signal {
			return signals
		}
	}
	return append(signals, signal)
}
