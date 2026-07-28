package proxy

import "github.com/codex2api/security/cybtext"

// relayCYBExtractUserSegments is the protocol adapter used only for the
// small-request feedback digest. Large learning/routing inputs use the bounded
// adapter below.
func relayCYBExtractUserSegments(rawBody []byte, endpoint string) (current, history []string) {
	return cybtext.ExtractUserSegments(rawBody, endpoint)
}

// relayCYBExtractUserWindows is the bounded counterpart used for very large
// learning samples and routing rescans. It preserves independent current-user
// and history windows without materializing an oversized JSON string.
func relayCYBExtractUserWindows(
	rawBody []byte,
	endpoint string,
	maxBytes int,
) (current, history []string) {
	return cybtext.ExtractUserWindows(rawBody, endpoint, maxBytes)
}

func relayCYBHasCurrentUserText(rawBody []byte, endpoint string) bool {
	current, _ := cybtext.ExtractUserWindows(rawBody, endpoint, 4*1024)
	return len(current) > 0
}
