package proxy

import (
	"testing"

	"github.com/codex2api/auth"
)

func TestResponsesAttemptUsesWebsocketTracksActualAccountTransport(t *testing.T) {
	oauthAccount := &auth.Account{AccessToken: "oauth-token"}
	relayAccount := &auth.Account{
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example.test/v1",
		APIKey:       "relay-key",
	}

	tests := []struct {
		name      string
		account   *auth.Account
		requested bool
		want      bool
	}{
		{name: "oauth websocket selected", account: oauthAccount, requested: true, want: true},
		{name: "oauth http selected", account: oauthAccount, requested: false, want: false},
		{name: "relay always uses http", account: relayAccount, requested: true, want: false},
		{name: "nil account cannot use websocket", requested: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := responsesAttemptUsesWebsocket(tc.account, tc.requested); got != tc.want {
				t.Fatalf("responsesAttemptUsesWebsocket() = %v, want %v", got, tc.want)
			}
		})
	}
}
