package proxy

import (
	"github.com/codex2api/security/promptfilter"
)

type wsPromptOutputBuffer struct{}

func newWSPromptOutputBuffer(_ promptfilter.Config) *wsPromptOutputBuffer {
	// sub2 owns output moderation. Returning nil keeps the existing call sites
	// in transparent-pass-through mode regardless of stale database settings.
	return nil
}

func (b *wsPromptOutputBuffer) Push(message []byte) ([][]byte, error) {
	return [][]byte{message}, nil
}

func (b *wsPromptOutputBuffer) Flush() ([][]byte, error) {
	return nil, nil
}
