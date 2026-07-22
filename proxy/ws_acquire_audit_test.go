package proxy

import (
	"context"
	"testing"
	"time"
)

func TestWsAcquireAuditAccumulatesResetsAndTolerates(t *testing.T) {
	ctx := withWsAcquireAudit(context.Background())
	AddWsAcquireDuration(ctx, 150*time.Millisecond)
	AddWsAcquireDuration(ctx, 350*time.Millisecond)
	if got := wsAcquireAuditMs(ctx); got != 500 {
		t.Fatalf("wsAcquireAuditMs = %d, want 500 (accumulated)", got)
	}

	// 每 attempt 清零：换号重试后旧值不得泄漏进新 attempt 的日志行
	resetWsAcquireAudit(ctx)
	if got := wsAcquireAuditMs(ctx); got != 0 {
		t.Fatalf("wsAcquireAuditMs after reset = %d, want 0", got)
	}

	// 非正时长与未挂载 audit 的 ctx 都必须安全无操作
	AddWsAcquireDuration(ctx, 0)
	AddWsAcquireDuration(context.Background(), time.Second)
	if got := wsAcquireAuditMs(context.Background()); got != 0 {
		t.Fatalf("wsAcquireAuditMs on bare ctx = %d, want 0", got)
	}
}
