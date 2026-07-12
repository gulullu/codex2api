package admin

import (
	"testing"
	"time"
)

func TestCodexAuditReportTimeoutAllowsWideWindowsHeadroom(t *testing.T) {
	end := time.Now()
	tests := []struct {
		name string
		span time.Duration
		want time.Duration
	}{
		{name: "three hours", span: 3 * time.Hour, want: 12 * time.Second},
		{name: "twenty four hours", span: 24 * time.Hour, want: 12 * time.Second},
		{name: "three days", span: 72 * time.Hour, want: 20 * time.Second},
		{name: "seven days", span: 168 * time.Hour, want: 20 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := codexAuditReportTimeout(end.Add(-tt.span), end); got != tt.want {
				t.Fatalf("timeout = %s, want %s", got, tt.want)
			}
		})
	}
}
