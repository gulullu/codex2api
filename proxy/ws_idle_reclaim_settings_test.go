package proxy

import "testing"

func TestDefaultRuntimeSettingsIdleReclaimDisabled(t *testing.T) {
	settings := DefaultRuntimeSettings()
	if settings.CodexWSIdleReclaimEnabled || settings.CodexWSIdleReclaimPercent != 0 {
		t.Fatalf("default idle reclaim = enabled:%v percent:%d, want disabled at 0%%", settings.CodexWSIdleReclaimEnabled, settings.CodexWSIdleReclaimPercent)
	}
	if settings.CodexWSIdleReclaimIdleSec != 10*60 {
		t.Fatalf("default idle threshold = %d, want 600", settings.CodexWSIdleReclaimIdleSec)
	}
}

func TestNormalizeRuntimeSettingsIdleReclaimFailClosed(t *testing.T) {
	settings := DefaultRuntimeSettings()
	settings.CodexWSIdleReclaimEnabled = true
	settings.CodexWSIdleReclaimPercent = 17
	settings.CodexWSIdleReclaimIdleSec = 60
	settings = NormalizeRuntimeSettings(settings)
	if settings.CodexWSIdleReclaimPercent != 0 {
		t.Fatalf("invalid rollout normalized to %d, want 0", settings.CodexWSIdleReclaimPercent)
	}
	if settings.CodexWSIdleReclaimIdleSec != 10*60 {
		t.Fatalf("unsafe idle threshold normalized to %d, want conservative default 600", settings.CodexWSIdleReclaimIdleSec)
	}

	settings.CodexWSIdleReclaimPercent = 5
	settings.CodexWSIdleReclaimIdleSec = 5 * 60
	settings = NormalizeRuntimeSettings(settings)
	if settings.CodexWSIdleReclaimPercent != 5 || settings.CodexWSIdleReclaimIdleSec != 5*60 {
		t.Fatalf("valid canary normalized to percent:%d idle:%d", settings.CodexWSIdleReclaimPercent, settings.CodexWSIdleReclaimIdleSec)
	}
}

func TestApplyRuntimeSettingsIdleReclaimHotUpdate(t *testing.T) {
	previous := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previous) })

	settings := previous
	settings.CodexWSIdleReclaimEnabled = true
	settings.CodexWSIdleReclaimPercent = 5
	settings.CodexWSIdleReclaimIdleSec = 8 * 60
	ApplyRuntimeSettings(settings)
	first := CurrentRuntimeSettings()
	if !first.CodexWSIdleReclaimEnabled || first.CodexWSIdleReclaimPercent != 5 || first.CodexWSIdleReclaimIdleSec != 8*60 {
		t.Fatalf("first hot update = %+v", first)
	}

	settings.CodexWSIdleReclaimPercent = 20
	settings.CodexWSIdleReclaimIdleSec = 10 * 60
	ApplyRuntimeSettings(settings)
	second := CurrentRuntimeSettings()
	if !second.CodexWSIdleReclaimEnabled || second.CodexWSIdleReclaimPercent != 20 || second.CodexWSIdleReclaimIdleSec != 10*60 {
		t.Fatalf("second hot update = %+v", second)
	}
}
