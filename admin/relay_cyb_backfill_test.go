package admin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDrainRelayCYBLegacyBackfillStopsOnEmptyBatch(t *testing.T) {
	scans := []int{100, 7, 0}
	calls := 0
	err := drainRelayCYBLegacyBackfill(
		context.Background(),
		3,
		func(int) time.Duration { return 0 },
		func(context.Context) (int, error) {
			scanned := scans[calls]
			calls++
			return scanned, nil
		},
	)
	if err != nil {
		t.Fatalf("drainRelayCYBLegacyBackfill: %v", err)
	}
	if calls != len(scans) {
		t.Fatalf("batch calls = %d, want %d", calls, len(scans))
	}
}

func TestDrainRelayCYBLegacyBackfillBoundsConsecutiveFailures(t *testing.T) {
	wantErr := errors.New("temporary backfill failure")
	calls := 0
	err := drainRelayCYBLegacyBackfill(
		context.Background(),
		3,
		func(int) time.Duration { return 0 },
		func(context.Context) (int, error) {
			calls++
			return 0, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if calls != 3 {
		t.Fatalf("batch calls = %d, want 3", calls)
	}
}

func TestDrainRelayCYBLegacyBackfillResetsFailuresAfterSuccess(t *testing.T) {
	wantErr := errors.New("temporary backfill failure")
	type batchResult struct {
		scanned int
		err     error
	}
	results := []batchResult{
		{err: wantErr},
		{scanned: 100},
		{err: wantErr},
		{},
	}
	calls := 0
	err := drainRelayCYBLegacyBackfill(
		context.Background(),
		2,
		func(int) time.Duration { return 0 },
		func(context.Context) (int, error) {
			result := results[calls]
			calls++
			return result.scanned, result.err
		},
	)
	if err != nil {
		t.Fatalf("drainRelayCYBLegacyBackfill: %v", err)
	}
	if calls != len(results) {
		t.Fatalf("batch calls = %d, want %d", calls, len(results))
	}
}

func TestDrainRelayCYBLegacyBackfillCancellationInterruptsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	firstCall := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- drainRelayCYBLegacyBackfill(
			ctx,
			3,
			func(int) time.Duration { return time.Hour },
			func(context.Context) (int, error) {
				close(firstCall)
				return 0, errors.New("temporary backfill failure")
			},
		)
	}()

	<-firstCall
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backfill retry did not stop after context cancellation")
	}
}

func TestRunRelayCYBLegacyBackfillPhasesClosesSafetyLagGap(t *testing.T) {
	startupCutoff := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	safetyLag := 10 * time.Minute
	var cutoffs []time.Time
	var waited time.Duration
	err := runRelayCYBLegacyBackfillPhases(
		context.Background(),
		startupCutoff,
		safetyLag,
		func(_ context.Context, delay time.Duration) error {
			waited = delay
			return nil
		},
		func(_ context.Context, cutoff time.Time) error {
			cutoffs = append(cutoffs, cutoff)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runRelayCYBLegacyBackfillPhases: %v", err)
	}
	if waited != safetyLag {
		t.Fatalf("waited = %s, want %s", waited, safetyLag)
	}
	if len(cutoffs) != 2 ||
		!cutoffs[0].Equal(startupCutoff.Add(-safetyLag)) ||
		!cutoffs[1].Equal(startupCutoff.Add(relayCYBLegacyBackfillFinalCutoffTick)) {
		t.Fatalf("phase cutoffs = %v", cutoffs)
	}
}

func TestRelayCYBLegacyBackfillFinalPhaseRetriesOldPrefixAfterPhaseOneFailure(t *testing.T) {
	startupCutoff := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	finalCutoff := startupCutoff.Add(relayCYBLegacyBackfillFinalCutoffTick)
	safetyLag := 10 * time.Minute

	if got := relayCYBLegacyBackfillPhaseStart(
		startupCutoff,
		finalCutoff,
		safetyLag,
		false,
	); !got.IsZero() {
		t.Fatalf("failed phase one skipped old prefix from %v", got)
	}
	if got := relayCYBLegacyBackfillPhaseStart(
		startupCutoff,
		finalCutoff,
		safetyLag,
		true,
	); !got.Equal(startupCutoff.Add(-safetyLag)) {
		t.Fatalf("successful phase one final cursor = %v", got)
	}
}
