package admin

import (
	"context"
	"errors"
	"log"
	"time"
)

var errRelayCYBLegacyBackfillBatchMissing = errors.New("relay CYB legacy backfill batch is nil")

const relayCYBLegacyBackfillFinalCutoffTick = time.Second

// runRelayCYBLegacyBackfill drains the bounded historical queue once at
// startup. Once a scan returns no candidates, the task exits permanently
// instead of continuing to query the full audit history on a ticker.
func (h *Handler) runRelayCYBLegacyBackfill(ctx context.Context) {
	startupCutoff := time.Now().UTC()
	phaseOneCompleted := false
	err := runRelayCYBLegacyBackfillPhases(
		ctx,
		startupCutoff,
		relayCYBLegacyBackfillSafetyLag,
		waitRelayCYBLegacyBackfill,
		func(ctx context.Context, cutoff time.Time) error {
			afterCreatedAt := relayCYBLegacyBackfillPhaseStart(
				startupCutoff,
				cutoff,
				relayCYBLegacyBackfillSafetyLag,
				phaseOneCompleted,
			)
			var afterRequestID string
			finalPhase := cutoff.After(startupCutoff)
			// Phase two only needs the safety-lag gap. Starting at its lower
			// boundary avoids re-evaluating the entire phase-one audit prefix.
			// If phase one exhausted its retry budget, start from zero instead
			// so the final phase also retries that older prefix.
			err := drainRelayCYBLegacyBackfill(
				ctx,
				relayCYBLegacyBackfillMaxFailures,
				relayCYBLegacyBackfillRetryDelay,
				func(ctx context.Context) (int, error) {
					result, err := h.imageProxy.BackfillLegacyRelayCYBMissSamplesPage(
						ctx,
						relayCYBLegacyBackfillLimit,
						cutoff,
						afterCreatedAt,
						afterRequestID,
					)
					if !result.NextCreatedAt.IsZero() {
						afterCreatedAt = result.NextCreatedAt
						afterRequestID = result.NextRequestID
					}
					if err != nil {
						return 0, err
					}
					if result.Queued+result.Rejected > 0 {
						log.Printf(
							"Relay CYB 历史漏放回填完成: scanned=%d queued=%d rejected=%d",
							result.Scanned,
							result.Queued,
							result.Rejected,
						)
					}
					return result.Scanned, nil
				},
			)
			if !finalPhase && err == nil {
				phaseOneCompleted = true
			}
			return err
		},
	)
	if err != nil && ctx.Err() == nil {
		log.Printf(
			"Relay CYB 历史漏放回填阶段失败（单阶段连续失败上限 %d）: %v",
			relayCYBLegacyBackfillMaxFailures,
			err,
		)
	}
}

func relayCYBLegacyBackfillPhaseStart(
	startupCutoff time.Time,
	phaseCutoff time.Time,
	safetyLag time.Duration,
	phaseOneCompleted bool,
) time.Time {
	if !phaseOneCompleted || !phaseCutoff.After(startupCutoff) {
		return time.Time{}
	}
	return startupCutoff.Add(-safetyLag)
}

func runRelayCYBLegacyBackfillPhases(
	ctx context.Context,
	startupCutoff time.Time,
	safetyLag time.Duration,
	wait func(context.Context, time.Duration) error,
	drain func(context.Context, time.Time) error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if drain == nil {
		return errRelayCYBLegacyBackfillBatchMissing
	}
	if startupCutoff.IsZero() {
		startupCutoff = time.Now().UTC()
	} else {
		startupCutoff = startupCutoff.UTC()
	}
	if safetyLag < 0 {
		safetyLag = 0
	}
	var phaseErrors []error
	if err := drain(ctx, startupCutoff.Add(-safetyLag)); err != nil {
		phaseErrors = append(phaseErrors, err)
	}
	if safetyLag > 0 {
		if wait == nil {
			wait = waitRelayCYBLegacyBackfill
		}
		if err := wait(ctx, safetyLag); err != nil {
			phaseErrors = append(phaseErrors, err)
			return errors.Join(phaseErrors...)
		}
	}
	// The database stores SQLite audit timestamps at one-second precision.
	// Advancing the final exclusive cutoff by one storage tick includes rows
	// whose persisted timestamp equals startupCutoff. The safety-lag wait makes
	// this small post-start window safe from the live sample writer race.
	if err := drain(ctx, startupCutoff.Add(relayCYBLegacyBackfillFinalCutoffTick)); err != nil {
		phaseErrors = append(phaseErrors, err)
	}
	return errors.Join(phaseErrors...)
}

func waitRelayCYBLegacyBackfill(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func relayCYBLegacyBackfillRetryDelay(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}
	return relayCYBLegacyBackfillRetryBasePeriod << (consecutiveFailures - 1)
}

// drainRelayCYBLegacyBackfill repeatedly runs bounded batches until the
// database reports an empty scan. Successful batches reset the consecutive
// failure budget; errors are retried only a finite number of times.
func drainRelayCYBLegacyBackfill(
	ctx context.Context,
	maxConsecutiveFailures int,
	retryDelay func(consecutiveFailures int) time.Duration,
	runBatch func(context.Context) (scanned int, err error),
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if runBatch == nil {
		return errRelayCYBLegacyBackfillBatchMissing
	}
	if maxConsecutiveFailures < 1 {
		maxConsecutiveFailures = 1
	}

	consecutiveFailures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanned, err := runBatch(ctx)
		if err == nil {
			consecutiveFailures = 0
			if scanned == 0 {
				return nil
			}
			continue
		}

		consecutiveFailures++
		if consecutiveFailures >= maxConsecutiveFailures {
			return err
		}
		delay := time.Duration(0)
		if retryDelay != nil {
			delay = retryDelay(consecutiveFailures)
		}
		if delay <= 0 {
			continue
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
