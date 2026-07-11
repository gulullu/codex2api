package admin

import (
	"context"
)

const (
	defaultAccountBaseConcurrencyMax   int64 = 50
	responsesAPIBaseConcurrencyMax     int64 = 10000
	responsesAPIDefaultBaseConcurrency int64 = 10000
)

func (h *Handler) baseConcurrencyMaxForTargets(ctx context.Context, ids []int64) (int64, error) {
	nonResponsesIDs, err := h.db.FindNonResponsesAPIAccountIDs(ctx, ids)
	if err != nil {
		return 0, err
	}
	if len(nonResponsesIDs) == 0 {
		return responsesAPIBaseConcurrencyMax, nil
	}
	return defaultAccountBaseConcurrencyMax, nil
}
