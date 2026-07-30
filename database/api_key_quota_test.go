package database

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestResetAPIKeyQuotaPreservesHistoricalUsage(t *testing.T) {
	db, err := New("sqlite", filepath.Join(t.TempDir(), "quota.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	id, err := db.InsertAPIKeyWithOptions(ctx, APIKeyInput{
		Name:       "limited",
		Key:        "sk-reset-single-1234567890",
		QuotaLimit: 10,
		QuotaUsed:  7.5,
	})
	if err != nil {
		t.Fatalf("InsertAPIKeyWithOptions: %v", err)
	}
	if _, err := db.conn.ExecContext(ctx, `UPDATE api_keys SET total_used = 21.5 WHERE id = $1`, id); err != nil {
		t.Fatalf("seed total_used: %v", err)
	}

	if err := db.ResetAPIKeyQuota(ctx, id); err != nil {
		t.Fatalf("ResetAPIKeyQuota: %v", err)
	}
	row, err := db.GetAPIKeyByID(ctx, id)
	if err != nil {
		t.Fatalf("GetAPIKeyByID: %v", err)
	}
	if row.QuotaUsed != 0 || row.TotalUsed != 21.5 {
		t.Fatalf("usage after reset = quota %v total %v, want 0 and 21.5", row.QuotaUsed, row.TotalUsed)
	}
	if row.ResetCount != 1 || !row.LastResetAt.Valid {
		t.Fatalf("reset metadata = count %d time valid %v, want 1 and true", row.ResetCount, row.LastResetAt.Valid)
	}
}

func TestResetAllAPIKeyQuotasOnlyResetsConfiguredQuotas(t *testing.T) {
	db, err := New("sqlite", filepath.Join(t.TempDir(), "quota-all.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	limitedIDs := make([]int64, 0, 2)
	for index, used := range []float64{2.5, 8} {
		id, err := db.InsertAPIKeyWithOptions(ctx, APIKeyInput{
			Name:       "limited",
			Key:        fmt.Sprintf("sk-reset-all-limited-%d-1234567890", index),
			QuotaLimit: 10,
			QuotaUsed:  used,
		})
		if err != nil {
			t.Fatalf("InsertAPIKeyWithOptions limited: %v", err)
		}
		limitedIDs = append(limitedIDs, id)
	}
	unlimitedID, err := db.InsertAPIKeyWithOptions(ctx, APIKeyInput{
		Name:      "unlimited",
		Key:       "sk-reset-all-unlimited-1234567890",
		QuotaUsed: 4,
	})
	if err != nil {
		t.Fatalf("InsertAPIKeyWithOptions unlimited: %v", err)
	}

	count, err := db.ResetAllAPIKeyQuotas(ctx)
	if err != nil {
		t.Fatalf("ResetAllAPIKeyQuotas: %v", err)
	}
	if count != 2 {
		t.Fatalf("reset count = %d, want 2", count)
	}
	for _, id := range limitedIDs {
		row, err := db.GetAPIKeyByID(ctx, id)
		if err != nil {
			t.Fatalf("GetAPIKeyByID(%d): %v", id, err)
		}
		if row.QuotaUsed != 0 || row.ResetCount != 1 || !row.LastResetAt.Valid {
			t.Fatalf("limited row after reset = %#v", row)
		}
	}
	unlimited, err := db.GetAPIKeyByID(ctx, unlimitedID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID(unlimited): %v", err)
	}
	if unlimited.QuotaUsed != 4 || unlimited.ResetCount != 0 || unlimited.LastResetAt.Valid {
		t.Fatalf("unlimited row was unexpectedly reset: %#v", unlimited)
	}
}
