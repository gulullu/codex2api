package proxy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/database"
)

func TestBackfillLegacyRelayCYBMissSamplesRepairsPrefixAndIsIdempotent(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "cyb-backfill.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID: "recoverable",
		CreatedAt: now,
		Endpoint:  "/v1/chat/completions",
		FullText: `{"messages":[
			{"role":"system","content":"system text must not be learned"},
			{"role":"user","content":"older dangerous user intent"},
			{"role":"assistant","content":"assistant text must not be learned"},
			{"role":"user","content":"current dangerous user intent`,
		ScanTruncated: true,
	}, "oauth")
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:     "unrecoverable",
		CreatedAt:     now.Add(time.Second),
		Endpoint:      "/v1/responses",
		FullText:      `{"instructions":"system only and truncated`,
		ScanTruncated: true,
	}, "oauth")
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID: "relay-cyber",
		CreatedAt: now.Add(2 * time.Second),
		Endpoint:  "/v1/responses",
		FullText:  `{"input":"must remain excluded"}`,
	}, "responses_api")

	handler := &Handler{db: db}
	result, err := handler.BackfillLegacyRelayCYBMissSamples(ctx, 10)
	if err != nil {
		t.Fatalf("BackfillLegacyRelayCYBMissSamples: %v", err)
	}
	if result.Scanned != 2 || result.Queued != 1 || result.Rejected != 1 {
		t.Fatalf("result = %+v", result)
	}

	recovered, err := db.GetRelayCYBMissSample(ctx, "recoverable")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(recoverable): %v", err)
	}
	if recovered.LearningStatus != database.RelayCYBLearningStatusQueued ||
		!strings.Contains(recovered.UserText, "current dangerous user intent") ||
		!strings.Contains(recovered.UserText, "older dangerous user intent") {
		t.Fatalf("recovered sample = %+v", recovered)
	}
	if strings.Contains(recovered.UserText, "system text") ||
		strings.Contains(recovered.UserText, "assistant text") {
		t.Fatalf("non-user content entered learning text: %q", recovered.UserText)
	}

	rejected, err := db.GetRelayCYBMissSample(ctx, "unrecoverable")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(unrecoverable): %v", err)
	}
	if rejected.LearningStatus != database.RelayCYBLearningStatusRejected ||
		rejected.UserText != "" || rejected.LearningError == "" {
		t.Fatalf("rejected sample = %+v", rejected)
	}
	if _, err := db.GetRelayCYBMissSample(ctx, "relay-cyber"); err == nil {
		t.Fatal("Relay account cyber_policy was backfilled as an OAuth miss")
	}

	second, err := handler.BackfillLegacyRelayCYBMissSamples(ctx, 10)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if second.Scanned != 0 || second.Queued != 0 || second.Rejected != 0 {
		t.Fatalf("second result = %+v", second)
	}
	notifications, err := db.ListRelayCYBLearningNotifications(
		ctx,
		now.Add(-time.Minute),
		10,
	)
	if err != nil {
		t.Fatalf("ListRelayCYBLearningNotifications: %v", err)
	}
	if len(notifications) != 1 || notifications[0].EventType != "legacy_backfill" {
		t.Fatalf("notifications = %+v", notifications)
	}
}

func TestRepairRelayCYBTruncatedJSONPrefixIsConservative(t *testing.T) {
	repaired, ok := repairRelayCYBTruncatedJSONPrefix([]byte(
		`{"input":[{"role":"user","content":"recover this user value`,
	))
	if !ok || !strings.Contains(string(repaired), "recover this user value") {
		t.Fatalf("repair = %q, %v", repaired, ok)
	}
	if _, ok := repairRelayCYBTruncatedJSONPrefix([]byte(`{"inpu`)); ok {
		t.Fatal("truncated key was guessed")
	}
	if _, ok := repairRelayCYBTruncatedJSONPrefix([]byte(`{"input":"bad\`)); ok {
		t.Fatal("incomplete escape was guessed")
	}
	colon, ok := repairRelayCYBTruncatedJSONPrefix([]byte(
		`{"input":[{"role":"user","content":"complete user"}],"metadata":`,
	))
	if !ok || !strings.Contains(string(colon), `"metadata":null`) {
		t.Fatalf("colon repair = %q, %v", colon, ok)
	}
	if _, ok := repairRelayCYBTruncatedJSONPrefix([]byte(`not-json`)); ok {
		t.Fatal("arbitrary text was repaired")
	}
}

func writeLegacyCYBAuditCase(
	t *testing.T,
	db *database.DB,
	request database.RelayAuditRequestInput,
	accountType string,
) {
	t.Helper()
	if err := db.WriteRelayAuditRequest(context.Background(), &request); err != nil {
		t.Fatalf("WriteRelayAuditRequest(%s): %v", request.RequestID, err)
	}
	if err := db.WriteRelayAuditAttempt(context.Background(), &database.RelayAuditAttemptInput{
		RequestID:    request.RequestID,
		AttemptIndex: 1,
		AccountID:    51,
		AccountType:  accountType,
		StatusCode:   400,
		ErrorKind:    "cyber_policy",
		SelectedAt:   request.CreatedAt,
	}); err != nil {
		t.Fatalf("WriteRelayAuditAttempt(%s): %v", request.RequestID, err)
	}
}
