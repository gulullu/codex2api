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
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "7")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
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
	if err := db.SetAccountGroups(ctx, 51, []int64{7}); err != nil {
		t.Fatalf("SetAccountGroups: %v", err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID: "recoverable",
		CreatedAt: now,
		Endpoint:  "/v1/chat/completions",
		FullText: `{"messages":[
			{"role":"system","content":"system text must not be learned"},
			{"role":"user","content":"older dangerous user intent"},
			{"role":"assistant","content":"assistant text must not be learned"},
			{"role":"user","content":"current dangerous user intent\u0000with suffix`,
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
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:   "relay-eligible",
		CreatedAt:   now.Add(3 * time.Second),
		Endpoint:    "/v1/responses",
		RouteSource: relayRouteSourceNoAffinity,
		FullText:    `{"input":"actual Relay CYB not covered locally"}`,
	}, "responses_api")
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:    "relay-continuation",
		CreatedAt:    now.Add(4 * time.Second),
		Endpoint:     "/v1/responses",
		RouteSource:  relayRouteSourceContinuation,
		RouteGroupID: 7,
		FullText:     `{"input":"continuation with a new current user should be learned"}`,
	}, "responses_api")
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:    "relay-old-group",
		CreatedAt:    now.Add(5 * time.Second),
		Endpoint:     "/v1/responses",
		RouteSource:  relayRouteSourceNoAffinity,
		RouteGroupID: 8,
		FullText:     `{"input":"old configured group must remain excluded"}`,
	}, "responses_api")
	overflowRequest := database.RelayAuditRequestInput{
		RequestID:   "overflow-relay-eligible",
		CreatedAt:   now.Add(6 * time.Second),
		Endpoint:    "/v1/responses",
		RouteSource: relayRouteSourceOverflow,
		FullText:    `{"input":"overflow Relay CYB not covered locally"}`,
	}
	if err := db.WriteRelayAuditRequest(ctx, &overflowRequest); err != nil {
		t.Fatalf("WriteRelayAuditRequest(overflow): %v", err)
	}
	for _, attempt := range []database.RelayAuditAttemptInput{
		{
			RequestID: "overflow-relay-eligible", AttemptIndex: 1,
			AccountID: 52, AccountType: "oauth", StatusCode: 400,
			ErrorKind: "cyber_policy", SelectedAt: overflowRequest.CreatedAt,
		},
		{
			RequestID: "overflow-relay-eligible", AttemptIndex: 2,
			AccountID: 51, AccountType: "responses_api", StatusCode: 200,
			SelectedAt: overflowRequest.CreatedAt.Add(time.Millisecond),
		},
	} {
		if err := db.WriteRelayAuditAttempt(ctx, &attempt); err != nil {
			t.Fatalf("WriteRelayAuditAttempt(overflow %d): %v", attempt.AttemptIndex, err)
		}
	}
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:    "overflow-relay-only",
		CreatedAt:    now.Add(7 * time.Second),
		Endpoint:     "/v1/responses",
		RouteSource:  relayRouteSourceOverflow,
		RouteGroupID: 7,
		FullText:     `{"input":"overflow direct Relay CYB not covered locally"}`,
	}, "responses_api")
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:    "relay-tool-only",
		CreatedAt:    now.Add(8 * time.Second),
		Endpoint:     "/v1/responses",
		RouteSource:  relayRouteSourceNoAffinity,
		RouteGroupID: 7,
		FullText: `{"input":[
			{"role":"user","content":"ordinary previous user"},
			{"role":"assistant","content":"ordinary previous answer"},
			{"type":"function_call_output","call_id":"call_1","output":"tool-only trigger"}
		]}`,
	}, "responses_api")

	handler := &Handler{db: db}
	result, err := handler.BackfillLegacyRelayCYBMissSamples(ctx, 10)
	if err != nil {
		t.Fatalf("BackfillLegacyRelayCYBMissSamples: %v", err)
	}
	if result.Scanned != 7 || result.Queued != 4 || result.Rejected != 3 {
		t.Fatalf("result = %+v", result)
	}

	recovered, err := db.GetRelayCYBMissSample(ctx, "recoverable")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(recoverable): %v", err)
	}
	if recovered.LearningStatus != database.RelayCYBLearningStatusRejected ||
		recovered.LearningError == "" ||
		!strings.Contains(recovered.UserText, "current dangerous user intent") ||
		!strings.Contains(recovered.UserText, "with suffix") ||
		!strings.Contains(recovered.UserText, "older dangerous user intent") {
		t.Fatalf("recovered sample = %+v", recovered)
	}
	if strings.ContainsRune(recovered.UserText, '\x00') {
		t.Fatalf("NUL was persisted in learning text: %q", recovered.UserText)
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
	relayEligible, err := db.GetRelayCYBMissSample(ctx, "relay-eligible")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(relay-eligible): %v", err)
	}
	if relayEligible.SampleSource != database.RelayCYBMissSourceRelay ||
		!strings.Contains(relayEligible.UserText, "actual Relay CYB") {
		t.Fatalf("relay eligible sample = %+v", relayEligible)
	}
	continuation, err := db.GetRelayCYBMissSample(ctx, "relay-continuation")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(relay continuation): %v", err)
	}
	if continuation.SampleSource != database.RelayCYBMissSourceRelay ||
		!strings.Contains(continuation.UserText, "new current user") {
		t.Fatalf("relay continuation sample = %+v", continuation)
	}
	if _, err := db.GetRelayCYBMissSample(ctx, "relay-old-group"); err == nil {
		t.Fatal("historical Relay request from another configured group entered learning")
	}
	overflowEligible, err := db.GetRelayCYBMissSample(ctx, "overflow-relay-eligible")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(overflow): %v", err)
	}
	if overflowEligible.SampleSource != database.RelayCYBMissSourceOAuth ||
		overflowEligible.AccountID != 52 {
		t.Fatalf("overflow sample did not preserve the earlier OAuth miss: %+v", overflowEligible)
	}
	overflowRelayOnly, err := db.GetRelayCYBMissSample(ctx, "overflow-relay-only")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(overflow Relay only): %v", err)
	}
	if overflowRelayOnly.SampleSource != database.RelayCYBMissSourceRelay ||
		overflowRelayOnly.AccountID != 51 {
		t.Fatalf("overflow Relay-only sample = %+v", overflowRelayOnly)
	}
	toolOnly, err := db.GetRelayCYBMissSample(ctx, "relay-tool-only")
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(tool-only): %v", err)
	}
	if toolOnly.LearningStatus != database.RelayCYBLearningStatusRejected ||
		toolOnly.UserText != "" ||
		!strings.Contains(toolOnly.LearningError, "当前用户语料") {
		t.Fatalf("tool-only historical sample = %+v", toolOnly)
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

func TestRelayCYBMissBackfillCandidateKeysetDoesNotRescanOldPrefix(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "cyb-backfill-keyset.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
	ctx := context.Background()
	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, requestID := range []string{"keyset-a", "keyset-b", "keyset-c"} {
		writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
			RequestID: requestID,
			CreatedAt: createdAt,
			Endpoint:  "/v1/responses",
			FullText:  `{"input":"historical OAuth CYB sample"}`,
		}, "oauth")
	}

	first, err := db.ListRelayCYBMissBackfillCandidatesAfter(
		ctx,
		0,
		createdAt.Add(time.Minute),
		time.Time{},
		"",
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].RequestID != "keyset-a" {
		t.Fatalf("first keyset page = %+v", first)
	}
	second, err := db.ListRelayCYBMissBackfillCandidatesAfter(
		ctx,
		0,
		createdAt.Add(time.Minute),
		first[0].CreatedAt,
		first[0].RequestID,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].RequestID != "keyset-b" {
		t.Fatalf("second keyset page = %+v", second)
	}
}

func TestBackfillLegacyRelayCYBMissSamplesRespectsStartupCutoff(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "7")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "cyb-backfill-cutoff.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
	ctx := context.Background()
	cutoff := time.Now().UTC().Truncate(time.Second)
	requestID := "live-long-cyb-after-startup-cutoff"
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID:     requestID,
		CreatedAt:     cutoff.Add(time.Second),
		Endpoint:      "/v1/responses",
		FullText:      `{"input":"truncated live request prefix`,
		ScanTruncated: true,
	}, "oauth")

	handler := &Handler{db: db}
	result, err := handler.BackfillLegacyRelayCYBMissSamplesBefore(ctx, 10, cutoff)
	if err != nil {
		t.Fatalf("BackfillLegacyRelayCYBMissSamplesBefore: %v", err)
	}
	if result.Scanned != 0 || result.Queued != 0 || result.Rejected != 0 {
		t.Fatalf("post-cutoff live request was backfilled: %+v", result)
	}
	if _, err := db.GetRelayCYBMissSample(ctx, requestID); err == nil {
		t.Fatal("post-cutoff live request was claimed before its live sample writer")
	}

	if err := db.WriteRelayCYBMissSample(ctx, &database.RelayCYBMissSampleInput{
		RequestID:         requestID,
		CreatedAt:         cutoff.Add(2 * time.Second),
		SampleSource:      database.RelayCYBMissSourceOAuth,
		UserText:          "actual long current-user tail from the live request",
		UserTextTruncated: true,
		RequestTruncated:  true,
		ContentHash:       "live-long-cyb-after-startup-cutoff-hash",
	}); err != nil {
		t.Fatalf("live sample writer: %v", err)
	}
	sample, err := db.GetRelayCYBMissSample(ctx, requestID)
	if err != nil {
		t.Fatalf("GetRelayCYBMissSample(live): %v", err)
	}
	if sample.LearningStatus != database.RelayCYBLearningStatusQueued ||
		!strings.Contains(sample.UserText, "actual long current-user tail") {
		t.Fatalf("live sample was not preserved for learning: %+v", sample)
	}
}

func TestBackfillLegacyRelayCYBMissSamplesFinalTickIncludesCutoffEquality(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "cyb-backfill-cutoff-equality.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
	ctx := context.Background()
	startupCutoff := time.Now().UTC().Truncate(time.Second)
	requestID := "historical-cyb-equal-to-startup-cutoff"
	writeLegacyCYBAuditCase(t, db, database.RelayAuditRequestInput{
		RequestID: requestID,
		CreatedAt: startupCutoff,
		Endpoint:  "/v1/responses",
		FullText:  `{"input":"historical request on the startup cutoff tick"}`,
	}, "oauth")

	handler := &Handler{db: db}
	strict, err := handler.BackfillLegacyRelayCYBMissSamplesBefore(
		ctx,
		10,
		startupCutoff,
	)
	if err != nil {
		t.Fatal(err)
	}
	if strict.Scanned != 0 {
		t.Fatalf("strict startup cutoff included equality: %+v", strict)
	}
	final, err := handler.BackfillLegacyRelayCYBMissSamplesBefore(
		ctx,
		10,
		startupCutoff.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if final.Scanned != 1 || final.Queued != 1 {
		t.Fatalf("final storage tick did not include cutoff equality: %+v", final)
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
