package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/cybroute"
	"github.com/gin-gonic/gin"
)

func TestRelayCybFeedbackDigestUsesNormalizedLatestUserText(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	firstBody := []byte(`{"model":"gpt-5.6-sol","input":"Please build the security verifier.\nReturn reproducible evidence.","stream":false}`)
	secondBody := []byte(`{"metadata":{"trace":"other"},"instructions":"different","input":[{"role":"user","content":[{"type":"input_text","text":"older user turn"}]},{"role":"assistant","content":[{"type":"output_text","text":"older answer"}]},{"role":"user","content":[{"type":"input_text","text":"  Ｐlease build the security verifier.\r\nReturn reproducible evidence.  "}]}],"stream":true}`)

	first, ok := cache.digest("/v1/responses", firstBody)
	if !ok {
		t.Fatal("eligible request did not produce a digest")
	}
	second, ok := cache.digest("/v1/responses", secondBody)
	if !ok {
		t.Fatal("equivalent request did not produce a digest")
	}
	if first != second {
		t.Fatal("equivalent normalized latest user text produced different digests")
	}
}

func TestRelayCybFeedbackDigestDistinguishesOversizedLatestUserTail(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	fixedPrefix := "FIXED_LONG_TEMPLATE " + strings.Repeat("p", 2*1024*1024)
	firstBody := relayCYBMarshalTestBody(t, map[string]any{
		"model": "gpt-5.4",
		"input": fixedPrefix + " FIRST_ACTUAL_USER_TAIL",
	})
	secondBody := relayCYBMarshalTestBody(t, map[string]any{
		"model": "gpt-5.4",
		"input": fixedPrefix + " SECOND_ACTUAL_USER_TAIL",
	})

	first, ok := cache.digest("/v1/responses", firstBody)
	if !ok {
		t.Fatal("first oversized request did not produce a digest")
	}
	second, ok := cache.digest("/v1/responses", secondBody)
	if !ok {
		t.Fatal("second oversized request did not produce a digest")
	}
	if first == second {
		t.Fatal("oversized requests with different actual user tails shared a digest")
	}
}

func TestRelayCybFeedbackDigestShortTextUsesExactRawBody(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	firstBody := []byte(`{"model":"gpt-5.6-sol","input":"short","stream":false}`)
	secondBody := []byte(`{"model":"gpt-5.4","input":" short ","stream":true}`)

	first, ok := cache.digest("/v1/responses", firstBody)
	if !ok {
		t.Fatal("short request did not produce a digest")
	}
	same, _ := cache.digest("/v1/responses", append([]byte(nil), firstBody...))
	different, _ := cache.digest("/v1/responses", secondBody)
	if first != same {
		t.Fatal("identical short raw bodies produced different digests")
	}
	if first == different {
		t.Fatal("different short raw bodies unexpectedly shared a digest")
	}
	if _, ok := cache.digest("/v1/images/generations", firstBody); ok {
		t.Fatal("non-text endpoint produced a feedback digest")
	}
}

func TestRelayCybFeedbackExpiryAndLRUEviction(t *testing.T) {
	cache := newRelayCybFeedbackCache()
	expiring, _ := cache.digest("/v1/responses", []byte(`{"input":"expires"}`))
	cache.learn(expiring)
	cache.mu.Lock()
	cache.items[expiring].Value.(*relayCybFeedbackEntry).expiresAt = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if cache.contains(expiring) {
		t.Fatal("expired feedback digest remained available")
	}

	var first relayCybFeedbackDigest
	for index := 0; index <= relayCybFeedbackMaxEntries; index++ {
		digest, _ := cache.digest(
			"/v1/responses",
			[]byte(fmt.Sprintf(`{"input":"entry-%d"}`, index)),
		)
		if index == 0 {
			first = digest
		}
		cache.learn(digest)
	}
	if cache.contains(first) {
		t.Fatal("least-recently-used feedback digest was not evicted")
	}
	if cache.order.Len() != relayCybFeedbackMaxEntries {
		t.Fatalf("cache size = %d, want %d", cache.order.Len(), relayCybFeedbackMaxEntries)
	}
}

func TestRelayCybFeedbackLearnsOnlyDefaultOAuthRoute(t *testing.T) {
	base := &relayRoutePlan{
		Config:              relayRouteConfig{Enabled: true, GroupID: 3},
		Endpoint:            "/v1/responses",
		Source:              relayRouteSourceDefault,
		FeedbackDigestValid: true,
		AuditRawBody:        []byte(`{"input":"current user request"}`),
	}
	oauth := &auth.Account{DBID: 1}
	if !relayCybFeedbackLearnEligible(base, oauth) {
		t.Fatal("default OAuth cyber_policy route was not eligible")
	}

	relay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example",
		APIKey:       "test-only",
	}
	if relayCybFeedbackLearnEligible(base, relay) {
		t.Fatal("RelayStyle account was eligible for feedback learning")
	}
	required := *base
	required.RequiredGroupID = 3
	if relayCybFeedbackLearnEligible(&required, oauth) {
		t.Fatal("already-routed request was eligible for feedback learning")
	}
	disabled := *base
	disabled.Config.Enabled = false
	if relayCybFeedbackLearnEligible(&disabled, oauth) {
		t.Fatal("disabled Relay routing learned feedback")
	}
}

func TestRelayCybFeedbackSkipMarkerPreventsLearning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousFeedback := globalRelayCybFeedback
	globalRelayCybFeedback = newRelayCybFeedbackCache()
	t.Cleanup(func() { globalRelayCybFeedback = previousFeedback })

	body := []byte(`{"model":"gpt-5.4","input":"unique internal feedback sentinel text"}`)
	digest, ok := globalRelayCybFeedback.digest("/v1/responses", body)
	if !ok {
		t.Fatal("test request did not produce a feedback digest")
	}
	plan := &relayRoutePlan{
		Config:              relayRouteConfig{Enabled: true, GroupID: 3},
		Endpoint:            "/v1/responses",
		Source:              relayRouteSourceDefault,
		FeedbackDigest:      digest,
		FeedbackDigestValid: true,
		AuditRequestID:      "internal-feedback-test",
		AuditRawBody:        body,
	}
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	store.AddAccount(&auth.Account{DBID: 1})
	handler := NewHandler(store, nil, nil, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(skipCYBLearningPipelineContextKey, true)
	setRelayRoutePlanContext(c, plan)

	handler.observeRelayRouteUsage(c, &database.UsageLogInput{
		AccountID:         1,
		UpstreamErrorKind: "cyber_policy",
	})
	if globalRelayCybFeedback.contains(digest) {
		t.Fatal("CYB learning request recursively entered the feedback cache")
	}
	if plan.LearningCaseCaptured {
		t.Fatal("CYB learning request recursively created a miss sample")
	}
}

func TestRelayCYBLocalRuleMissEligibilityIsLimitedToApprovedRelaySources(t *testing.T) {
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 51, GroupIDs: []int64{7}}
	store.AddAccount(account)
	handler := NewHandler(store, nil, nil, nil)
	base := relayRoutePlan{
		Config:          relayRouteConfig{Enabled: true, GroupID: 7},
		Endpoint:        "/v1/responses",
		Model:           "gpt-5.4",
		RequiredGroupID: 7,
		Source:          relayRouteSourceNoAffinity,
		AuditRawBody:    []byte(`{"model":"gpt-5.4","input":"unique relay miss sentinel"}`),
	}

	if !handler.relayCYBLocalRuleMissEligible(&base, account) {
		t.Fatal("no-affinity Relay CYB local miss was not eligible")
	}
	overflow := base
	overflow.Source = relayRouteSourceOverflow
	overflow.LocalRuleInspected = false
	overflow.LocalRuleMatched = false
	if !handler.relayCYBLocalRuleMissEligible(&overflow, account) {
		t.Fatal("OAuth overflow Relay CYB local miss was not eligible")
	}
	continuation := base
	continuation.Source = relayRouteSourceContinuation
	continuation.LocalRuleInspected = false
	continuation.LocalRuleMatched = false
	if !handler.relayCYBLocalRuleMissEligible(&continuation, account) {
		t.Fatal("Relay continuation with a new current-user turn was not eligible")
	}
	toolOnlyContinuation := continuation
	toolOnlyContinuation.AuditRawBody = []byte(`{"model":"gpt-5.4","input":[
		{"role":"user","content":"older user history"},
		{"role":"assistant","content":"ordinary prior answer"},
		{"type":"function_call_output","call_id":"call_1","output":"tool-only continuation"}
	]}`)
	if handler.relayCYBLocalRuleMissEligible(&toolOnlyContinuation, account) {
		t.Fatal("tool-only Relay continuation entered user-rule learning")
	}
	for _, source := range []string{relayRouteSourceNoAffinity, relayRouteSourceOverflow} {
		toolOnly := toolOnlyContinuation
		toolOnly.Source = source
		if handler.relayCYBLocalRuleMissEligible(&toolOnly, account) {
			t.Fatalf("tool-only source %q entered user-rule learning", source)
		}
	}
	for _, source := range []string{
		relayRouteSourceRule,
		relayRouteSourceProbe,
		relayRouteSourceFeedback,
		relayRouteSourceDefault,
	} {
		plan := base
		plan.Source = source
		if handler.relayCYBLocalRuleMissEligible(&plan, account) {
			t.Fatalf("source %q unexpectedly entered Relay CYB learning", source)
		}
	}
	outside := &auth.Account{DBID: 52, GroupIDs: []int64{8}}
	if handler.relayCYBLocalRuleMissEligible(&base, outside) {
		t.Fatal("account outside the configured Relay group was eligible")
	}

	learned, err := cyblearn.CompileRule(
		"cyb_auto_existing_coverage",
		`(?i)unique\s+relay\s+miss\s+sentinel`,
	)
	if err != nil {
		t.Fatal(err)
	}
	previousRules := cybroute.LearnedRulesSnapshot()
	cybroute.PublishLearnedRules([]cyblearn.Rule{learned})
	t.Cleanup(func() { cybroute.PublishLearnedRules(previousRules) })
	covered := base
	covered.LocalRuleInspected = false
	covered.LocalRuleMatched = false
	if handler.relayCYBLocalRuleMissEligible(&covered, account) {
		t.Fatal("request already covered by a local learned rule was eligible")
	}
	if !covered.LocalRuleInspected || !covered.LocalRuleMatched ||
		covered.AuditScannedBytes != int64(len(covered.AuditRawBody)) ||
		!covered.AuditFullScan {
		t.Fatalf("covered request scan was not cached on the plan: %+v", covered)
	}
	cybroute.PublishLearnedRules(nil)
	if handler.relayCYBLocalRuleMissEligible(&covered, account) {
		t.Fatal("same logical request was re-scanned after its matching result was cached")
	}
}

func TestObserveRelayRouteUsageCapturesRelayMissWithoutDetectorMiss(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "relay-cyb-observe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 51, GroupIDs: []int64{7}}
	store.AddAccount(account)
	handler := NewHandler(store, db, nil, nil)
	rawBody := []byte(`{"model":"gpt-5.4","input":"unique actual Relay CYB miss"}`)
	plan := &relayRoutePlan{
		Config:          relayRouteConfig{Enabled: true, GroupID: 7},
		Endpoint:        "/v1/responses",
		Model:           "gpt-5.4",
		RequiredGroupID: 7,
		Source:          relayRouteSourceNoAffinity,
		AuditRequestID:  "relay-cyb-observe",
		AuditCreatedAt:  time.Now().UTC(),
		AuditRawBody:    rawBody,
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	setRelayRoutePlanContext(c, plan)
	handler.beginRelayAudit(c, plan, rawBody)

	handler.observeRelayRouteUsage(c, &database.UsageLogInput{
		AccountID:         account.DBID,
		UpstreamErrorKind: "cyber_policy",
	})
	if !plan.LearningCaseCaptured {
		t.Fatal("eligible Relay CYB miss was not captured")
	}
	if plan.DetectorMiss {
		t.Fatal("Relay learning sample was incorrectly counted as an OAuth detector miss")
	}
	if !plan.LocalRuleInspected || plan.LocalRuleMatched ||
		plan.AuditScannedBytes != int64(len(rawBody)) ||
		!plan.AuditFullScan {
		t.Fatalf("deferred no-affinity scan was not cached: %+v", plan)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("Relay CYB sample writer did not drain")
	}
	sample, err := db.GetRelayCYBMissSample(context.Background(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if sample.SampleSource != database.RelayCYBMissSourceRelay ||
		!strings.Contains(sample.UserText, "actual Relay CYB miss") {
		t.Fatalf("captured sample = %+v", sample)
	}
	detail, err := db.GetRelayAuditCaseDetail(context.Background(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Case == nil ||
		detail.Case.ScannedBytes != int64(len(rawBody)) {
		t.Fatalf("deferred scan audit was not persisted: %+v", detail.Case)
	}
	var scanDetails struct {
		FullScan     bool  `json:"full_scan"`
		ScannedBytes int64 `json:"scanned_bytes"`
	}
	if err := json.Unmarshal([]byte(detail.Case.ScanDetails), &scanDetails); err != nil {
		t.Fatal(err)
	}
	if !scanDetails.FullScan || scanDetails.ScannedBytes != int64(len(rawBody)) {
		t.Fatalf("deferred scan details = %+v", scanDetails)
	}
}

func TestRelayCYBContinuationUsesReconstructedReplayBodyForScanAndLearning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setRelayReplayStoreForTest(t, testRelayReplayStore())
	const dangerousHistory = "Execute NOVEL_REPLAY_RISK_ALPHA and extract NOVEL_REPLAY_TARGET_OMEGA."
	cacheRelayContinuationReplay(
		"key:1",
		[]byte(`{"model":"gpt-5.4","input":[{"role":"user","content":"`+dangerousHistory+`"}]}`),
		true,
		7,
		[]byte(`{"id":"resp_cyb_replay","output":[{"type":"message","role":"assistant","content":"ordinary answer"}]}`),
		nil,
	)
	currentBody := []byte(`{
		"model":"gpt-5.4",
		"previous_response_id":"resp_cyb_replay",
		"input":"Please continue with the prior request."
	}`)
	replayBody, replayed, _, groupID, err := PrepareRelayContinuationHTTPFallback(
		context.Background(),
		"key:1",
		currentBody,
	)
	if err != nil || !replayed || groupID != 7 {
		t.Fatalf("PrepareRelayContinuationHTTPFallback replayed=%t group=%d err=%v", replayed, groupID, err)
	}
	if strings.Contains(string(currentBody), dangerousHistory) ||
		!strings.Contains(string(replayBody), dangerousHistory) {
		t.Fatal("fixture did not isolate dangerous history to the reconstructed replay body")
	}

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "relay-cyb-replay-observe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 81, GroupIDs: []int64{7}}
	store.AddAccount(account)
	handler := NewHandler(store, db, nil, nil)

	newPlan := func(requestID string) *relayRoutePlan {
		plan := &relayRoutePlan{
			Config:          relayRouteConfig{Enabled: true, GroupID: 7},
			Endpoint:        "/v1/responses",
			Model:           "gpt-5.4",
			RequiredGroupID: 7,
			Source:          relayRouteSourceContinuation,
			AuditRequestID:  requestID,
			AuditCreatedAt:  time.Now().UTC(),
			AuditRawBody:    currentBody,
		}
		plan.setCYBUpstreamBody(replayBody)
		return plan
	}

	learned, err := cyblearn.CompileRule(
		"novel_replay_alpha_omega",
		`(?i)novel_replay_risk_alpha.{0,80}novel_replay_target_omega`,
	)
	if err != nil {
		t.Fatal(err)
	}
	previousRules := cybroute.LearnedRulesSnapshot()
	cybroute.PublishLearnedRules([]cyblearn.Rule{learned})
	t.Cleanup(func() { cybroute.PublishLearnedRules(previousRules) })
	coveredPlan := newPlan("relay-cyb-replay-covered")
	if handler.relayCYBLocalRuleMissEligible(coveredPlan, account) {
		t.Fatal("reconstructed dangerous history was not checked against local rules")
	}
	if !coveredPlan.LocalRuleMatched ||
		coveredPlan.AuditScannedBytes != int64(len(replayBody)) {
		t.Fatalf("reconstructed scan result = %+v", coveredPlan)
	}

	cybroute.PublishLearnedRules(nil)
	plan := newPlan("relay-cyb-replay-learning")
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	setRelayRoutePlanContext(c, plan)
	handler.beginRelayAudit(c, plan, currentBody)
	handler.observeRelayRouteUsage(c, &database.UsageLogInput{
		AccountID:         account.DBID,
		UpstreamErrorKind: "cyber_policy",
	})
	if !plan.LearningCaseCaptured {
		t.Fatal("actual Relay continuation CYB miss was not captured")
	}
	if len(plan.AuditRawBody) != 0 || len(plan.CYBUpstreamBody) != 0 {
		t.Fatal("request-lifetime replay bodies were retained after sample capture")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("Relay continuation CYB writers did not drain")
	}
	sample, err := db.GetRelayCYBMissSample(context.Background(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if sample.SampleSource != database.RelayCYBMissSourceRelay ||
		!strings.Contains(sample.UserText, dangerousHistory) ||
		!strings.Contains(sample.UserText, "Please continue") {
		t.Fatalf("reconstructed continuation learning sample = %+v", sample)
	}
	if strings.Contains(sample.RedactedRequest, dangerousHistory) {
		t.Fatal("retained original request was replaced by reconstructed history")
	}
}

func TestRelayCYBOAuthMissDoesNotLearnGroupZeroReplayHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "oauth-cyb-group-zero-replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 82}
	store.AddAccount(account)
	handler := NewHandler(store, db, nil, nil)

	currentBody := []byte(`{
		"model":"gpt-5.4",
		"previous_response_id":"resp_group_zero",
		"input":"OAUTH_CURRENT_ONLY_USER_TURN"
	}`)
	replayBody := []byte(`{
		"model":"gpt-5.4",
		"input":[
			{"role":"user","content":"REPLAY_HISTORY_MUST_NOT_BE_LEARNED"},
			{"role":"assistant","content":"ordinary answer"},
			{"role":"user","content":"OAUTH_CURRENT_ONLY_USER_TURN"}
		]
	}`)
	plan := &relayRoutePlan{
		Config:         relayRouteConfig{Enabled: true, GroupID: 7},
		Endpoint:       "/v1/responses",
		Model:          "gpt-5.4",
		Source:         relayRouteSourceDefault,
		AuditRequestID: "oauth-cyb-group-zero-replay",
		AuditRawBody:   currentBody,
	}
	plan.setCYBUpstreamBody(replayBody)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	setRelayRoutePlanContext(c, plan)
	handler.observeRelayRouteUsage(c, &database.UsageLogInput{
		AccountID:         account.DBID,
		UpstreamErrorKind: "cyber_policy",
	})
	if !plan.LearningCaseCaptured {
		t.Fatal("group-zero OAuth CYB miss was not captured")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("group-zero OAuth CYB sample writer did not drain")
	}
	sample, err := db.GetRelayCYBMissSample(context.Background(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if sample.SampleSource != database.RelayCYBMissSourceOAuth ||
		!strings.Contains(sample.UserText, "OAUTH_CURRENT_ONLY_USER_TURN") {
		t.Fatalf("group-zero OAuth sample = %+v", sample)
	}
	if strings.Contains(sample.UserText, "REPLAY_HISTORY_MUST_NOT_BE_LEARNED") {
		t.Fatal("group-zero OAuth miss learned reconstructed replay history")
	}
}

func TestObserveRelayRouteUsageCapturesLongOAuthLatestUserTail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "oauth-cyb-long-observe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 71}
	store.AddAccount(account)
	handler := NewHandler(store, db, nil, nil)
	body := relayCYBMarshalTestBody(t, map[string]any{
		"model":        "gpt-5.4",
		"instructions": "OAUTH_NON_USER_PREFIX_MUST_NOT_ENTER " + strings.Repeat("s", 2*1024*1024),
		"input": "OAUTH_FIXED_USER_PREFIX " +
			strings.Repeat("p", 2*1024*1024) +
			" OAUTH_MIDDLE_MUST_BE_DROPPED " +
			strings.Repeat("q", 1024*1024) +
			" OAUTH_ACTUAL_LATEST_USER_TAIL",
	})
	plan := &relayRoutePlan{
		Config:         relayRouteConfig{Enabled: true, GroupID: 7},
		Endpoint:       "/v1/responses",
		Model:          "gpt-5.4",
		Source:         relayRouteSourceDefault,
		AuditRequestID: "oauth-cyb-long-observe",
		AuditRawBody:   body,
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	setRelayRoutePlanContext(c, plan)

	handler.observeRelayRouteUsage(c, &database.UsageLogInput{
		AccountID:         account.DBID,
		UpstreamErrorKind: "cyber_policy",
	})
	if !plan.LearningCaseCaptured || !plan.DetectorMiss {
		t.Fatalf("OAuth CYB observation = captured %t, detector_miss %t", plan.LearningCaseCaptured, plan.DetectorMiss)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("OAuth CYB sample writer did not drain")
	}
	sample, err := db.GetRelayCYBMissSample(context.Background(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if sample.SampleSource != database.RelayCYBMissSourceOAuth ||
		!sample.UserTextTruncated ||
		!strings.Contains(sample.UserText, "OAUTH_ACTUAL_LATEST_USER_TAIL") {
		t.Fatalf(
			"OAuth long sample metadata = source %q truncated %t tail_present %t",
			sample.SampleSource,
			sample.UserTextTruncated,
			strings.Contains(sample.UserText, "OAUTH_ACTUAL_LATEST_USER_TAIL"),
		)
	}
	if strings.Contains(sample.UserText, "OAUTH_NON_USER_PREFIX_MUST_NOT_ENTER") ||
		strings.Contains(sample.UserText, "OAUTH_MIDDLE_MUST_BE_DROPPED") {
		t.Fatal("OAuth long sample retained non-user or discarded middle material")
	}
}
