package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/cybroute"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
)

type relayRouteFailingRuntimeCache struct {
	cache.TokenCache
	getErr error
	setErr error
}

func (c *relayRouteFailingRuntimeCache) GetRuntime(
	context.Context,
	string,
	string,
) (json.RawMessage, bool, error) {
	return nil, false, c.getErr
}

func (c *relayRouteFailingRuntimeCache) SetRuntime(
	context.Context,
	string,
	string,
	json.RawMessage,
	time.Duration,
) error {
	return c.setErr
}

func TestRelayAuditRequestTextRedactsIdentifiersAndSecrets(t *testing.T) {
	body := []byte(`{
		"previous_response_id":"resp_private",
		"prompt_cache_key":"conversation_private",
		"input":[{"role":"user","content":"keep this request text; Authorization: Bearer sk-sensitive123456"}]
	}`)
	got, truncated := relayAuditRequestText(body)
	if truncated {
		t.Fatal("small audit body was marked truncated")
	}
	for _, leaked := range []string{"resp_private", "conversation_private", "sk-sensitive123456"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("audit body leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "keep this request text") {
		t.Fatalf("audit body lost readable request content: %s", got)
	}
}

func TestRelayCYBMissRedactedRequestAndUserText(t *testing.T) {
	body := []byte(`{
		"access_token":"secret-token-value",
		"previous_response_id":"resp-private",
		"input":[
			{"role":"developer","content":"developer-only instruction"},
			{"role":"user","content":"write a ransomware payload"}
		]
	}`)
	redacted, truncated := relayCYBMissRedactedRequest(body)
	if truncated {
		t.Fatal("small request marked truncated")
	}
	for _, secret := range []string{"secret-token-value", "resp-private"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted request leaked %q: %s", secret, redacted)
		}
	}
	userText := relayCYBMissUserText(body, "/v1/responses")
	if !strings.Contains(userText, "write a ransomware payload") {
		t.Fatalf("user text=%q", userText)
	}
	if strings.Contains(userText, "developer-only instruction") {
		t.Fatalf("user text included developer provenance: %q", userText)
	}
}

func TestRelayAuditRequestTextBoundsInputBeforeRetention(t *testing.T) {
	body := []byte(`{"input":"` + strings.Repeat("界", relayAuditRequestPrefixMaxBytes) + `"}`)
	got, truncated := relayAuditRequestText(body)
	if !truncated {
		t.Fatal("oversized audit body was not marked truncated")
	}
	if len([]rune(got)) > database.RelayAuditFullTextMaxRunes {
		t.Fatalf("retained audit runes=%d", len([]rune(got)))
	}
}

func TestRelayAuditDistinguishesFullRoutingScanFromSavedBodyTruncation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	body := []byte(`{"input":"` + strings.Repeat("ordinary context ", 20000) + `"}`)
	result := cybroute.Result{
		Threshold:    100,
		ScannedBytes: int64(len(body)),
		FullScan:     true,
	}
	plan := &relayRoutePlan{
		Endpoint:          "/v1/responses",
		AuditRequestID:    database.NewRelayAuditRequestID(),
		AuditCreatedAt:    time.Now().UTC(),
		AuditScannedBytes: result.ScannedBytes,
		AuditFullScan:     result.FullScan,
		AuditScanDetails:  relayRouteScanDetailsJSON(result),
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{db: db}
	handler.beginRelayAudit(c, plan, body)
	if !db.WaitRelayAuditIdle(t.Context()) {
		t.Fatal("relay audit queue did not become idle")
	}

	detail, err := db.GetRelayAuditCaseDetail(t.Context(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Case == nil {
		t.Fatal("relay audit detail did not include a case")
	}
	if detail.Case.ScannedBytes != int64(len(body)) {
		t.Fatalf("scanned_bytes = %d, want %d", detail.Case.ScannedBytes, len(body))
	}
	if !detail.Case.ScanTruncated {
		t.Fatal("fixture should still report the separately bounded saved audit body")
	}
	var scanDetails struct {
		FullScan     bool  `json:"full_scan"`
		ScannedBytes int64 `json:"scanned_bytes"`
	}
	if err := json.Unmarshal([]byte(detail.Case.ScanDetails), &scanDetails); err != nil {
		t.Fatal(err)
	}
	if !scanDetails.FullScan || scanDetails.ScannedBytes != int64(len(body)) {
		t.Fatalf("scan details = %+v", scanDetails)
	}
}

func TestRelayAuditDoesNotReportUnperformedNoAffinityScan(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	body := []byte(`{"model":"gpt-5.4","input":"ordinary no-affinity request"}`)
	plan := &relayRoutePlan{
		Endpoint:       "/v1/responses",
		Source:         relayRouteSourceNoAffinity,
		AuditRequestID: database.NewRelayAuditRequestID(),
		AuditCreatedAt: time.Now().UTC(),
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{db: db}
	handler.beginRelayAudit(c, plan, body)
	if !db.WaitRelayAuditIdle(t.Context()) {
		t.Fatal("relay audit queue did not become idle")
	}

	detail, err := db.GetRelayAuditCaseDetail(t.Context(), plan.AuditRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Case == nil {
		t.Fatal("relay audit detail did not include a case")
	}
	if detail.Case.ScannedBytes != 0 {
		t.Fatalf("unperformed no-affinity scan reported %d bytes", detail.Case.ScannedBytes)
	}
	var scanDetails struct {
		FullScan     bool  `json:"full_scan"`
		ScannedBytes int64 `json:"scanned_bytes"`
	}
	if err := json.Unmarshal([]byte(detail.Case.ScanDetails), &scanDetails); err != nil {
		t.Fatal(err)
	}
	if scanDetails.FullScan || scanDetails.ScannedBytes != 0 {
		t.Fatalf("unperformed scan details = %+v", scanDetails)
	}
}

func TestRelayAuditRequestTextRedactsSensitiveValueAcrossPrefixBoundary(t *testing.T) {
	body := []byte(`{"input":"keep visible","encrypted_content":"` +
		strings.Repeat("opaque-private-fragment-", relayAuditRequestPrefixMaxBytes) +
		`"}`)
	got, truncated := relayAuditRequestText(body)
	if !truncated {
		t.Fatal("oversized sensitive field was not marked truncated")
	}
	if strings.Contains(got, "opaque-private-fragment") {
		t.Fatalf("audit body retained a truncated sensitive field: %s", got)
	}
	if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("audit body lost readable content or marker: %s", got)
	}
}

func TestRelayAuditRequestTextRedactsTruncatedPrivateKeyAndCredentialFields(t *testing.T) {
	t.Run("pem_without_footer", func(t *testing.T) {
		const secret = "audit-pem-secret-"
		body := []byte(`{"input":"keep visible\n-----BEGIN PRIVATE KEY-----\n` +
			strings.Repeat(secret, relayAuditRequestPrefixMaxBytes/len(secret)+32) +
			`"}`)
		got, truncated := relayAuditRequestText(body)
		if !truncated {
			t.Fatal("oversized PEM body was not marked truncated")
		}
		if strings.Contains(got, "audit-pem-secret") {
			t.Fatal("audit body retained a PEM fragment after prefix truncation")
		}
		if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
			t.Fatalf("audit body lost readable content or PEM marker: %q", got)
		}
	})

	for _, field := range []string{"private_key", "credential", "credentials"} {
		t.Run(field, func(t *testing.T) {
			secret := field + "-secret-fragment-"
			body := []byte(`{"input":"keep visible","` + field + `":"` +
				strings.Repeat(secret, relayAuditRequestPrefixMaxBytes/len(secret)+32) +
				`"}`)
			got, truncated := relayAuditRequestText(body)
			if !truncated {
				t.Fatal("oversized credential body was not marked truncated")
			}
			if strings.Contains(got, secret) {
				t.Fatalf("audit body retained truncated %s data", field)
			}
			if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED]") {
				t.Fatalf("audit body lost readable content or marker: %q", got)
			}
		})
	}
}

func TestRelayCYBMissTextRedactsTruncatedPrivateKeyAndCredential(t *testing.T) {
	t.Run("raw_request_pem_without_footer", func(t *testing.T) {
		const secret = "sample-pem-secret-"
		body := []byte(`{"input":"keep visible\n-----BEGIN PRIVATE KEY-----\n` +
			strings.Repeat(secret, relayCYBMissRawMaxBytes/len(secret)+32) +
			`"}`)
		got, truncated := relayCYBMissRedactedRequest(body)
		if !truncated {
			t.Fatal("oversized learning sample was not marked truncated")
		}
		if strings.Contains(got, "sample-pem-secret") {
			t.Fatal("learning sample retained a PEM fragment after prefix truncation")
		}
		if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
			t.Fatalf("learning sample lost readable content or PEM marker: %q", got)
		}
	})

	t.Run("raw_request_credential_across_boundary", func(t *testing.T) {
		const secret = "sample-credential-secret-"
		body := []byte(`{"input":"keep visible","credential":"` +
			strings.Repeat(secret, relayCYBMissRawMaxBytes/len(secret)+32) +
			`"}`)
		got, truncated := relayCYBMissRedactedRequest(body)
		if !truncated {
			t.Fatal("oversized learning sample was not marked truncated")
		}
		if strings.Contains(got, secret) {
			t.Fatal("learning sample retained a truncated credential")
		}
		if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("learning sample lost readable content or marker: %q", got)
		}
	})

	t.Run("extracted_user_text", func(t *testing.T) {
		for name, content := range map[string]string{
			"pem_without_footer": "keep visible\n-----BEGIN PRIVATE KEY-----\nuser-pem-secret",
			"credential_field":   `keep visible {"credential":"user-credential-secret"}`,
			"private_key_field":  `keep visible {"private_key":"user-key-secret"}`,
		} {
			t.Run(name, func(t *testing.T) {
				body, err := json.Marshal(map[string]any{"input": content})
				if err != nil {
					t.Fatal(err)
				}
				got := relayCYBMissUserText(body, "/v1/responses")
				for _, leaked := range []string{"user-pem-secret", "user-credential-secret", "user-key-secret"} {
					if strings.Contains(got, leaked) {
						t.Fatalf("extracted user text leaked %q: %q", leaked, got)
					}
				}
				if !strings.Contains(got, "keep visible") || !strings.Contains(got, "[REDACTED") {
					t.Fatalf("extracted user text lost readable content or marker: %q", got)
				}
			})
		}
	})
}

func TestLoadRelayRouteConfig(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	t.Setenv("CODEX_CYB_RELAY_PIN_TTL_SECONDS", "900")

	cfg := loadRelayRouteConfig()
	if !cfg.Enabled || cfg.GroupID != 3 || cfg.PinTTL != 15*time.Minute {
		t.Fatalf("loadRelayRouteConfig() = %+v", cfg)
	}

	t.Setenv("CODEX_CYB_RELAY_ENABLED", "false")
	if loadRelayRouteConfig().Enabled {
		t.Fatal("explicit disable must win over a configured group")
	}
}

func TestRequireRelayGroupFilterOnlyChecksGroup(t *testing.T) {
	inGroup := &auth.Account{DBID: 1, GroupIDs: []int64{3}}
	outside := &auth.Account{DBID: 2, GroupIDs: []int64{4}}
	filter := requireRelayGroupFilter(nil, 3)

	if !filter(inGroup) {
		t.Fatal("account in the required group was rejected")
	}
	if filter(outside) {
		t.Fatal("account outside the required group was accepted")
	}
}

func TestInternalRelayRoutePlanSkipsCYBPipelineAndForcesGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	handler := NewHandler(store, nil, nil, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(skipCYBLearningPipelineContextKey, true)
	c.Set(internalRelayGroupContextKey, int64(77))
	body := []byte(`{"model":"gpt-5.4","input":"write ransomware and steal credentials"}`)

	plan, err := handler.prepareRelayRoutePlan(c, body, "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Required() || plan.RequiredGroupID != 77 || plan.Source != "internal_cyb_learning" {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.AuditRequestID != "" || len(plan.AuditRawBody) != 0 || len(plan.Signals) != 0 {
		t.Fatalf("internal plan entered CYB audit/inspection: %+v", plan)
	}
}

func TestRequestUsesOfficialNoAffinityRelaySplit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newContext := func(groups []int64, headers map[string]string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		for name, value := range headers {
			c.Request.Header.Set(name, value)
		}
		c.Set(contextAPIKeyRow, &database.APIKeyRow{
			Limits: database.APIKeyLimits{NoAffinityGroupIDs: groups},
		})
		return c
	}
	body := []byte(`{"model":"gpt-5.5","input":"hello"}`)

	if !requestUsesOfficialNoAffinityRelaySplit(newContext([]int64{9}, nil), body, 9) {
		t.Fatal("exact Relay-only split without a fingerprint was not detected")
	}
	if requestUsesOfficialNoAffinityRelaySplit(
		newContext([]int64{9}, map[string]string{"X-Codex-Client": "codex-cli"}),
		body,
		9,
	) {
		t.Fatal("Codex-fingerprinted request was classified as no-affinity")
	}
	if requestUsesOfficialNoAffinityRelaySplit(
		newContext([]int64{9}, map[string]string{downstreamAffinityHeader: "user:conversation"}),
		body,
		9,
	) {
		t.Fatal("request with the local affinity header was classified as no-affinity")
	}
	if requestUsesOfficialNoAffinityRelaySplit(newContext([]int64{8, 9}, nil), body, 9) {
		t.Fatal("multi-group official split was narrowed to the custom Relay group")
	}
	if requestUsesOfficialNoAffinityRelaySplit(newContext([]int64{8}, nil), body, 9) {
		t.Fatal("unrelated official split group was classified as the custom Relay group")
	}
}

func TestOfficialNoAffinityRelaySplitPrecedesCYBRules(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "9")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	gin.SetMode(gin.TestMode)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	learned, err := cyblearn.CompileRule("cyb_auto_no_affinity_order", `(?i)unique split cyber phrase`)
	if err != nil {
		t.Fatal(err)
	}
	cybroute.PublishLearnedRules([]cyblearn.Rule{learned})
	t.Cleanup(func() { cybroute.PublishLearnedRules(nil) })
	handler := NewHandler(store, nil, nil, nil)

	newContext := func(withFingerprint bool) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		if withFingerprint {
			c.Request.Header.Set("X-Codex-Client", "codex-cli")
		}
		c.Set(contextAPIKeyRow, &database.APIKeyRow{
			AllowedGroupIDs: []int64{7, 9},
			Limits: database.APIKeyLimits{
				NoAffinityGroupIDs: []int64{9},
			},
		})
		return c
	}
	body := []byte(`{"model":"gpt-5.5","input":"unique split cyber phrase"}`)

	noAffinityContext := newContext(false)
	noAffinityPlan, err := handler.prepareRelayRoutePlan(noAffinityContext, body, "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	if !noAffinityPlan.Required() || noAffinityPlan.RequiredGroupID != 9 ||
		noAffinityPlan.Source != relayRouteSourceNoAffinity ||
		!noAffinityPlan.SkipPinPersistence ||
		noAffinityPlan.Reason != "official_no_affinity_group" {
		t.Fatalf("no-affinity plan=%+v", noAffinityPlan)
	}
	if strings.Join(noAffinityPlan.Signals, ",") != "official_no_affinity_split" {
		t.Fatalf("no-affinity request entered CYB detection: %v", noAffinityPlan.Signals)
	}
	becameOverflow, err := handler.observeRelayRouteSelection(
		noAffinityContext,
		noAffinityPlan,
		&auth.Account{DBID: 11, GroupIDs: []int64{9}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if becameOverflow || noAffinityPlan.Source != relayRouteSourceNoAffinity {
		t.Fatalf("official split was reclassified as overflow: %+v", noAffinityPlan)
	}
	noAffinityFilter := applyAffinityGroupRouting(
		noAffinityContext,
		resolveRequestSessionIdentity(noAffinityContext.Request.Header, body),
		nil,
	)
	noAffinityFilter = noAffinityPlan.composeFilter(noAffinityFilter)
	if noAffinityFilter(&auth.Account{DBID: 12, GroupIDs: []int64{7}}) ||
		!noAffinityFilter(&auth.Account{DBID: 13, GroupIDs: []int64{9}}) {
		t.Fatal("official and custom no-affinity filters did not preserve the Relay-only candidate set")
	}

	fingerprintedContext := newContext(true)
	fingerprintedPlan, err := handler.prepareRelayRoutePlan(
		fingerprintedContext,
		body,
		"/v1/responses",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprintedPlan.Required() || fingerprintedPlan.RequiredGroupID != 9 ||
		fingerprintedPlan.Source != relayRouteSourceRule {
		t.Fatalf("fingerprinted CYB plan=%+v", fingerprintedPlan)
	}
	fingerprintedFilter := applyAffinityGroupRouting(
		fingerprintedContext,
		resolveRequestSessionIdentity(fingerprintedContext.Request.Header, body),
		nil,
	)
	fingerprintedFilter = fingerprintedPlan.composeFilter(fingerprintedFilter)
	if fingerprintedFilter(&auth.Account{DBID: 14, GroupIDs: []int64{7}}) ||
		!fingerprintedFilter(&auth.Account{DBID: 15, GroupIDs: []int64{9}}) {
		t.Fatal("allowed groups and the CYB Relay constraint produced the wrong candidate set")
	}
}

func TestRelayRouteUsesIndependentLearnedRuleSnapshot(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "9")
	t.Setenv("CODEX_CYB_RELAY_ENABLED", "true")
	gin.SetMode(gin.TestMode)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	learned, err := cyblearn.CompileRule("cyb_auto_example", `(?i)unique learned cyber phrase`)
	if err != nil {
		t.Fatal(err)
	}
	cybroute.PublishLearnedRules([]cyblearn.Rule{learned})
	t.Cleanup(func() { cybroute.PublishLearnedRules(nil) })
	handler := NewHandler(store, nil, nil, nil)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	body := []byte(`{"model":"gpt-5.4","input":"unique learned cyber phrase"}`)

	plan, err := handler.prepareRelayRoutePlan(c, body, "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Required() || plan.RequiredGroupID != 9 || plan.Source != relayRouteSourceRule {
		t.Fatalf("plan=%+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Signals, ","), "learned_rule:cyb_auto_example") {
		t.Fatalf("signals=%v", plan.Signals)
	}
}

func TestRelayRoutePinCandidatesSeparateTrustedAffinitiesOnSharedKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	makeContext := func(affinity string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		req.Header.Set(downstreamAffinityHeader, affinity)
		c.Request = req
		return c
	}

	a := relayRoutePinCandidates(makeContext("user-a:conversation-1"), []byte(`{"model":"gpt-5.5"}`), 9)
	b := relayRoutePinCandidates(makeContext("user-b:conversation-1"), []byte(`{"model":"gpt-5.5"}`), 9)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("candidate counts = %d/%d, want 1/1", len(a), len(b))
	}
	if a[0].Key == b[0].Key {
		t.Fatal("different trusted affinities sharing one API key produced the same pin key")
	}
}

func TestRelayRoutePinCandidatesTrustGatewayAffinityExclusively(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	req.Header.Set("Session-Id", "client-controlled-session")
	c.Request = req

	candidates := relayRoutePinCandidates(
		c,
		[]byte(`{"prompt_cache_key":"client-cache","previous_response_id":"resp_client"}`),
		9,
	)
	if len(candidates) != 1 || candidates[0].Kind != "trusted_affinity" {
		t.Fatalf("candidates = %+v, want only trusted_affinity", candidates)
	}
}

func TestRelayRoutePinCandidatesUseOfficialExplicitSessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set("Idempotency-Key", "request-123")
	c.Request = req

	candidates := relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 9)
	if len(candidates) != 1 || candidates[0].Kind != "explicit_session" {
		t.Fatalf("candidates = %+v, want Idempotency-Key explicit session", candidates)
	}
	want := relayRoutePinCacheKey(9, "explicit_session", ResolveExplicitSessionID(req.Header, nil))
	if candidates[0].Key != want {
		t.Fatalf("candidate key = %q, want %q", candidates[0].Key, want)
	}
}

func TestOrdinaryRequestWithoutStableScopeStaysOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("ordinary request returned an error: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.StateFallbackLogged {
		t.Fatalf("ordinary route plan = %+v", plan)
	}
}

func TestOrdinaryRequestWithPinMissStaysOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("ordinary pin miss returned an error: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.StateFallbackLogged {
		t.Fatalf("ordinary pin-miss plan = %+v", plan)
	}
}

func TestLegacyRelayRoutePinNamespaceIsIgnored(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	runtimeCache := cache.NewMemory(1)
	handler := &Handler{}
	handler.SetRuntimeCache(runtimeCache)

	candidates := relayRoutePinCandidates(c, nil, 11)
	if len(candidates) != 1 {
		t.Fatalf("pin candidates = %+v", candidates)
	}
	raw, err := json.Marshal(relayRoutePinValue{GroupID: 3, Source: relayRouteSourceRule})
	if err != nil {
		t.Fatalf("marshal legacy pin: %v", err)
	}
	if err := runtimeCache.SetRuntime(
		c.Request.Context(),
		"relay-group-pin-v1",
		candidates[0].Key,
		raw,
		time.Hour,
	); err != nil {
		t.Fatalf("set legacy pin: %v", err)
	}

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("ordinary request returned an error: %v", err)
	}
	if plan.Required() || plan.Source != relayRouteSourceDefault || plan.StateFallbackLogged {
		t.Fatalf("legacy pin affected the new namespace: %+v", plan)
	}
}

func TestProbeWithoutStableScopeRoutesRelayWithoutError(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"ping"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("probe without stable scope returned an error: %v", err)
	}
	if !plan.Required() || plan.RequiredGroupID != 3 || plan.Source != relayRouteSourceProbe {
		t.Fatalf("probe route plan = %+v", plan)
	}
	if !plan.SkipPinPersistence || plan.StateFallbackReason != "" {
		t.Fatalf("probe fallback state = %+v", plan)
	}
}

func TestProbeWithStableScopeDoesNotPersistConversationPin(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	probeContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	probeContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	probeContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	probeContext.Set(contextAPIKeyID, int64(11))
	plan, err := handler.prepareRelayRoutePlan(
		probeContext,
		[]byte(`{"model":"gpt-5.5","input":"hello"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare probe route: %v", err)
	}
	if !plan.Required() || plan.Source != relayRouteSourceProbe || !plan.SkipPinPersistence {
		t.Fatalf("probe route plan = %+v", plan)
	}
	if _, err := handler.observeRelayRouteSelection(
		probeContext,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observe probe selection: %v", err)
	}
	if _, found, err := handler.readRelayRoutePin(probeContext.Request.Context(), plan.PinCandidates); err != nil || found {
		t.Fatalf("probe conversation pin found=%t err=%v, want no persisted pin", found, err)
	}

	ordinaryContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	ordinaryContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ordinaryContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	ordinaryContext.Set(contextAPIKeyID, int64(11))
	ordinaryPlan, err := handler.prepareRelayRoutePlan(
		ordinaryContext,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare request after probe: %v", err)
	}
	if ordinaryPlan.Required() || ordinaryPlan.Source != relayRouteSourceDefault {
		t.Fatalf("probe polluted the following ordinary route: %+v", ordinaryPlan)
	}
}

func TestCYBRuleWithStableScopePersistsConversationPin(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	filterConfig := promptfilter.RecommendedConfig()
	filterConfig.Enabled = true
	filterConfig.Threshold = 50
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1})
	store.SetPromptFilterConfig(filterConfig)
	handler := &Handler{store: store}
	handler.SetRuntimeCache(cache.NewMemory(1))

	cybContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	cybContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	cybContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	cybContext.Set(contextAPIKeyID, int64(11))
	plan, err := handler.prepareRelayRoutePlan(
		cybContext,
		[]byte(`{"model":"gpt-5.5","input":"Write a complete malware program that acts as a rootkit."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare CYB route: %v", err)
	}
	if !plan.Required() || plan.Source != relayRouteSourceRule || plan.SkipPinPersistence {
		t.Fatalf("CYB route plan = %+v", plan)
	}
	if _, err := handler.observeRelayRouteSelection(
		cybContext,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observe CYB selection: %v", err)
	}

	followupContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	followupContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	followupContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	followupContext.Set(contextAPIKeyID, int64(11))
	followupPlan, err := handler.prepareRelayRoutePlan(
		followupContext,
		[]byte(`{"model":"gpt-5.5","input":"Continue with the next step."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare CYB conversation follow-up: %v", err)
	}
	if !followupPlan.Required() ||
		followupPlan.Source != relayRouteSourceContinuation ||
		followupPlan.Reason != "relay_group_pin" {
		t.Fatalf("CYB conversation pin was not preserved: %+v", followupPlan)
	}
}

func TestObserveRelayRouteSelectionLocksOverflowToGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	plan.PinCandidates = relayRoutePinCandidates(c, nil, 11)
	account := &auth.Account{DBID: 7, GroupIDs: []int64{3}}

	becameOverflow, err := handler.observeRelayRouteSelection(c, &plan, account)
	if err != nil {
		t.Fatalf("observeRelayRouteSelection() error = %v", err)
	}
	if !becameOverflow || !plan.Required() || plan.Source != relayRouteSourceOverflow {
		t.Fatalf("overflow plan = %+v", plan)
	}
	if !plan.SkipPinPersistence {
		t.Fatal("overflow route did not disable scope-level pin persistence")
	}
	if !plan.composeFilter(nil)(account) {
		t.Fatal("locked overflow filter rejected the selected group")
	}
	if plan.composeFilter(nil)(&auth.Account{DBID: 8, GroupIDs: []int64{4}}) {
		t.Fatal("locked overflow filter allowed a different group")
	}
}

func TestOverflowWithoutStableScopeKeepsRelaySelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("overflow without stable scope returned an error: %v", err)
	}
	if !becameOverflow || !plan.Required() || plan.Source != relayRouteSourceOverflow {
		t.Fatalf("overflow plan = %+v", plan)
	}
	if !plan.SkipPinPersistence || plan.StateFallbackReason != "" {
		t.Fatalf("overflow fallback state = %+v", plan)
	}
}

func TestOverflowWithStableScopeDoesNotPersistConversationPin(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	overflowContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	overflowContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	overflowContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	overflowContext.Set(contextAPIKeyID, int64(11))
	plan := defaultRelayRoutePlan(loadRelayRouteConfig())
	plan.Endpoint = "/v1/responses"
	plan.PinCandidates = relayRoutePinCandidates(overflowContext, nil, 11)
	becameOverflow, err := handler.observeRelayRouteSelection(
		overflowContext,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("observe overflow selection: %v", err)
	}
	if !becameOverflow || !plan.Required() ||
		plan.Source != relayRouteSourceOverflow ||
		!plan.SkipPinPersistence {
		t.Fatalf("overflow route plan = %+v", plan)
	}
	if _, found, err := handler.readRelayRoutePin(overflowContext.Request.Context(), plan.PinCandidates); err != nil || found {
		t.Fatalf("overflow conversation pin found=%t err=%v, want no persisted pin", found, err)
	}

	ordinaryContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	ordinaryContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ordinaryContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	ordinaryContext.Set(contextAPIKeyID, int64(11))
	ordinaryPlan, err := handler.prepareRelayRoutePlan(
		ordinaryContext,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare request after overflow: %v", err)
	}
	if ordinaryPlan.Required() || ordinaryPlan.Source != relayRouteSourceDefault {
		t.Fatalf("overflow polluted the following ordinary route: %+v", ordinaryPlan)
	}

	continuationContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	continuationContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	continuationContext.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	continuationContext.Set(contextAPIKeyID, int64(11))
	continuationPlan, err := handler.prepareRelayRoutePlan(
		continuationContext,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_1","input":"Continue."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepare overflow continuation: %v", err)
	}
	if continuationPlan.Required() || continuationPlan.Source != relayRouteSourceDefault {
		t.Fatalf("overflow scope polluted a later response branch: %+v", continuationPlan)
	}
}

func TestRequiredRelayRouteWithoutStableScopeSkipsPin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("required Relay route failed without a stable conversation scope: %v", err)
	}
	if becameOverflow {
		t.Fatal("already-required Relay route was marked as overflow")
	}
	if !plan.SkipPinPersistence {
		t.Fatal("missing stable scope did not disable pin persistence")
	}
	if plan.StateFallbackReason != "missing_scope" || !plan.StateFallbackLogged {
		t.Fatalf("missing-scope fallback state = %+v", plan)
	}
}

func TestRelayRoutePinRoundTripStoresGroupNotAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceRule
	plan.Origin = relayRouteSourceRule
	plan.PinCandidates = relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 11)
	if err := handler.writeRelayRoutePins(c.Request.Context(), &plan); err != nil {
		t.Fatalf("writeRelayRoutePins() error = %v", err)
	}

	pin, found, err := handler.readRelayRoutePin(c.Request.Context(), plan.PinCandidates)
	if err != nil || !found {
		t.Fatalf("readRelayRoutePin() found=%t err=%v", found, err)
	}
	if pin.GroupID != 3 || pin.Source != relayRouteSourceRule {
		t.Fatalf("pin = %+v", pin)
	}
}

func TestRelayFeedbackRouteDoesNotPersistConversationPin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceFeedback
	plan.Origin = relayRouteSourceFeedback
	plan.SkipPinPersistence = true
	plan.PinCandidates = relayRoutePinCandidates(c, []byte(`{"model":"gpt-5.5"}`), 11)
	if err := handler.writeRelayRoutePins(c.Request.Context(), &plan); err != nil {
		t.Fatalf("writeRelayRoutePins() error = %v", err)
	}

	if _, found, err := handler.readRelayRoutePin(c.Request.Context(), plan.PinCandidates); err != nil || found {
		t.Fatalf("feedback-only pin found=%t err=%v, want no persisted pin", found, err)
	}
}

func TestRelayRoutePinRejectsCorruptCachedState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(downstreamAffinityHeader, "user-a:conversation-1")
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(candidates))
	}
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		json.RawMessage(`{"group_id":0}`),
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}
	if _, _, err := handler.readRelayRoutePin(c.Request.Context(), candidates); err == nil {
		t.Fatal("corrupt pin state was silently treated as a cache miss")
	}
}

func TestRelayContinuationWithoutStableScopeKeepsOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_without_scope","input":"continue"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("continuation without stable scope returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Source != relayRouteSourceDefault ||
		plan.Reason != "" || plan.StateFallbackReason != "" {
		t.Fatalf("ordinary continuation changed official route: %+v", plan)
	}
}

func TestRelayContinuationWithPinMissKeepsOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_without_pin","input":"continue"}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("continuation pin miss returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Source != relayRouteSourceDefault ||
		plan.Reason != "" || plan.StateFallbackReason != "" {
		t.Fatalf("ordinary continuation pin miss changed official route: %+v", plan)
	}
}

func TestCompleteReplayRestoresRelayGroupWithoutConversationPin(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	cfg := loadRelayRouteConfig()
	plan := defaultRelayRoutePlan(cfg)
	handler := &Handler{}

	handler.applyRelayContinuationReplayRoute(nil, &plan, true, 3)
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceContinuation ||
		plan.Reason != "complete_replay_group" {
		t.Fatalf("replay provenance did not restore Relay group: %+v", plan)
	}
	filter := plan.composeFilter(nil)
	if filter(&auth.Account{DBID: 1, GroupIDs: []int64{2}}) {
		t.Fatal("replayed continuation allowed an account outside its Relay group")
	}
	if !filter(&auth.Account{DBID: 2, GroupIDs: []int64{3}}) {
		t.Fatal("replayed continuation rejected an account inside its Relay group")
	}
}

func TestCompleteReplayOverridesNoAffinityAuditSource(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	plan := defaultRelayRoutePlan(loadRelayRouteConfig())
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceNoAffinity
	plan.Origin = relayRouteSourceNoAffinity
	plan.Reason = "official_no_affinity_group"
	handler := &Handler{}

	handler.applyRelayContinuationReplayRoute(nil, &plan, true, 3)
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceContinuation ||
		plan.Origin != relayRouteSourceContinuation ||
		plan.Reason != "complete_replay_group" {
		t.Fatalf("replay did not take precedence over no-affinity source: %+v", plan)
	}
}

func TestUnknownContinuationReplayDoesNotForceRelayGroup(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	plan := defaultRelayRoutePlan(loadRelayRouteConfig())
	handler := &Handler{}

	handler.applyRelayContinuationReplayRoute(nil, &plan, false, 0)
	if plan.Required() || plan.RequiredGroupID != 0 || plan.Source != relayRouteSourceDefault {
		t.Fatalf("unknown continuation changed official route: %+v", plan)
	}
}

func TestRelayNativeFallbackPreservesReplayMissReason(t *testing.T) {
	plan := defaultRelayRoutePlan(relayRouteConfig{})
	plan.HasPreviousResponseID = true
	handler := &Handler{}

	handler.recordRelayContinuationNativeFallback(
		&plan,
		&RelayContinuationReplayError{Reason: RelayReplayIncomplete},
	)
	if plan.AuditReplayStatus != string(RelayReplayIncomplete) ||
		plan.AuditReplaySource != relayReplaySourceNative {
		t.Fatalf("native fallback audit state = %+v", plan)
	}
}

func TestRelayRoutePinReadFailureKeepsOrdinaryRequestOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		getErr:     errors.New("redis unavailable"),
	})

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("pin read failure returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Source != relayRouteSourceDefault ||
		plan.Reason != "" ||
		plan.StateFallbackReason != "pin_read_error" {
		t.Fatalf("pin read degraded plan = %+v", plan)
	}
}

func TestRelayRouteCorruptPinKeepsOrdinaryRequestOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		json.RawMessage(`{"group_id":0}`),
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("corrupt pin returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Reason != "" ||
		plan.StateFallbackReason != "pin_invalid" {
		t.Fatalf("corrupt pin degraded plan = %+v", plan)
	}
}

func TestRelayRouteStalePinKeepsOrdinaryRequestOnOfficialRoute(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(cache.NewMemory(1))
	candidates := relayRoutePinCandidates(c, nil, 11)
	raw, err := json.Marshal(relayRoutePinValue{GroupID: 8, Source: relayRouteSourceRule})
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	if err := handler.cache.SetRuntime(
		c.Request.Context(),
		relayRoutePinNamespace,
		candidates[0].Key,
		raw,
		time.Minute,
	); err != nil {
		t.Fatalf("SetRuntime(): %v", err)
	}

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("stale pin returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Reason != "" ||
		plan.StateFallbackReason != "pin_invalid" {
		t.Fatalf("stale pin degraded plan = %+v", plan)
	}
}

func TestRelayRoutePinReadFailureDoesNotMisrouteOAuthContinuation(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))
	handler := &Handler{}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		getErr:     errors.New("redis unavailable"),
	})

	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","previous_response_id":"resp_oauth","input":"Continue."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("continuation pin read failure returned an error: %v", err)
	}
	if plan.Required() || plan.RequiredGroupID != 0 ||
		plan.Source != relayRouteSourceDefault ||
		plan.Reason != "" ||
		plan.StateFallbackReason != "pin_read_error" {
		t.Fatalf("OAuth continuation was misrouted after pin read failure: %+v", plan)
	}

	handler.applyRelayContinuationReplayRoute(c, plan, true, 3)
	if !plan.Required() || plan.RequiredGroupID != 3 ||
		plan.Source != relayRouteSourceContinuation ||
		plan.Reason != "complete_replay_group" {
		t.Fatalf("verified Relay replay did not restore the group: %+v", plan)
	}
}

func TestRelayRoutePinWriteFailureKeepsRelaySelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	handler := &Handler{}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		setErr:     errors.New("redis unavailable"),
	})
	plan := defaultRelayRoutePlan(relayRouteConfig{Enabled: true, GroupID: 3, PinTTL: time.Minute})
	plan.Endpoint = "/v1/responses"
	plan.RequiredGroupID = 3
	plan.Source = relayRouteSourceRule
	plan.Origin = relayRouteSourceRule
	plan.PinCandidates = relayRoutePinCandidates(c, nil, 11)

	becameOverflow, err := handler.observeRelayRouteSelection(
		c,
		&plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	)
	if err != nil {
		t.Fatalf("pin write failure returned an error: %v", err)
	}
	if becameOverflow {
		t.Fatal("already-required Relay route was marked as overflow")
	}
	if !plan.SkipPinPersistence || plan.SelectionCount != 1 {
		t.Fatalf("pin write fallback plan = %+v", plan)
	}
	if plan.StateFallbackReason != "pin_write_error" || !plan.StateFallbackLogged {
		t.Fatalf("pin write fallback state = %+v", plan)
	}
}

func TestRelayRouteStateFallbackMetricPersistsOncePerRequest(t *testing.T) {
	t.Setenv("CODEX_CYB_RELAY_GROUP_ID", "3")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("Idempotency-Key", "request-123")
	c.Set(contextAPIKeyID, int64(11))

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("database.New(sqlite): %v", err)
	}
	defer db.Close()

	handler := &Handler{db: db}
	handler.SetRuntimeCache(&relayRouteFailingRuntimeCache{
		TokenCache: cache.NewMemory(1),
		getErr:     errors.New("redis read unavailable"),
		setErr:     errors.New("redis write unavailable"),
	})
	plan, err := handler.prepareRelayRoutePlan(
		c,
		[]byte(`{"model":"gpt-5.5","input":"Explain this API response."}`),
		"/v1/responses",
	)
	if err != nil {
		t.Fatalf("prepareRelayRoutePlan() error = %v", err)
	}
	if _, err := handler.observeRelayRouteSelection(
		c,
		plan,
		&auth.Account{DBID: 7, GroupIDs: []int64{3}},
	); err != nil {
		t.Fatalf("observeRelayRouteSelection() error = %v", err)
	}
	if !db.WaitRelayAuditIdle(t.Context()) {
		t.Fatal("relay audit queue did not become idle")
	}
	stats, err := db.GetRelayRouteStats(t.Context(), 24*time.Hour)
	if err != nil {
		t.Fatalf("GetRelayRouteStats() error = %v", err)
	}
	if stats.StateFallbacks != 1 {
		t.Fatalf("state_fallbacks = %d, want 1", stats.StateFallbacks)
	}
	if stats.RouteAttempts != 1 || stats.LogicalRoutes != 1 {
		t.Fatalf(
			"fallback route totals = attempts:%d logical:%d, want 1/1",
			stats.RouteAttempts,
			stats.LogicalRoutes,
		)
	}
}

func TestRelayAuditFinalizerUsesOfficialSuccessUsageTransport(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("database.New(sqlite): %v", err)
	}
	defer db.Close()

	handler := &Handler{db: db}
	now := time.Now().UTC()
	plan := &relayRoutePlan{
		Endpoint:        "/v1/responses",
		Model:           "gpt-5.4",
		RequiredGroupID: 3,
		AuditRequestID:  database.NewRelayAuditRequestID(),
		AuditCreatedAt:  now,
	}
	setRelayRoutePlanContext(c, plan)
	handler.beginRelayAudit(c, plan, []byte(`{"model":"gpt-5.4","input":"hello"}`))
	handler.recordRelayRouteSelection(c, plan, &auth.Account{
		DBID:         7,
		UpstreamType: auth.UpstreamOpenAIResponses,
		GroupIDs:     []int64{3},
	})

	// Successful official usage rows intentionally have AttemptIndex == 0.
	handler.logRelayAuditUsage(c, &database.UsageLogInput{
		AccountID:        7,
		Endpoint:         "/v1/responses",
		UpstreamEndpoint: "/v1/responses",
		StatusCode:       http.StatusOK,
		ViaWebsocket:     true,
	})
	handler.finalizeRelayAuditRequest(c, plan)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !db.WaitRelayAuditIdle(waitCtx) {
		t.Fatal("relay audit queue did not become idle")
	}
	page, err := db.ListRelayAuditCasesPage(context.Background(), database.RelayAuditCaseQuery{
		Kind:     database.RelayAuditCaseRelayRoute,
		Start:    now.Add(-time.Minute),
		End:      now.Add(time.Minute),
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page=%+v", page)
	}
	item := page.Items[0]
	if item.FinalStatusCode != http.StatusOK || item.FinalTransport != "websocket" ||
		item.FinalAccountID != 7 || item.AttemptCount != 1 {
		t.Fatalf("final audit=%+v", item)
	}
	if len(item.Attempts) != 1 || !item.Attempts[0].ViaWebsocket ||
		item.Attempts[0].Transport != "websocket" {
		t.Fatalf("attempts=%+v", item.Attempts)
	}
}
