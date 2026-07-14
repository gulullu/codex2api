package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CodexAuditCyberCase is a canonical logical-request case file. Account,
// routing and final outcome fields come exclusively from usage_logs. A prompt
// row may enrich the case only when it has the exact same logical_request_id.
// Empty legacy IDs deliberately receive no prompt enrichment.
type CodexAuditCyberCase struct {
	ID                    int64               `json:"id"`
	AuditRequestID        string              `json:"audit_request_id"`
	LogicalRequestID      string              `json:"logical_request_id"`
	Legacy                bool                `json:"legacy"`
	Scope                 string              `json:"scope"`
	CreatedAt             time.Time           `json:"created_at"`
	CyberAttempts         int                 `json:"cyber_attempts"`
	AttemptCount          int                 `json:"attempt_count"`
	CyberAccountID        int64               `json:"cyber_account_id"`
	CyberAccountName      string              `json:"cyber_account_name"`
	CyberAccountType      string              `json:"cyber_account_type"`
	CyberStatusCode       int                 `json:"cyber_status_code"`
	CyberErrorMessage     string              `json:"cyber_error_message"`
	FinalUsageID          int64               `json:"final_usage_id"`
	FinalCreatedAt        time.Time           `json:"final_created_at"`
	FinalAccountID        int64               `json:"final_account_id"`
	FinalAccountName      string              `json:"final_account_name"`
	FinalAccountType      string              `json:"final_account_type"`
	FinalStatusCode       int                 `json:"final_status_code"`
	Endpoint              string              `json:"endpoint"`
	InboundEndpoint       string              `json:"inbound_endpoint"`
	UpstreamEndpoint      string              `json:"upstream_endpoint"`
	Model                 string              `json:"model"`
	APIKeyID              int64               `json:"api_key_id"`
	APIKeyName            string              `json:"api_key_name"`
	APIKeyMasked          string              `json:"api_key_masked"`
	ClientIP              string              `json:"client_ip"`
	RouteClass            string              `json:"route_class"`
	RouteReason           string              `json:"route_reason"`
	RouteSource           string              `json:"route_source"`
	RouteSignals          string              `json:"route_signals"`
	PinKind               string              `json:"pin_kind"`
	RouteGroupID          int64               `json:"route_group_id"`
	RoutePinned           bool                `json:"route_pinned"`
	PromptLogID           int64               `json:"prompt_log_id"`
	PromptSource          string              `json:"prompt_source"`
	Score                 int                 `json:"score"`
	Threshold             int                 `json:"threshold"`
	MatchedPatterns       string              `json:"matched_patterns"`
	TextPreview           string              `json:"text_preview"`
	FullText              string              `json:"full_text"`
	PayloadBytes          int64               `json:"payload_bytes"`
	ScannedBytes          int64               `json:"scanned_bytes"`
	ScanTruncated         bool                `json:"scan_truncated"`
	ScanDetails           string              `json:"scan_details"`
	ContentClassification string              `json:"content_classification"`
	Attempts              []CodexAuditAttempt `json:"attempts"`
}

type CodexAuditCyberCasesPage struct {
	Items       []*CodexAuditCyberCase `json:"items"`
	Total       int                    `json:"total"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	WindowStart time.Time              `json:"window_start"`
	WindowEnd   time.Time              `json:"window_end"`
}

const codexAuditCyberPolicyAttemptSQL = `(u.upstream_error_kind = 'cyber_policy')`

const codexAuditOAuthCyberAttemptSQL = `(` + codexAuditCyberPolicyAttemptSQL + `
	AND u.upstream_account_type = 'oauth'
)`

const codexAuditRelayCyberAttemptSQL = `(` + codexAuditCyberPolicyAttemptSQL + `
	AND u.upstream_account_type = 'openai_responses'
	AND u.route_class = 'cyb_relay'
	AND u.route_group_id > 0
)`

func codexAuditCyberScopeSQL(kind string) (scope string, predicate string, err error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case CodexAuditCaseOAuthCyber:
		return "oauth", codexAuditOAuthCyberAttemptSQL, nil
	case CodexAuditCaseRelayCyber:
		return "relay", codexAuditRelayCyberAttemptSQL, nil
	default:
		return "", "", fmt.Errorf("unsupported cyber case kind %q", kind)
	}
}

// codexAuditCyberCandidatesCTE starts from the rare, indexable cyber_policy
// attempts and only then resolves their visible business final. This prevents a
// multi-hour case page from sorting every usage row or touching large prompt
// payloads before LIMIT. A hidden row is accepted only when it is a positive
// business attempt associated with a visible final in the same fixed window.
func codexAuditCyberCandidatesCTE(cyberPredicate string) string {
	return `WITH cyber_hits AS MATERIALIZED (
		SELECT u.id, u.created_at, COALESCE(u.logical_request_id, '') AS logical_request_id,
		       COALESCE(NULLIF(u.logical_request_id, ''), 'legacy:' || CAST(u.id AS TEXT)) AS audit_request_id
		FROM usage_logs u
		WHERE u.created_at >= $1 AND u.created_at <= $2
		  AND ` + cyberPredicate + `
		  AND (
			NOT COALESCE(u.guardian_attempt_only, FALSE)
			OR (
				COALESCE(u.guardian_attempt_only, FALSE)
				AND COALESCE(u.attempt_index, 0) > 0
				AND COALESCE(u.logical_request_id, '') <> ''
				AND EXISTS (
					SELECT 1 FROM usage_logs visible
					WHERE visible.logical_request_id = u.logical_request_id
					  AND visible.created_at >= $1 AND visible.created_at <= $2
					  AND NOT COALESCE(visible.guardian_attempt_only, FALSE)
				)
			)
		  )
	), ranked_cyber AS MATERIALIZED (
		SELECT h.*,
		       COUNT(*) OVER (PARTITION BY audit_request_id) AS cyber_attempts,
		       ROW_NUMBER() OVER (
		         PARTITION BY audit_request_id ORDER BY created_at DESC, id DESC
		       ) AS cyber_rn
		FROM cyber_hits h
	), candidate_requests AS MATERIALIZED (
		SELECT audit_request_id, logical_request_id, cyber_attempts,
		       id AS last_cyber_id, created_at AS last_cyber_at
		FROM ranked_cyber WHERE cyber_rn = 1
	)`
}

// ListCodexAuditCyberCasesPage returns one case per canonical logical request.
// The window end is supplied by the caller and never advanced between pages.
func (db *DB) ListCodexAuditCyberCasesPage(ctx context.Context, query CodexAuditCasesQuery) (*CodexAuditCyberCasesPage, error) {
	return db.listCodexAuditCyberCasesPage(ctx, query, true)
}

func (db *DB) listCodexAuditCyberCasesPage(ctx context.Context, query CodexAuditCasesQuery, includeTotal bool) (*CodexAuditCyberCasesPage, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if !query.Start.Before(query.End) {
		return nil, fmt.Errorf("invalid codex audit case window")
	}
	scope, scopePredicate, err := codexAuditCyberScopeSQL(query.Kind)
	if err != nil {
		return nil, err
	}
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	startArg, endArg := db.timeRangeArgs(query.Start, query.End)
	baseCTE := codexAuditCyberCandidatesCTE(scopePredicate)

	var total int
	if includeTotal {
		if err := db.conn.QueryRowContext(ctx, baseCTE+` SELECT COUNT(*) FROM candidate_requests`, startArg, endArg).Scan(&total); err != nil {
			return nil, err
		}
	}

	rows, err := db.conn.QueryContext(ctx, baseCTE+`, paged_candidates AS MATERIALIZED (
		SELECT * FROM candidate_requests
		ORDER BY last_cyber_at DESC, last_cyber_id DESC
		LIMIT $3 OFFSET $4
	), ranked_visible AS (
		SELECT u.*,
		       ROW_NUMBER() OVER (PARTITION BY c.audit_request_id ORDER BY u.id DESC) AS final_rn
		FROM paged_candidates c
		JOIN usage_logs u ON (
			(COALESCE(c.logical_request_id, '') <> '' AND u.logical_request_id = c.logical_request_id)
			OR (COALESCE(c.logical_request_id, '') = '' AND u.id = c.last_cyber_id)
		)
		WHERE u.created_at >= $1 AND u.created_at <= $2
		  AND NOT COALESCE(u.guardian_attempt_only, FALSE)
	), final_usage AS MATERIALIZED (
		SELECT * FROM ranked_visible WHERE final_rn = 1
	), page_request_ids AS MATERIALIZED (
		SELECT logical_request_id FROM paged_candidates
		WHERE COALESCE(logical_request_id, '') <> ''
	), ranked_prompts AS (
		SELECT p.*,
		       ROW_NUMBER() OVER (
			PARTITION BY p.logical_request_id
			ORDER BY CASE COALESCE(p.source, '')
				WHEN 'upstream_cyber_policy' THEN 0
				WHEN 'local_filter' THEN 1
				WHEN 'cyb_relay_routed' THEN 2
				ELSE 3
			END, p.id DESC
		       ) AS prompt_rn
		FROM prompt_filter_logs p
		JOIN page_request_ids ids ON ids.logical_request_id = p.logical_request_id
	)
		SELECT c.audit_request_id, c.logical_request_id, c.last_cyber_id, c.last_cyber_at,
		       c.cyber_attempts,
		       COALESCE(cu.account_id, 0), COALESCE(ca.name, ''), COALESCE(cu.upstream_account_type, ''),
		       COALESCE(cu.status_code, 0), COALESCE(cu.error_message, ''),
		       COALESCE(fu.id, 0), fu.created_at, COALESCE(fu.account_id, 0), COALESCE(fa.name, ''),
		       COALESCE(fu.upstream_account_type, ''), COALESCE(fu.status_code, 0),
		       COALESCE(fu.endpoint, ''), COALESCE(fu.inbound_endpoint, ''), COALESCE(fu.upstream_endpoint, ''),
		       COALESCE(NULLIF(fu.effective_model, ''), fu.model, ''),
		       COALESCE(fu.api_key_id, 0), COALESCE(fu.api_key_name, ''), COALESCE(fu.api_key_masked, ''),
		       COALESCE(fu.client_ip, ''), COALESCE(fu.route_class, ''), COALESCE(fu.route_reason, ''),
		       COALESCE(fu.route_source, ''), COALESCE(fu.route_signals, '[]'), COALESCE(fu.pin_kind, ''),
		       COALESCE(fu.route_group_id, 0), COALESCE(fu.route_pinned, FALSE),
		       COALESCE(p.id, 0), COALESCE(p.source, ''), COALESCE(p.score, 0), COALESCE(p.threshold_value, 0),
		       COALESCE(p.matched_patterns, '[]'), COALESCE(p.text_preview, ''), COALESCE(p.full_text, ''),
		       COALESCE(p.payload_bytes, 0), COALESCE(p.scanned_bytes, 0),
		       COALESCE(p.scan_truncated, FALSE), COALESCE(p.scan_details, '{}')
		FROM paged_candidates c
		JOIN usage_logs cu ON cu.id = c.last_cyber_id
		JOIN final_usage fu ON (
			(COALESCE(c.logical_request_id, '') <> '' AND fu.logical_request_id = c.logical_request_id)
			OR (COALESCE(c.logical_request_id, '') = '' AND fu.id = c.last_cyber_id)
		)
		LEFT JOIN accounts ca ON ca.id = cu.account_id
		LEFT JOIN accounts fa ON fa.id = fu.account_id
		LEFT JOIN ranked_prompts p ON p.logical_request_id = c.logical_request_id AND p.prompt_rn = 1
		ORDER BY c.last_cyber_at DESC, c.last_cyber_id DESC
	`, startArg, endArg, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CodexAuditCyberCase, 0, pageSize)
	for rows.Next() {
		item := &CodexAuditCyberCase{Scope: scope, ContentClassification: "unconfirmed", Attempts: []CodexAuditAttempt{}}
		var cyberAtRaw, finalAtRaw any
		if err := rows.Scan(
			&item.AuditRequestID, &item.LogicalRequestID, &item.ID, &cyberAtRaw, &item.CyberAttempts,
			&item.CyberAccountID, &item.CyberAccountName, &item.CyberAccountType, &item.CyberStatusCode, &item.CyberErrorMessage,
			&item.FinalUsageID, &finalAtRaw, &item.FinalAccountID, &item.FinalAccountName, &item.FinalAccountType,
			&item.FinalStatusCode, &item.Endpoint, &item.InboundEndpoint, &item.UpstreamEndpoint, &item.Model,
			&item.APIKeyID, &item.APIKeyName, &item.APIKeyMasked, &item.ClientIP,
			&item.RouteClass, &item.RouteReason, &item.RouteSource, &item.RouteSignals, &item.PinKind,
			&item.RouteGroupID, &item.RoutePinned, &item.PromptLogID, &item.PromptSource, &item.Score,
			&item.Threshold, &item.MatchedPatterns, &item.TextPreview, &item.FullText,
			&item.PayloadBytes, &item.ScannedBytes, &item.ScanTruncated, &item.ScanDetails,
		); err != nil {
			return nil, err
		}
		item.CreatedAt, err = parseDBTimeValue(cyberAtRaw)
		if err != nil {
			return nil, err
		}
		item.FinalCreatedAt, err = parseDBTimeValue(finalAtRaw)
		if err != nil {
			return nil, err
		}
		item.Legacy = strings.TrimSpace(item.LogicalRequestID) == ""
		item.ContentClassification = classifyCodexAuditCyberContent(item)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if err := db.attachCodexAuditCyberAttempts(ctx, items, query.Start, query.End); err != nil {
		return nil, err
	}
	return &CodexAuditCyberCasesPage{
		Items: items, Total: total, Page: page, PageSize: pageSize,
		WindowStart: query.Start, WindowEnd: query.End,
	}, nil
}

func classifyCodexAuditCyberContent(item *CodexAuditCyberCase) string {
	if item == nil {
		return "unconfirmed"
	}
	evidence := strings.ToLower(item.MatchedPatterns + "\n" + item.FullText)
	hasSQL := strings.Contains(evidence, "sql_injection_attack") || strings.Contains(evidence, "sql injection")
	hasOperational := strings.Contains(evidence, "operational_exploit_request")
	hasCredential := containsAnyString(evidence, "password", "credential", "passwd", "token")
	hasExtraction := containsAnyString(evidence, "extract", "exfil", "dump", "retrieve", "steal")
	if hasSQL && hasOperational && hasCredential && hasExtraction {
		return "confirmed_route_gap"
	}
	if item.Threshold > 0 && item.Score >= item.Threshold {
		return "local_rule_hit"
	}
	return "unconfirmed"
}

func containsAnyString(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func (db *DB) attachCodexAuditCyberAttempts(ctx context.Context, items []*CodexAuditCyberCase, start, end time.Time) error {
	byLogicalID := make(map[string]*CodexAuditCyberCase, len(items))
	logicalIDs := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if item.Legacy {
			item.Attempts = []CodexAuditAttempt{{
				AccountID: item.CyberAccountID, AccountName: item.CyberAccountName,
				AccountType: item.CyberAccountType, StatusCode: item.CyberStatusCode,
				UpstreamErrorKind: "cyber_policy", ErrorMessage: item.CyberErrorMessage,
				RouteClass: item.RouteClass, RouteReason: item.RouteReason, RouteSource: item.RouteSource,
				RouteSignals: item.RouteSignals, PinKind: item.PinKind, RouteGroupID: item.RouteGroupID,
				RoutePinned: item.RoutePinned, InboundEndpoint: item.InboundEndpoint,
				UpstreamEndpoint: item.UpstreamEndpoint, Model: item.Model, CreatedAt: item.CreatedAt,
			}}
			item.AttemptCount = 1
			continue
		}
		byLogicalID[item.LogicalRequestID] = item
		logicalIDs = append(logicalIDs, item.LogicalRequestID)
	}
	if len(logicalIDs) == 0 {
		return nil
	}
	sort.Strings(logicalIDs)
	args := []any{db.timeArg(start), db.timeArg(end)}
	placeholders := make([]string, 0, len(logicalIDs))
	for _, logicalID := range logicalIDs {
		args = append(args, logicalID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(u.logical_request_id, ''), COALESCE(u.account_id, 0), COALESCE(a.name, ''),
		       COALESCE(u.upstream_account_type, ''), COALESCE(u.status_code, 0), COALESCE(u.attempt_index, 0),
		       COALESCE(u.is_retry_attempt, FALSE), COALESCE(u.upstream_error_kind, ''), COALESCE(u.error_message, ''),
		       COALESCE(u.route_class, ''), COALESCE(u.route_reason, ''), COALESCE(u.route_source, ''),
		       COALESCE(u.route_signals, '[]'), COALESCE(u.pin_kind, ''), COALESCE(u.route_group_id, 0),
		       COALESCE(u.route_pinned, FALSE), COALESCE(u.inbound_endpoint, ''), COALESCE(u.upstream_endpoint, ''),
		       COALESCE(NULLIF(u.effective_model, ''), u.model, ''), u.created_at
		FROM usage_logs u
		LEFT JOIN accounts a ON a.id = u.account_id
		WHERE u.created_at >= $1 AND u.created_at <= $2
		  AND u.logical_request_id IN (`+strings.Join(placeholders, ", ")+`)
		  AND (
			NOT COALESCE(u.guardian_attempt_only, FALSE)
			OR (COALESCE(u.guardian_attempt_only, FALSE) AND COALESCE(u.attempt_index, 0) > 0)
		  )
		ORDER BY u.logical_request_id, u.id
	`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var logicalID string
		var attempt CodexAuditAttempt
		var createdAtRaw any
		if err := rows.Scan(
			&logicalID, &attempt.AccountID, &attempt.AccountName, &attempt.AccountType, &attempt.StatusCode,
			&attempt.AttemptIndex, &attempt.IsRetryAttempt, &attempt.UpstreamErrorKind, &attempt.ErrorMessage,
			&attempt.RouteClass, &attempt.RouteReason, &attempt.RouteSource, &attempt.RouteSignals,
			&attempt.PinKind, &attempt.RouteGroupID, &attempt.RoutePinned, &attempt.InboundEndpoint,
			&attempt.UpstreamEndpoint, &attempt.Model, &createdAtRaw,
		); err != nil {
			return err
		}
		attempt.CreatedAt, err = parseDBTimeValue(createdAtRaw)
		if err != nil {
			return err
		}
		if item := byLogicalID[logicalID]; item != nil {
			item.Attempts = append(item.Attempts, attempt)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		if item != nil {
			item.AttemptCount = len(item.Attempts)
		}
	}
	return nil
}
