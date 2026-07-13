package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	CodexAuditCaseRelayRoute   = "relay_route"
	CodexAuditCaseSessionBleed = "session_bleed"
	CodexAuditCaseOAuthCyber   = "oauth_cyber"
	CodexAuditCaseRelayCyber   = "relay_cyber"
)

type CodexAuditCasesQuery struct {
	Kind     string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

type CodexAuditCasesPage struct {
	Items       []*PromptFilterLog `json:"items"`
	Total       int                `json:"total"`
	Page        int                `json:"page"`
	PageSize    int                `json:"page_size"`
	WindowStart time.Time          `json:"window_start"`
	WindowEnd   time.Time          `json:"window_end"`
}

type CodexAuditAttempt struct {
	AccountID         int64     `json:"account_id"`
	AccountName       string    `json:"account_name"`
	StatusCode        int       `json:"status_code"`
	AttemptIndex      int       `json:"attempt_index"`
	IsRetryAttempt    bool      `json:"is_retry_attempt"`
	UpstreamErrorKind string    `json:"upstream_error_kind"`
	ErrorMessage      string    `json:"error_message"`
	RouteSource       string    `json:"route_source"`
	CreatedAt         time.Time `json:"created_at"`
}

// ListCodexAuditCasesPage returns stable server-side pagination. Relay routing
// cases are canonicalized to one record per logical request; event-style case
// kinds keep every row. The time window is applied first so every page and the
// total are derived from exactly the same audit window.
func (db *DB) ListCodexAuditCasesPage(ctx context.Context, query CodexAuditCasesQuery) (*CodexAuditCasesPage, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	kind := strings.ToLower(strings.TrimSpace(query.Kind))
	if kind == "" {
		kind = CodexAuditCaseRelayRoute
	}
	if !query.Start.Before(query.End) {
		return nil, fmt.Errorf("invalid codex audit case window")
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
	if kind == CodexAuditCaseRelayRoute {
		return db.listCodexAuditRelayCasesPage(ctx, query.Start, query.End, page, pageSize)
	}

	where, args, err := db.codexAuditCaseWhere(kind, query.Start, query.End)
	if err != nil {
		return nil, err
	}
	partitionKey := "'row:' || CAST(p.id AS TEXT)"
	cte := `WITH ranked_cases AS (
		SELECT p.*,
		       ROW_NUMBER() OVER (
		         PARTITION BY ` + partitionKey + `
		         ORDER BY p.id DESC
		       ) AS audit_case_rn
		FROM prompt_filter_logs p
		WHERE ` + where + `
	), canonical_cases AS (
		SELECT * FROM ranked_cases WHERE audit_case_rn = 1
	)`

	var total int
	if err := db.conn.QueryRowContext(ctx, cte+` SELECT COUNT(*) FROM canonical_cases`, args...).Scan(&total); err != nil {
		return nil, err
	}

	selectArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	limitArg := len(selectArgs) - 1
	offsetArg := len(selectArgs)
	rows, err := db.conn.QueryContext(ctx, cte+`
		SELECT id, created_at, COALESCE(source, ''), COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(action, ''), COALESCE(mode, ''), COALESCE(score, 0), COALESCE(threshold_value, 0),
		       COALESCE(matched_patterns, '[]'), COALESCE(text_preview, ''), COALESCE(api_key_id, 0),
		       COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''), COALESCE(client_ip, ''), COALESCE(error_code, ''),
		       COALESCE(review_model, ''), COALESCE(review_flagged, false), COALESCE(review_error, ''), COALESCE(full_text, ''),
		       COALESCE(client_request_id, ''), COALESCE(logical_request_id, ''),
		       COALESCE(account_id, 0), COALESCE(route_class, ''), COALESCE(route_reason, ''),
		       COALESCE(route_source, ''), COALESCE(route_signals, '[]'), COALESCE(pin_kind, ''), COALESCE(route_group_id, 0),
		       COALESCE(route_pinned, false), COALESCE(upstream_account_type, '')
		FROM canonical_cases
		ORDER BY created_at DESC, id DESC
		LIMIT $`+fmt.Sprint(limitArg)+` OFFSET $`+fmt.Sprint(offsetArg), selectArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*PromptFilterLog, 0, pageSize)
	for rows.Next() {
		item := &PromptFilterLog{}
		var createdAtRaw any
		if err := rows.Scan(
			&item.ID, &createdAtRaw, &item.Source, &item.Endpoint, &item.Model,
			&item.Action, &item.Mode, &item.Score, &item.Threshold,
			&item.MatchedPatterns, &item.TextPreview, &item.APIKeyID,
			&item.APIKeyName, &item.APIKeyMasked, &item.ClientIP, &item.ErrorCode,
			&item.ReviewModel, &item.ReviewFlagged, &item.ReviewError, &item.FullText,
			&item.ClientRequestID, &item.LogicalRequestID,
			&item.AccountID, &item.RouteClass, &item.RouteReason,
			&item.RouteSource, &item.RouteSignals, &item.PinKind, &item.RouteGroupID,
			&item.RoutePinned, &item.UpstreamAccountType,
		); err != nil {
			return nil, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = createdAt
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &CodexAuditCasesPage{
		Items:       items,
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		WindowStart: query.Start,
		WindowEnd:   query.End,
	}, nil
}

func (db *DB) listCodexAuditAttempts(ctx context.Context, logicalRequestID string, start, end time.Time) ([]CodexAuditAttempt, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		WITH business_request AS MATERIALIZED (
			SELECT u.logical_request_id
			FROM usage_logs u
			WHERE u.logical_request_id = $1
			  AND u.created_at >= $2 AND u.created_at <= $3
			  AND NOT COALESCE(u.guardian_attempt_only, FALSE)
			GROUP BY u.logical_request_id
		)
		SELECT COALESCE(u.account_id, 0), COALESCE(a.name, ''), COALESCE(u.status_code, 0),
		       COALESCE(u.attempt_index, 0), COALESCE(u.is_retry_attempt, false),
		       COALESCE(u.upstream_error_kind, ''), COALESCE(u.error_message, ''),
		       COALESCE(u.route_source, ''), u.created_at
		FROM usage_logs u
		LEFT JOIN accounts a ON a.id = u.account_id
		WHERE u.logical_request_id = $1 AND u.created_at >= $2 AND u.created_at <= $3
		  AND (
			NOT COALESCE(u.guardian_attempt_only, FALSE)
			OR (
				COALESCE(u.guardian_attempt_only, FALSE)
				AND COALESCE(u.attempt_index, 0) > 0
				AND EXISTS (SELECT 1 FROM business_request)
			)
		  )
		ORDER BY u.id ASC
	`, logicalRequestID, startArg, endArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CodexAuditAttempt, 0, 2)
	for rows.Next() {
		var item CodexAuditAttempt
		var createdAtRaw any
		if err := rows.Scan(&item.AccountID, &item.AccountName, &item.StatusCode, &item.AttemptIndex,
			&item.IsRetryAttempt, &item.UpstreamErrorKind, &item.ErrorMessage, &item.RouteSource, &createdAtRaw); err != nil {
			return nil, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = createdAt
		result = append(result, item)
	}
	return result, rows.Err()
}

// listCodexAuditRelayCasesPage uses the canonical final usage row as the
// routing authority. Prompt-filter rows only enrich the case with the
// redacted payload and classification that were captured before account
// selection; they never override the final route source or account metadata.
func (db *DB) listCodexAuditRelayCasesPage(ctx context.Context, start, end time.Time, page, pageSize int) (*CodexAuditCasesPage, error) {
	startArg, endArg := db.timeRangeArgs(start, end)
	var total int
	if err := db.conn.QueryRowContext(ctx, `WITH ranked_routes AS (
		SELECT COALESCE(route_class, '') AS route_class,
		       ROW_NUMBER() OVER (
		         PARTITION BY COALESCE(NULLIF(logical_request_id, ''), 'legacy:' || CAST(id AS TEXT))
		         ORDER BY id DESC
		       ) AS audit_rn
		FROM usage_logs
		WHERE created_at >= $1 AND created_at <= $2
		  AND NOT COALESCE(guardian_attempt_only, FALSE)
	)
		SELECT COUNT(*) FROM ranked_routes
		WHERE audit_rn = 1 AND route_class = 'cyb_relay'
	`, startArg, endArg).Scan(&total); err != nil {
		return nil, err
	}

	// Page the canonical usage rows before enriching them with prompt payloads.
	// Prompt full_text values are large (tens of MiB in a normal multi-hour
	// window); joining the complete ranked prompt set before LIMIT caused
	// PostgreSQL to compare every relay row with every prompt row and made the
	// three-hour report hit its request deadline. The page boundary is also the
	// contract boundary: prompt rows may enrich these selected cases, but can
	// never influence which logical requests belong to the page.
	rows, err := db.conn.QueryContext(ctx, codexAuditCanonicalUsageCTE+`, paged_usage AS MATERIALIZED (
		SELECT * FROM final_usage
		WHERE COALESCE(route_class, '') = 'cyb_relay'
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4
	), page_request_ids AS MATERIALIZED (
		SELECT DISTINCT logical_request_id
		FROM paged_usage
		WHERE COALESCE(logical_request_id, '') <> ''
	), ranked_prompts AS (
		SELECT p.*,
		       ROW_NUMBER() OVER (
		         PARTITION BY p.logical_request_id
		         ORDER BY CASE COALESCE(p.source, '')
		                    WHEN 'cyb_relay_routed' THEN 0
		                    WHEN 'local_filter' THEN 1
		                    ELSE 2
		                  END,
		                  p.id DESC
		       ) AS prompt_rn
		FROM prompt_filter_logs p
		JOIN page_request_ids page_ids ON page_ids.logical_request_id = p.logical_request_id
		WHERE p.created_at >= $1 AND p.created_at <= $2
		  AND COALESCE(p.source, '') IN ('cyb_relay_routed', 'local_filter')
	)
		SELECT u.id, u.created_at, 'cyb_relay_routed',
		       COALESCE(NULLIF(u.inbound_endpoint, ''), u.endpoint, ''),
		       COALESCE(NULLIF(u.effective_model, ''), u.model, ''),
		       COALESCE(NULLIF(p.action, ''), 'route'), COALESCE(p.mode, ''),
		       COALESCE(p.score, 0), COALESCE(p.threshold_value, 0),
		       COALESCE(p.matched_patterns, '[]'), COALESCE(p.text_preview, ''),
		       COALESCE(u.api_key_id, 0), COALESCE(u.api_key_name, ''), COALESCE(u.api_key_masked, ''),
		       COALESCE(u.client_ip, ''), COALESCE(p.error_code, ''),
		       COALESCE(p.review_model, ''), COALESCE(p.review_flagged, false), COALESCE(p.review_error, ''),
		       COALESCE(p.full_text, ''), COALESCE(p.client_request_id, ''), COALESCE(u.logical_request_id, ''),
		       COALESCE(u.account_id, 0), COALESCE(a.name, ''), COALESCE(u.route_class, ''),
		       COALESCE(u.route_reason, ''), COALESCE(u.route_source, ''), COALESCE(u.route_signals, '[]'),
		       COALESCE(u.pin_kind, ''), COALESCE(u.route_group_id, 0), COALESCE(u.route_pinned, false),
		       COALESCE(u.upstream_account_type, '')
		FROM paged_usage u
		LEFT JOIN ranked_prompts p
		  ON p.logical_request_id = u.logical_request_id AND p.prompt_rn = 1
		LEFT JOIN accounts a ON a.id = u.account_id
		ORDER BY u.created_at DESC, u.id DESC
	`, startArg, endArg, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*PromptFilterLog, 0, pageSize)
	for rows.Next() {
		item := &PromptFilterLog{}
		var createdAtRaw any
		if err := rows.Scan(
			&item.ID, &createdAtRaw, &item.Source, &item.Endpoint, &item.Model,
			&item.Action, &item.Mode, &item.Score, &item.Threshold,
			&item.MatchedPatterns, &item.TextPreview, &item.APIKeyID, &item.APIKeyName, &item.APIKeyMasked,
			&item.ClientIP, &item.ErrorCode, &item.ReviewModel, &item.ReviewFlagged, &item.ReviewError,
			&item.FullText, &item.ClientRequestID, &item.LogicalRequestID,
			&item.AccountID, &item.AccountName, &item.RouteClass, &item.RouteReason, &item.RouteSource,
			&item.RouteSignals, &item.PinKind, &item.RouteGroupID, &item.RoutePinned, &item.UpstreamAccountType,
		); err != nil {
			return nil, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = createdAt
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, item := range items {
		if strings.TrimSpace(item.LogicalRequestID) == "" {
			continue
		}
		attempts, err := db.listCodexAuditAttempts(ctx, item.LogicalRequestID, start, end)
		if err != nil {
			return nil, err
		}
		item.AuditAttempts = attempts
	}
	return &CodexAuditCasesPage{
		Items:       items,
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		WindowStart: start,
		WindowEnd:   end,
	}, nil
}

func (db *DB) codexAuditCaseWhere(kind string, start, end time.Time) (string, []any, error) {
	args := []any{db.timeArg(start), db.timeArg(end)}
	window := "p.created_at >= $1 AND p.created_at <= $2"
	switch kind {
	case CodexAuditCaseRelayRoute:
		return window + " AND COALESCE(p.source, '') = 'cyb_relay_routed'", args, nil
	case CodexAuditCaseSessionBleed:
		return window + " AND COALESCE(p.source, '') = 'session_bleed'", args, nil
	case CodexAuditCaseOAuthCyber:
		return window + " AND COALESCE(p.source, '') = 'upstream_cyber_policy' AND COALESCE(p.upstream_account_type, '') = 'oauth'", args, nil
	case CodexAuditCaseRelayCyber:
		return window + " AND COALESCE(p.source, '') = 'upstream_cyber_policy' AND COALESCE(p.upstream_account_type, '') = 'openai_responses' AND COALESCE(p.route_class, '') = 'cyb_relay' AND COALESCE(p.route_group_id, 0) > 0", args, nil
	default:
		return "", nil, fmt.Errorf("unsupported codex audit case kind %q", kind)
	}
}
