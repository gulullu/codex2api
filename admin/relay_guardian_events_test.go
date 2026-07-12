package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func newGuardianEventsTestHandler(t *testing.T) (*Handler, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{db: db}, db
}

func invokeGuardianEvents(handler *Handler, values url.Values) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	target := "/api/admin/relay-guardian/events"
	if len(values) > 0 {
		target += "?" + values.Encode()
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)
	handler.ListRelayGuardianEvents(ctx)
	return recorder
}

func TestParseGuardianTimeAcceptsFrontendAndLegacyFormats(t *testing.T) {
	tests := []string{
		"2026-07-12T17:00:00+08:00",
		"2026-07-12T17:00:00.123456789+08:00",
		"2026-07-12 17:00:00",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if parsed, err := parseGuardianTime(raw); err != nil || parsed.IsZero() {
				t.Fatalf("parseGuardianTime(%q) = %v, %v", raw, parsed, err)
			}
		})
	}
}

func TestListRelayGuardianEventsAcceptsFrontendRFC3339Window(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newGuardianEventsTestHandler(t)
	defer db.Close()
	values := url.Values{
		"start": {"2026-07-12T17:00:00+08:00"},
		"end":   {"2026-07-12T18:00:00.123456789+08:00"},
	}
	recorder := invokeGuardianEvents(handler, values)
	if recorder.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestListRelayGuardianEventsRejectsInvalidTimeBoundaries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newGuardianEventsTestHandler(t)
	defer db.Close()
	tests := []struct {
		name   string
		values url.Values
	}{
		{name: "invalid_start", values: url.Values{"start": {"not-a-time"}}},
		{name: "invalid_end", values: url.Values{"end": {"2026-02-30T00:00:00Z"}}},
		{name: "provided_empty_start", values: url.Values{"start": {""}}},
		{name: "provided_empty_end", values: url.Values{"end": {""}}},
		{name: "start_after_end", values: url.Values{
			"start": {"2026-07-12T18:00:00+08:00"},
			"end":   {"2026-07-12T17:00:00+08:00"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := invokeGuardianEvents(handler, tt.values)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestListRelayGuardianEventsPaginationRemainsBoundedByDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newGuardianEventsTestHandler(t)
	defer db.Close()
	maxInt := int(^uint(0) >> 1)
	tests := []struct {
		name         string
		values       url.Values
		wantPage     int
		wantPageSize int
	}{
		{name: "nonnumeric", values: url.Values{"page": {"oops"}, "page_size": {"oops"}}, wantPage: 1, wantPageSize: 20},
		{name: "negative", values: url.Values{"page": {"-9"}, "page_size": {"-7"}}, wantPage: 1, wantPageSize: 20},
		{name: "page_size_capped", values: url.Values{"page": {"2"}, "page_size": {"201"}}, wantPage: 2, wantPageSize: 200},
		{name: "overflowing_offset", values: url.Values{"page": {strconv.Itoa(maxInt)}, "page_size": {"200"}}, wantPage: 1, wantPageSize: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := invokeGuardianEvents(handler, tt.values)
			if recorder.Code != http.StatusOK {
				t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var page database.RelayGuardianEventPage
			if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if page.Page != tt.wantPage || page.PageSize != tt.wantPageSize {
				t.Fatalf("page=%d page_size=%d, want %d/%d", page.Page, page.PageSize, tt.wantPage, tt.wantPageSize)
			}
			if page.PageSize > 200 {
				t.Fatalf("unbounded page size=%d", page.PageSize)
			}
		})
	}
}

func TestListRelayGuardianEventsWithoutDatabaseReturns503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := invokeGuardianEvents(&Handler{}, url.Values{
		"start": {time.Now().Add(-time.Hour).Format(time.RFC3339Nano)},
		"end":   {time.Now().Format(time.RFC3339Nano)},
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
