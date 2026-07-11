package promptfilter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestReviewTextAllowsWhenNotFlagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "omni-moderation-latest",
			"results": []map[string]any{
				{"flagged": false},
			},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	flagged, model, err := client.ReviewText(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "test-key",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	}, "/v1/responses")
	if err != nil {
		t.Fatalf("ReviewText returned error: %v", err)
	}
	if flagged {
		t.Fatal("flagged = true, want false")
	}
	if model != "omni-moderation-latest" {
		t.Fatalf("model = %q, want omni-moderation-latest", model)
	}
}

func TestReviewTextReturnsErrorWhenResultsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"omni-moderation-latest","results":[]}`))
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	_, _, err := client.ReviewText(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "test-key",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	}, "/v1/responses")
	if err == nil {
		t.Fatal("ReviewText returned nil error, want missing results error")
	}
}

func TestReviewTextDetailedAggregatesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(reviewResponse{
			Model: "omni-detailed",
			Results: []reviewResult{
				{
					Flagged:        false,
					Categories:     map[string]bool{"illicit": true, "hate": false},
					CategoryScores: map[string]float64{"illicit": 0.2, "hate": 0.8},
				},
				{
					Flagged:        true,
					Categories:     map[string]bool{"illicit": false, "hate": true, "future-category": true},
					CategoryScores: map[string]float64{"illicit": 0.7, "hate": 0.3, "future-category": 0.4},
				},
			},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	outcome, err := client.ReviewTextDetailed(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "test-key",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	})
	if err != nil {
		t.Fatalf("ReviewTextDetailed returned error: %v", err)
	}
	if outcome.Model != "omni-detailed" {
		t.Fatalf("model = %q, want omni-detailed", outcome.Model)
	}
	if !outcome.Flagged {
		t.Fatal("flagged = false, want OR-aggregated true")
	}
	for _, category := range []string{"illicit", "hate", "future-category"} {
		if !outcome.Categories[category] {
			t.Fatalf("category %q = false, want OR-aggregated true; categories=%v", category, outcome.Categories)
		}
	}
	if got := outcome.CategoryScores["illicit"]; got != 0.7 {
		t.Fatalf("illicit score = %v, want max 0.7", got)
	}
	if got := outcome.CategoryScores["hate"]; got != 0.8 {
		t.Fatalf("hate score = %v, want max 0.8", got)
	}
	if !outcome.FlaggedForEndpoint("/v1/responses") {
		t.Fatal("text endpoint flagged = false, want raw aggregate flag")
	}
	if !outcome.FlaggedForEndpoint("/v1/images/generations") {
		t.Fatal("image endpoint flagged = false, want illicit image policy block")
	}
}

func TestReviewTextDetailedPreservesPerResultImageFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(reviewResponse{
			Model: "omni-moderation-latest",
			Results: []reviewResult{
				// A non-standard result with no category metadata must retain the
				// legacy raw-flag fallback even if a later result has maps.
				{Flagged: true},
				{
					Flagged:        false,
					Categories:     map[string]bool{"violence": true},
					CategoryScores: map[string]float64{"violence": 0.9},
				},
			},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	outcome, err := client.ReviewTextDetailed(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "test-key",
		BaseURL:        server.URL,
		TimeoutSeconds: 2,
	})
	if err != nil {
		t.Fatalf("ReviewTextDetailed returned error: %v", err)
	}
	if !outcome.FlaggedForEndpoint("/v1/images/generations") {
		t.Fatal("image endpoint flagged = false, want per-result fallback to preserve true")
	}
}

func TestReviewTextDetailedFailsOverWithCategories(t *testing.T) {
	reviewKeyCursor.Store(0)
	t.Cleanup(func() { reviewKeyCursor.Store(0) })

	var mu sync.Mutex
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		seen[key]++
		mu.Unlock()
		if key == "bad" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(reviewResponse{
			Model: "omni-failover",
			Results: []reviewResult{{
				Flagged:        true,
				Categories:     map[string]bool{"illicit": true},
				CategoryScores: map[string]float64{"illicit": 0.93},
			}},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	outcome, err := client.ReviewTextDetailed(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "bad\ngood",
		BaseURL:        server.URL,
		TimeoutSeconds: 2,
	})
	if err != nil {
		t.Fatalf("ReviewTextDetailed returned error: %v", err)
	}
	if outcome.Model != "omni-failover" || !outcome.Flagged || !outcome.Categories["illicit"] || outcome.CategoryScores["illicit"] != 0.93 {
		t.Fatalf("unexpected failover outcome: %+v", outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["bad"] != 1 || seen["good"] != 1 {
		t.Fatalf("expected deterministic bad->good failover, seen=%v", seen)
	}
}

func TestReviewTextImagePolicyRegression(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		result   reviewResult
		want     bool
	}{
		{
			name:     "non-standard raw flag fallback",
			endpoint: "/v1/images/generations",
			result:   reviewResult{Flagged: true},
			want:     true,
		},
		{
			name:     "sexual minors score threshold",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				CategoryScores: map[string]float64{"sexual/minors": 0.15},
			},
			want: true,
		},
		{
			name:     "adult sexual category",
			endpoint: "/v1/images/edits",
			result: reviewResult{
				Categories: map[string]bool{"sexual": true},
			},
			want: true,
		},
		{
			name:     "illicit score threshold",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				CategoryScores: map[string]float64{"illicit": 0.5},
			},
			want: true,
		},
		{
			name:     "illicit violent score threshold",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				CategoryScores: map[string]float64{"illicit/violent": 0.5},
			},
			want: true,
		},
		{
			name:     "hate category",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				Categories: map[string]bool{"hate": true},
			},
			want: true,
		},
		{
			name:     "harassment threatening category",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				Categories: map[string]bool{"harassment/threatening": true},
			},
			want: true,
		},
		{
			name:     "violence and self-harm remain allowed for images",
			endpoint: "/v1/images/generations",
			result: reviewResult{
				Flagged:        true,
				Categories:     map[string]bool{"violence": true, "self-harm": true},
				CategoryScores: map[string]float64{"violence": 0.99, "self-harm": 0.99},
			},
			want: false,
		},
		{
			name:     "text endpoint retains provider aggregate flag",
			endpoint: "/v1/responses",
			result: reviewResult{
				Flagged:        true,
				Categories:     map[string]bool{"violence": true},
				CategoryScores: map[string]float64{"violence": 0.99},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(reviewResponse{
					Model:   "omni-moderation-latest",
					Results: []reviewResult{tt.result},
				})
			}))
			defer server.Close()

			client := ReviewClient{HTTPClient: server.Client()}
			flagged, _, err := client.ReviewText(context.Background(), "hello", ReviewConfig{
				Enabled:        true,
				APIKey:         "test-key",
				BaseURL:        server.URL,
				TimeoutSeconds: 2,
			}, tt.endpoint)
			if err != nil {
				t.Fatalf("ReviewText returned error: %v", err)
			}
			if flagged != tt.want {
				t.Fatalf("flagged = %v, want %v", flagged, tt.want)
			}
		})
	}
}

func TestApplyReviewResultClearsLocalBlockWhenCleared(t *testing.T) {
	verdict := Verdict{Action: ActionBlock, Reason: "local block"}
	got := ApplyReviewResult(verdict, false, "omni-moderation-latest", nil, ReviewConfig{FailClosed: true, Model: "omni-moderation-latest"})
	if got.Action != ActionAllow {
		t.Fatalf("action = %s, want allow", got.Action)
	}
	if !got.Reviewed || got.ReviewFlagged {
		t.Fatalf("review metadata = %+v, want reviewed and not flagged", got)
	}
}

func TestApplyReviewResultBlocksWhenReviewFailsClosed(t *testing.T) {
	verdict := Verdict{Action: ActionAllow}
	got := ApplyReviewResult(verdict, false, "omni-moderation-latest", context.DeadlineExceeded, ReviewConfig{FailClosed: true, Model: "omni-moderation-latest"})
	if got.Action != ActionBlock {
		t.Fatalf("action = %s, want block", got.Action)
	}
	if got.ReviewError == "" {
		t.Fatal("expected review_error to be recorded")
	}
}

func TestApplyReviewResultAllowsWhenReviewFailsOpen(t *testing.T) {
	verdict := Verdict{Action: ActionBlock}
	got := ApplyReviewResult(verdict, false, "omni-moderation-latest", context.DeadlineExceeded, ReviewConfig{FailClosed: false, Model: "omni-moderation-latest"})
	if got.Action != ActionAllow {
		t.Fatalf("action = %s, want allow", got.Action)
	}
	if got.ReviewError == "" {
		t.Fatal("expected review_error to be recorded")
	}
}

func TestApplyReviewResultBlocksHighRiskWhenReviewFailsOpen(t *testing.T) {
	verdict := Verdict{Action: ActionBlock, Score: HighRiskReviewFailureScore}
	got := ApplyReviewResult(verdict, false, "omni-moderation-latest", context.DeadlineExceeded, ReviewConfig{FailClosed: false, Model: "omni-moderation-latest"})
	if got.Action != ActionBlock {
		t.Fatalf("action = %s, want block", got.Action)
	}
	if got.ReviewError == "" {
		t.Fatal("expected review_error to be recorded")
	}
	if !strings.Contains(got.Reason, "high-risk") {
		t.Fatalf("reason = %q, want high-risk marker", got.Reason)
	}
}

func TestApplyReviewResultBlocksStrictMatchWhenReviewFailsOpen(t *testing.T) {
	verdict := Verdict{Action: ActionBlock, Matched: []Match{{Name: "credential_theft", Strict: true}}}
	got := ApplyReviewResult(verdict, false, "omni-moderation-latest", context.DeadlineExceeded, ReviewConfig{FailClosed: false, Model: "omni-moderation-latest"})
	if got.Action != ActionBlock {
		t.Fatalf("action = %s, want block", got.Action)
	}
}

func TestParseReviewAPIKeys(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"single", "sk-1", []string{"sk-1"}},
		{"newline separated", "sk-1\nsk-2\nsk-3", []string{"sk-1", "sk-2", "sk-3"}},
		{"comma and spaces", "sk-1, sk-2 ,sk-3", []string{"sk-1", "sk-2", "sk-3"}},
		{"dedupe and blanks", "sk-1\n\nsk-1\nsk-2\n  ", []string{"sk-1", "sk-2"}},
		{"empty", "   ", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseReviewAPIKeys(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("parseReviewAPIKeys(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseReviewAPIKeys(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestReviewTextFailsOverToNextKeyOn429(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		seen[key]++
		mu.Unlock()
		if key != "good" {
			// 模拟低等级账号 TPM 限流。
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "omni-moderation-latest",
			"results": []map[string]any{{"flagged": false}},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	flagged, _, err := client.ReviewText(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "bad1\nbad2\ngood",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	}, "/v1/responses")
	if err != nil {
		t.Fatalf("ReviewText returned error: %v", err)
	}
	if flagged {
		t.Fatal("flagged = true, want false")
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["good"] == 0 {
		t.Fatalf("expected failover to reach the good key, seen=%v", seen)
	}
}

func TestReviewTextReturnsErrorWhenAllKeysRateLimited(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		seen[key]++
		mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	_, _, err := client.ReviewText(context.Background(), "hello", ReviewConfig{
		Enabled:        true,
		APIKey:         "k1\nk2",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	}, "/v1/responses")
	if err == nil {
		t.Fatal("ReviewText returned nil error, want error after all keys rate limited")
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["k1"] == 0 || seen["k2"] == 0 {
		t.Fatalf("expected both keys to be tried, seen=%v", seen)
	}
}

func TestReviewTextRoundRobinsAcrossKeys(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		seen[key]++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "omni-moderation-latest",
			"results": []map[string]any{{"flagged": false}},
		})
	}))
	defer server.Close()

	client := ReviewClient{HTTPClient: server.Client()}
	cfg := ReviewConfig{
		Enabled:        true,
		APIKey:         "ka\nkb\nkc",
		BaseURL:        server.URL,
		Model:          "omni-moderation-latest",
		TimeoutSeconds: 2,
	}
	// 连续多次请求应把成功请求分摊到全部 key 上。
	for i := 0; i < 9; i++ {
		if _, _, err := client.ReviewText(context.Background(), "hello", cfg, "/v1/responses"); err != nil {
			t.Fatalf("ReviewText #%d error: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, key := range []string{"ka", "kb", "kc"} {
		if seen[key] == 0 {
			t.Fatalf("key %q never used, seen=%v", key, seen)
		}
	}
}
