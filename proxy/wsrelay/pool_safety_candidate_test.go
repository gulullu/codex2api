package wsrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

func candidateSafeIdentity(manager *Manager, accountID int64, owner string, headers http.Header) safeConnectionIdentity {
	decision, generation := manager.admitSafePoolOwner(accountID, owner, safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 10000, valid: true})
	if !decision.admitted() || generation == 0 {
		panic("test safe-pool owner admission failed")
	}
	return safeConnectionIdentity{
		ownerKey:             owner,
		handshakeFingerprint: safePoolHeaderFingerprint(headers),
		generation:           generation,
	}
}

// A reused physical socket must never forward a second response identity into
// the current logical request. The current implementation forwards the frame
// before noticing anything because it has no response identity guard.
func TestCandidateRejectsResponseIdentityMismatchBeforeForwarding(t *testing.T) {
	r := &WsResponse{safePool: true}
	forwarded := 0
	callback := func([]byte) bool {
		forwarded++
		return true
	}

	if err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":0,"response":{"id":"resp_A"}}`), callback); err != nil {
		t.Fatalf("first response.created: %v", err)
	}
	err := r.handleMessage([]byte(`{"type":"response.output_text.delta","sequence_number":1,"response_id":"resp_B","delta":"must-not-leak"}`), callback)
	if err == nil {
		t.Fatal("mismatched response identity was accepted")
	}
	if forwarded != 1 {
		t.Fatalf("forwarded frames = %d, want only the first identity", forwarded)
	}
	r.mu.Lock()
	broken := r.connBroken
	r.mu.Unlock()
	if !broken {
		t.Fatal("response identity mismatch did not poison the connection")
	}
}

func TestSafePoolValidatesOfficialItemAndContentGraph(t *testing.T) {
	r := &WsResponse{safePool: true}
	frames := []string{
		`{"type":"response.created","sequence_number":37,"response":{"id":"resp_graph"}}`,
		`{"type":"response.output_item.added","sequence_number":38,"output_index":0,"item":{"id":"msg_1","type":"message"}}`,
		`{"type":"response.content_part.added","sequence_number":39,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text"}}`,
		`{"type":"response.output_text.delta","sequence_number":40,"item_id":"msg_1","output_index":0,"content_index":0,"delta":"ok"}`,
		`{"type":"response.content_part.done","sequence_number":41,"item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text"}}`,
		`{"type":"response.output_item.done","sequence_number":42,"output_index":0,"item":{"id":"msg_1","type":"message"}}`,
		`{"type":"response.completed","sequence_number":43,"response":{"id":"resp_graph","status":"completed"}}`,
	}
	forwarded := 0
	for i, frame := range frames {
		err := r.handleMessage([]byte(frame), func([]byte) bool {
			forwarded++
			return true
		})
		if i == len(frames)-1 {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("terminal error = %v, want io.EOF", err)
			}
		} else if err != nil {
			t.Fatalf("frame %d rejected: %v", i, err)
		}
	}
	if forwarded != len(frames) {
		t.Fatalf("forwarded frames = %d, want %d", forwarded, len(frames))
	}
}

func TestSafePoolAcceptsOfficialPreCreatedRateLimits(t *testing.T) {
	r := &WsResponse{safePool: true}
	var forwarded []string
	callback := func(frame []byte) bool {
		forwarded = append(forwarded, string(frame))
		return true
	}

	frames := []string{
		`{"type":"codex.rate_limits","plan_type":"plus","rate_limits":{"allowed":true}}`,
		`{"type":"response.created","sequence_number":37,"response":{"id":"resp_rate"}}`,
		`{"type":"response.completed","sequence_number":38,"response":{"id":"resp_rate","status":"completed"}}`,
	}
	for i, frame := range frames {
		err := r.handleMessage([]byte(frame), callback)
		if i == len(frames)-1 {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("terminal error = %v, want io.EOF", err)
			}
		} else if err != nil {
			t.Fatalf("official frame %d rejected: %v", i, err)
		}
	}
	if len(forwarded) != len(frames) {
		t.Fatalf("forwarded frames = %d, want %d", len(forwarded), len(frames))
	}
}

func TestSafePoolBuffersOfficialTurnStateUntilCreated(t *testing.T) {
	r := &WsResponse{safePool: true}
	metadata := `{"type":"response.metadata","headers":{"x-codex-turn-state":"ts-1"}}`
	created := `{"type":"response.created","sequence_number":11,"response":{"id":"resp_meta"}}`
	var forwarded []string
	callback := func(frame []byte) bool {
		forwarded = append(forwarded, string(frame))
		return true
	}

	if err := r.handleMessage([]byte(metadata), callback); err != nil {
		t.Fatalf("metadata prelude: %v", err)
	}
	if len(forwarded) != 0 {
		t.Fatalf("metadata escaped before created: %q", forwarded)
	}
	if err := r.handleMessage([]byte(created), callback); err != nil {
		t.Fatalf("created: %v", err)
	}
	if len(forwarded) != 2 || forwarded[0] != metadata || forwarded[1] != created {
		t.Fatalf("forwarded order = %#v, want metadata then created", forwarded)
	}
}

func TestSafePoolMetadataAndTimingPhaseRules(t *testing.T) {
	for _, tt := range []struct {
		name  string
		frame string
	}{
		{"prelude metadata with negative sequence", `{"type":"response.metadata","sequence_number":-1}`},
		{"output before created", `{"type":"response.output_text.delta","item_id":"old","output_index":0,"content_index":0,"delta":"leak"}`},
		{"terminal before created", `{"type":"response.completed","response":{"id":"old","status":"completed"}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &WsResponse{safePool: true}
			forwarded := 0
			err := r.handleMessage([]byte(tt.frame), func([]byte) bool { forwarded++; return true })
			if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
				t.Fatalf("error = %v, want isolation violation", err)
			}
			if forwarded != 0 {
				t.Fatalf("invalid prelude reached callback %d times", forwarded)
			}
		})
	}

	t.Run("prelude controls buffer and matching id flushes", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		var forwarded []string
		callback := func(frame []byte) bool { forwarded = append(forwarded, string(frame)); return true }
		for _, frame := range []string{
			`{"type":"response.metadata","response_id":"resp_match","sequence_number":7,"metadata":{"ok":true}}`,
			`{"type":"codex.rate_limits","plan_type":"plus"}`,
			`{"type":"codex.response.metadata","headers":{"x-codex-safety-buffering-enabled":"true"}}`,
			`{"type":"responsesapi.websocket_timing","elapsed_ms":1}`,
		} {
			if err := r.handleMessage([]byte(frame), callback); err != nil {
				t.Fatalf("prelude %s: %v", frame, err)
			}
		}
		if len(forwarded) != 0 {
			t.Fatalf("controls escaped before created: %#v", forwarded)
		}
		if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_match"}}`), callback); err != nil {
			t.Fatalf("matching created: %v", err)
		}
		if len(forwarded) != 5 {
			t.Fatalf("forwarded = %d, want four preludes plus created", len(forwarded))
		}
	})

	t.Run("prelude response id mismatch rejected before callback", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		if err := r.handleMessage([]byte(`{"type":"response.metadata","response_id":"resp_A"}`), func([]byte) bool { forwarded++; return true }); err != nil {
			t.Fatalf("metadata: %v", err)
		}
		err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_B"}}`), func([]byte) bool { forwarded++; return true })
		if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 0 {
			t.Fatalf("mismatch err=%v forwarded=%d", err, forwarded)
		}
	})

	t.Run("prelude item ownership rejected before buffering", func(t *testing.T) {
		for _, frame := range []string{
			`{"type":"codex.rate_limits","item_id":"old_item"}`,
			`{"type":"response.metadata","item":{"id":"old_item"}}`,
		} {
			r := &WsResponse{safePool: true}
			forwarded := 0
			err := r.handleMessage([]byte(frame), func([]byte) bool { forwarded++; return true })
			if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 0 || len(r.preludeFrames) != 0 {
				t.Fatalf("frame=%s err=%v forwarded=%d buffered=%d", frame, err, forwarded, len(r.preludeFrames))
			}
		}
	})

	t.Run("active unowned controls accepted", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		if err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":7,"response":{"id":"resp_active"}}`), callback); err != nil {
			t.Fatalf("created: %v", err)
		}
		for _, frame := range []string{
			`{"type":"response.metadata","headers":{"x-codex-turn-state":"late"}}`,
			`{"type":"codex.response.metadata","headers":{"x-codex-safety-buffering-enabled":"true"}}`,
			`{"type":"responsesapi.websocket_timing","elapsed_ms":2}`,
			`{"type":"codex.rate_limits","limits":[]}`,
		} {
			if err := r.handleMessage([]byte(frame), callback); err != nil {
				t.Fatalf("active control %s: %v", frame, err)
			}
		}
		if forwarded != 5 {
			t.Fatalf("active control forwarded=%d, want 5 including created", forwarded)
		}
	})

	t.Run("active control cannot claim old response or item", func(t *testing.T) {
		for _, frame := range []string{
			`{"type":"codex.rate_limits","response_id":"resp_old"}`,
			`{"type":"codex.rate_limits","item_id":"old_item"}`,
			`{"type":"response.metadata","item":{"id":"old_item"}}`,
		} {
			r := &WsResponse{safePool: true}
			forwarded := 0
			callback := func([]byte) bool { forwarded++; return true }
			if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_active"}}`), callback); err != nil {
				t.Fatalf("created: %v", err)
			}
			err := r.handleMessage([]byte(frame), callback)
			if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 1 {
				t.Fatalf("frame=%s err=%v forwarded=%d, want isolation before callback", frame, err, forwarded)
			}
		}
	})

	t.Run("active owned metadata and timing accepted", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		frames := []string{
			`{"type":"response.created","sequence_number":20,"response":{"id":"resp_active"}}`,
			`{"type":"response.metadata","sequence_number":22,"response_id":"resp_active","metadata":{"ok":true}}`,
			`{"type":"responsesapi.websocket_timing","elapsed_ms":2}`,
			`{"type":"response.completed","sequence_number":24,"response":{"id":"resp_active","status":"completed"}}`,
		}
		for i, frame := range frames {
			err := r.handleMessage([]byte(frame), callback)
			if i == len(frames)-1 {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("terminal error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("frame %d rejected: %v", i, err)
			}
		}
		if forwarded != len(frames) {
			t.Fatalf("forwarded = %d, want %d", forwarded, len(frames))
		}
	})
}

func TestSafePoolPreludeBoundsAndFlushFailure(t *testing.T) {
	t.Run("frame bound", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		for i := 0; i < safePoolMaxPreludeFrames; i++ {
			frame := fmt.Sprintf(`{"type":"response.metadata","headers":{"x-codex-turn-state":"ts-%d"}}`, i)
			if err := r.handleMessage([]byte(frame), func([]byte) bool { return true }); err != nil {
				t.Fatalf("metadata %d: %v", i, err)
			}
		}
		err := r.handleMessage([]byte(`{"type":"response.metadata","headers":{"x-codex-turn-state":"overflow"}}`), func([]byte) bool { return true })
		if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
			t.Fatalf("overflow error = %v, want isolation violation", err)
		}
	})

	t.Run("downstream stops during flush", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		if err := r.handleMessage([]byte(`{"type":"response.metadata","headers":{"x-codex-turn-state":"ts"}}`), func([]byte) bool { return true }); err != nil {
			t.Fatalf("metadata: %v", err)
		}
		calls := 0
		err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":1,"response":{"id":"resp_flush"}}`), func([]byte) bool {
			calls++
			return false
		})
		if !errors.Is(err, io.EOF) || calls != 1 {
			t.Fatalf("flush error=%v calls=%d, want io.EOF after first buffered frame", err, calls)
		}
		r.mu.Lock()
		broken := r.connBroken
		r.mu.Unlock()
		if !broken || len(r.preludeFrames) != 0 || r.preludeBytes != 0 {
			t.Fatalf("flush failure did not poison and clear response: broken=%v frames=%d bytes=%d", broken, len(r.preludeFrames), r.preludeBytes)
		}
	})
}

func TestSafePoolSequenceIsOptionalButMonotonicWhenPresent(t *testing.T) {
	t.Run("official lifecycle without sequence", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		frames := []string{
			`{"type":"response.created","response":{"id":"resp_no_seq"}}`,
			`{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_no_seq","type":"message"}}`,
			`{"type":"response.content_part.added","item_id":"msg_no_seq","output_index":0,"content_index":0,"part":{"type":"output_text"}}`,
			`{"type":"response.output_text.delta","item_id":"msg_no_seq","output_index":0,"content_index":0,"delta":"ok"}`,
			`{"type":"response.completed","response":{"id":"resp_no_seq","status":"completed"}}`,
		}
		for i, frame := range frames {
			err := r.handleMessage([]byte(frame), func([]byte) bool { return true })
			if i == len(frames)-1 {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("terminal error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("unsequenced frame %d rejected: %v", i, err)
			}
		}
	})

	t.Run("gaps and unsequenced controls do not break ordering", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		frames := []string{
			`{"type":"response.created","sequence_number":37,"response":{"id":"resp_gap"}}`,
			`{"type":"response.metadata","headers":{"x-codex-turn-state":"ts"}}`,
			`{"type":"response.completed","sequence_number":39,"response":{"id":"resp_gap","status":"completed"}}`,
		}
		for i, frame := range frames {
			err := r.handleMessage([]byte(frame), func([]byte) bool { return true })
			if i == len(frames)-1 {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("terminal error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("frame %d rejected: %v", i, err)
			}
		}
	})

	t.Run("non-advancing sequence rejected", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		if err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":39,"response":{"id":"resp_back"}}`), callback); err != nil {
			t.Fatalf("created: %v", err)
		}
		err := r.handleMessage([]byte(`{"type":"response.completed","sequence_number":38,"response":{"id":"resp_back","status":"completed"}}`), callback)
		if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 1 {
			t.Fatalf("out-of-order err=%v forwarded=%d", err, forwarded)
		}
	})
}

func TestSafePoolAcceptsDoneOnlyEventsWithCompletePublicIdentity(t *testing.T) {
	r := &WsResponse{safePool: true}
	frames := []string{
		`{"type":"response.created","response":{"id":"resp_done_only"}}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_done_only","type":"message"}}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"msg_part_only","type":"message"}}`,
		`{"type":"response.content_part.done","item_id":"msg_part_only","output_index":1,"content_index":0,"part":{"type":"output_text"}}`,
		`{"type":"response.output_text.delta","item_id":"msg_part_only","output_index":1,"content_index":0,"delta":"ok"}`,
		`{"type":"response.completed","response":{"id":"resp_done_only","status":"completed"}}`,
	}
	for i, frame := range frames {
		err := r.handleMessage([]byte(frame), func([]byte) bool { return true })
		if i == len(frames)-1 {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("terminal error = %v", err)
			}
		} else if err != nil {
			t.Fatalf("done-only frame %d rejected: %v", i, err)
		}
	}
}

func TestSafePoolCallIDOwnershipSupportsOfficialToolDeltas(t *testing.T) {
	t.Run("known call id may omit item and output index", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		frames := []string{
			`{"type":"response.created","response":{"id":"resp_tool"}}`,
			`{"type":"response.output_item.added","output_index":0,"item":{"id":"ct_1","type":"custom_tool_call","call_id":"call_1"}}`,
			`{"type":"response.custom_tool_call_input.delta","call_id":"call_1","delta":"arg"}`,
			`{"type":"response.completed","response":{"id":"resp_tool","status":"completed"}}`,
		}
		for i, frame := range frames {
			err := r.handleMessage([]byte(frame), func([]byte) bool { return true })
			if i == len(frames)-1 {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("terminal error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("tool frame %d rejected: %v", i, err)
			}
		}
	})

	t.Run("unknown call id is compatibility not isolation", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_unknown_call"}}`), callback); err != nil {
			t.Fatalf("created: %v", err)
		}
		err := r.handleMessage([]byte(`{"type":"response.custom_tool_call_input.delta","call_id":"missing","delta":"arg"}`), callback)
		if !errors.Is(err, proxy.ErrWebsocketReadUncertain) || errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 1 {
			t.Fatalf("unknown call err=%v forwarded=%d", err, forwarded)
		}
	})

	t.Run("call id cannot move between items", func(t *testing.T) {
		r := &WsResponse{safePool: true}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		for _, frame := range []string{
			`{"type":"response.created","response":{"id":"resp_call_conflict"}}`,
			`{"type":"response.output_item.added","output_index":0,"item":{"id":"ct_A","type":"custom_tool_call","call_id":"call_same"}}`,
		} {
			if err := r.handleMessage([]byte(frame), callback); err != nil {
				t.Fatalf("setup: %v", err)
			}
		}
		err := r.handleMessage([]byte(`{"type":"response.output_item.added","output_index":1,"item":{"id":"ct_B","type":"custom_tool_call","call_id":"call_same"}}`), callback)
		if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) || forwarded != 2 {
			t.Fatalf("call conflict err=%v forwarded=%d", err, forwarded)
		}
	})
}

func TestSafePoolMissingIdentityIsCompatibilityButProvidedConflictIsIsolation(t *testing.T) {
	t.Run("missing public identity downgrades without isolation alarm", func(t *testing.T) {
		manager := NewManager()
		t.Cleanup(manager.Stop)
		account := &auth.Account{DBID: 9020, Name: "compat-account", Tags: []string{safePoolAccountTag}}
		conn, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "compat-owner")
		conn.safeReusable.Store(true)
		r := &WsResponse{safePool: true, conn: conn, manager: manager}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_compat"}}`), callback); err != nil {
			t.Fatalf("created: %v", err)
		}
		err := r.handleMessage([]byte(`{"type":"response.output_text.delta","delta":"shape changed"}`), callback)
		if !errors.Is(err, proxy.ErrWebsocketReadUncertain) {
			t.Fatalf("missing identity error = %v, want read-uncertain compatibility downgrade", err)
		}
		metrics := manager.SafePoolMetricsSnapshot()
		if metrics.CompatibilityFallbacks != 1 || metrics.FuseTrips != 0 || forwarded != 1 {
			t.Fatalf("compat metrics=%+v forwarded=%d", metrics, forwarded)
		}
	})

	t.Run("provided unknown identity is a hard isolation violation", func(t *testing.T) {
		manager := NewManager()
		t.Cleanup(manager.Stop)
		account := &auth.Account{DBID: 9021, Name: "isolation-account", Tags: []string{safePoolAccountTag}}
		conn, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "isolation-owner")
		conn.safeReusable.Store(true)
		r := &WsResponse{safePool: true, conn: conn, manager: manager}
		forwarded := 0
		callback := func([]byte) bool { forwarded++; return true }
		if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_isolation"}}`), callback); err != nil {
			t.Fatalf("created: %v", err)
		}
		err := r.handleMessage([]byte(`{"type":"response.output_text.delta","item_id":"old_item","output_index":0,"content_index":0,"delta":"leak"}`), callback)
		if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
			t.Fatalf("provided conflict error = %v, want isolation violation", err)
		}
		metrics := manager.SafePoolMetricsSnapshot()
		if metrics.FuseTrips != 1 || metrics.CompatibilityFallbacks != 0 || forwarded != 1 {
			t.Fatalf("isolation metrics=%+v forwarded=%d", metrics, forwarded)
		}
	})
}

func TestSafePoolUnknownUnscopedExtensionIsDroppedAndCompatibilityFused(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 9025, Name: "extension-account", Tags: []string{safePoolAccountTag}}
	conn, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "extension-owner")
	conn.safeReusable.Store(true)
	pending := conn.session.AddPendingRequest("extension-owner")
	r := &WsResponse{safePool: true, conn: conn, manager: manager, pendingReq: pending, sessionID: "extension-owner"}
	forwarded := 0
	callback := func([]byte) bool { forwarded++; return true }

	if err := r.handleMessage([]byte(`{"type":"codex.future_control","value":1}`), callback); err != nil {
		t.Fatalf("unknown extension should be safely dropped: %v", err)
	}
	if forwarded != 0 || !conn.retireAfterLease.Load() {
		t.Fatalf("unknown extension forwarded=%d retired=%v", forwarded, conn.retireAfterLease.Load())
	}
	if err := r.handleMessage([]byte(`{"type":"response.created","response":{"id":"resp_extension"}}`), callback); err != nil {
		t.Fatalf("created after dropped extension: %v", err)
	}
	if err := r.handleMessage([]byte(`{"type":"response.completed","response":{"id":"resp_extension","status":"completed"}}`), callback); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal after dropped extension: %v", err)
	}
	metrics := manager.SafePoolMetricsSnapshot()
	if metrics.CompatibilityDrops != 1 || metrics.CompatibilityFallbacks != 1 || metrics.FuseTrips != 0 || !manager.IsSafePoolFused(account.ID()) {
		t.Fatalf("unknown extension fallback metrics=%+v fused=%v, want one compatibility drop/fallback without hard isolation trip", metrics, manager.IsSafePoolFused(account.ID()))
	}
}

func TestSafePoolCompatibilityFuseUpgradesOneWayToIsolation(t *testing.T) {
	t.Run("compatibility then hard", func(t *testing.T) {
		manager := NewManager()
		t.Cleanup(manager.Stop)
		manager.TripSafePoolCompatibilityFuse(9030, errors.New("compat"))
		manager.TripSafePoolFuse(9030, errors.New("hard"))
		manager.TripSafePoolCompatibilityFuse(9030, errors.New("late compat"))
		manager.TripSafePoolFuse(9030, errors.New("duplicate hard"))
		stored, ok := manager.safePoolFuses.Load(int64(9030))
		state, typed := stored.(safePoolFuseState)
		if !ok || !typed || state.compatibility || !strings.Contains(state.reason, "hard") {
			t.Fatalf("final fuse state = %#v", stored)
		}
		metrics := manager.SafePoolMetricsSnapshot()
		if metrics.CompatibilityFallbacks != 1 || metrics.FuseTrips != 1 {
			t.Fatalf("one-way upgrade metrics = %+v", metrics)
		}
	})

	t.Run("hard then compatibility stays hard", func(t *testing.T) {
		manager := NewManager()
		t.Cleanup(manager.Stop)
		manager.TripSafePoolFuse(9031, errors.New("hard first"))
		manager.TripSafePoolCompatibilityFuse(9031, errors.New("compat later"))
		stored, _ := manager.safePoolFuses.Load(int64(9031))
		state := stored.(safePoolFuseState)
		if state.compatibility || !strings.Contains(state.reason, "hard first") {
			t.Fatalf("hard fuse was overwritten: %#v", state)
		}
		metrics := manager.SafePoolMetricsSnapshot()
		if metrics.FuseTrips != 1 || metrics.CompatibilityFallbacks != 0 {
			t.Fatalf("hard-first metrics = %+v", metrics)
		}
	})

	t.Run("concurrent attempts end hard and remain idempotent", func(t *testing.T) {
		manager := NewManager()
		t.Cleanup(manager.Stop)
		start := make(chan struct{})
		done := make(chan struct{}, 64)
		for i := 0; i < 64; i++ {
			go func(hard bool) {
				<-start
				if hard {
					manager.TripSafePoolFuse(9032, errors.New("hard concurrent"))
				} else {
					manager.TripSafePoolCompatibilityFuse(9032, errors.New("compat concurrent"))
				}
				done <- struct{}{}
			}(i%2 == 0)
		}
		close(start)
		for i := 0; i < 64; i++ {
			<-done
		}
		stored, _ := manager.safePoolFuses.Load(int64(9032))
		state := stored.(safePoolFuseState)
		if state.compatibility {
			t.Fatalf("concurrent final state stayed compatibility: %#v", state)
		}
		metrics := manager.SafePoolMetricsSnapshot()
		if metrics.FuseTrips != 1 || metrics.CompatibilityFallbacks > 1 {
			t.Fatalf("concurrent metrics = %+v", metrics)
		}
	})
}

func TestSafePoolReasoningDeltaUsesItemOwnershipWithoutInventedPartLifecycle(t *testing.T) {
	r := &WsResponse{safePool: true}
	frames := []string{
		`{"type":"response.created","sequence_number":70,"response":{"id":"resp_reasoning"}}`,
		`{"type":"response.output_item.added","sequence_number":71,"output_index":0,"item":{"id":"rs_1","type":"reasoning"}}`,
		`{"type":"response.reasoning_text.delta","sequence_number":72,"item_id":"rs_1","output_index":0,"content_index":0,"delta":"private"}`,
		`{"type":"response.completed","sequence_number":73,"response":{"id":"resp_reasoning","status":"completed"}}`,
	}
	for i, frame := range frames {
		err := r.handleMessage([]byte(frame), func([]byte) bool { return true })
		if i == len(frames)-1 {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("terminal error = %v, want io.EOF", err)
			}
		} else if err != nil {
			t.Fatalf("reasoning frame %d rejected: %v", i, err)
		}
	}
}

func TestSafePoolRejectsOfficialDeltaWithoutResponseID(t *testing.T) {
	tests := []struct {
		name  string
		setup []string
		bad   string
	}{
		{
			name:  "unknown item",
			setup: []string{`{"type":"response.created","sequence_number":11,"response":{"id":"resp_new"}}`},
			bad:   `{"type":"response.output_text.delta","sequence_number":12,"item_id":"msg_old","output_index":0,"content_index":0,"delta":"LEAK"}`,
		},
		{
			name: "wrong output index",
			setup: []string{
				`{"type":"response.created","sequence_number":20,"response":{"id":"resp_new"}}`,
				`{"type":"response.output_item.added","sequence_number":21,"output_index":0,"item":{"id":"msg_new","type":"message"}}`,
				`{"type":"response.content_part.added","sequence_number":22,"item_id":"msg_new","output_index":0,"content_index":0,"part":{"type":"output_text"}}`,
			},
			bad: `{"type":"response.output_text.delta","sequence_number":23,"item_id":"msg_new","output_index":1,"content_index":0,"delta":"LEAK"}`,
		},
		{
			name: "wrong content index",
			setup: []string{
				`{"type":"response.created","sequence_number":30,"response":{"id":"resp_new"}}`,
				`{"type":"response.output_item.added","sequence_number":31,"output_index":0,"item":{"id":"msg_new","type":"message"}}`,
				`{"type":"response.content_part.added","sequence_number":32,"item_id":"msg_new","output_index":0,"content_index":0,"part":{"type":"output_text"}}`,
			},
			bad: `{"type":"response.output_text.delta","sequence_number":33,"item_id":"msg_new","output_index":0,"content_index":1,"delta":"LEAK"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &WsResponse{safePool: true}
			forwarded := 0
			for _, frame := range tt.setup {
				if err := r.handleMessage([]byte(frame), func([]byte) bool { forwarded++; return true }); err != nil {
					t.Fatalf("setup frame rejected: %v", err)
				}
			}
			before := forwarded
			err := r.handleMessage([]byte(tt.bad), func([]byte) bool { forwarded++; return true })
			if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
				t.Fatalf("bad delta error = %v, want isolation violation", err)
			}
			if forwarded != before {
				t.Fatalf("bad delta reached callback: before=%d after=%d", before, forwarded)
			}
		})
	}
}

func TestSafePoolRejectsStaleCreatedBeyondOldHistoryWindow(t *testing.T) {
	wc := &WsConnection{}
	for i := 0; i < 300; i++ {
		wc.recordRecentResponseID(fmt.Sprintf("resp_old_%d", i))
	}
	r := &WsResponse{safePool: true, conn: wc}
	forwarded := 0
	err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":91,"response":{"id":"resp_old_0"}}`), func([]byte) bool {
		forwarded++
		return true
	})
	if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
		t.Fatalf("stale created error = %v, want isolation violation", err)
	}
	if forwarded != 0 {
		t.Fatalf("stale response.created reached callback %d times", forwarded)
	}
}

func TestSafePoolResponseHistoryRetiresInsteadOfEvicting(t *testing.T) {
	wc := &WsConnection{}
	for i := 0; i < safePoolMaxRecentResponseIDs; i++ {
		wc.recordRecentResponseID(fmt.Sprintf("resp_history_%d", i))
	}
	wc.recordRecentResponseID("resp_overflow")
	if !wc.retireAfterLease.Load() {
		t.Fatal("full response history did not retire the physical socket")
	}
	if got := len(wc.recentResponseIDs); got != safePoolMaxRecentResponseIDs {
		t.Fatalf("response history size = %d, want hard cap %d", got, safePoolMaxRecentResponseIDs)
	}
	if !wc.hasRecentResponseID("resp_history_0") || wc.hasRecentResponseID("resp_overflow") {
		t.Fatal("history cap evicted an old ID or retained an ID beyond the retirement boundary")
	}
}

func TestSafePoolTerminalIdentityTable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		terminal string
		wantErr  error
	}{
		{"valid completed", `{"type":"response.completed","sequence_number":8,"response":{"id":"resp_terminal","status":"completed"}}`, io.EOF},
		{"missing id", `{"type":"response.failed","sequence_number":8,"response":{"status":"failed"}}`, proxy.ErrWebsocketReadUncertain},
		{"wrong id", `{"type":"response.incomplete","sequence_number":8,"response":{"id":"resp_other","status":"incomplete"}}`, proxy.ErrWebsocketIsolationViolation},
		{"status conflict", `{"type":"response.completed","sequence_number":8,"response":{"id":"resp_terminal","status":"failed"}}`, proxy.ErrWebsocketIsolationViolation},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &WsResponse{safePool: true}
			forwarded := 0
			if err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":7,"response":{"id":"resp_terminal"}}`), func([]byte) bool { forwarded++; return true }); err != nil {
				t.Fatalf("created: %v", err)
			}
			err := r.handleMessage([]byte(tt.terminal), func([]byte) bool { forwarded++; return true })
			if tt.wantErr == io.EOF {
				if !errors.Is(err, io.EOF) || forwarded != 2 {
					t.Fatalf("valid terminal err=%v forwarded=%d", err, forwarded)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("invalid terminal error = %v, want %v", err, tt.wantErr)
			}
			if forwarded != 1 {
				t.Fatalf("invalid terminal reached callback: %d", forwarded)
			}
		})
	}
}

func TestSafePoolFuseIsAccountLocalAndIdempotent(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	first := &auth.Account{DBID: 9001, Name: "dynamic-first", Tags: []string{safePoolAccountTag}, DynamicConcurrencyLimit: 100}
	second := &auth.Account{DBID: 9002, Name: "dynamic-second", Tags: []string{safePoolAccountTag}, DynamicConcurrencyLimit: 100}
	manager.TripSafePoolFuse(first.ID(), errors.New("fault one"))
	manager.TripSafePoolFuse(first.ID(), errors.New("fault two"))
	if !manager.IsSafePoolFused(first.ID()) || manager.IsSafePoolFused(second.ID()) {
		t.Fatal("safe-pool fuse crossed account boundary")
	}
	if got := manager.SafePoolMetricsSnapshot().FuseTrips; got != 1 {
		t.Fatalf("FuseTrips = %d, want 1 for idempotent trip", got)
	}
	if first.Name != "dynamic-first" || first.DynamicConcurrencyLimit != 100 || len(first.Tags) != 1 || first.Tags[0] != safePoolAccountTag {
		t.Fatalf("fuse mutated dynamic account state: %+v", first)
	}
}

func TestSafePoolOwnerCapacityDoesNotEvictBoundContinuationSockets(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 9010, Name: "dynamic-pool"}
	const ownerSlots = 32

	connections := make([]*WsConnection, 0, ownerSlots)
	for i := 0; i < ownerSlots; i++ {
		owner := fmt.Sprintf("owner-%02d", i)
		conn, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", owner)
		identity := candidateSafeIdentity(manager, account.ID(), owner, http.Header{})
		conn.safeOwnerKey = identity.ownerKey
		conn.handshakeFingerprint = identity.handshakeFingerprint
		conn.safeGeneration = identity.generation
		conn.safeReusable.Store(true)
		manager.BindResponseConn("resp_"+owner, conn, owner, account.ID(), "key-A")
		connections = append(connections, conn)
	}

	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	admitted := manager.ensureSafePoolAccountCapacity(account.ID(), ownerSlots, "new-owner")
	accountLock.Unlock()
	if !admitted {
		t.Fatal("33rd owner was rejected even though all prior sockets are separately budgeted continuation state")
	}
	for i, conn := range connections {
		responseID := fmt.Sprintf("resp_owner-%02d", i)
		if !conn.IsConnected() {
			t.Fatalf("bound continuation socket %d was evicted by ordinary owner capacity", i)
		}
		if got, _ := manager.lookupResponseConn(responseID, account.ID(), "key-A"); got != conn {
			t.Fatalf("continuation binding %s was lost before continuation budget", responseID)
		}
	}
}

func TestSafePoolSaturationReturnsCapacityWithoutOverflowHandshake(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		handshakes.Add(1)
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4201, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{}
	identity := candidateSafeIdentity(manager, account.ID(), "owner", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner", headers)

	first, pending, _, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 50*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	t.Cleanup(func() {
		if first.session != nil && pending != nil {
			first.session.RemovePendingRequest(pending.RequestID)
		}
		manager.DiscardConnection(first)
	})

	_, _, _, err = manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 25*time.Millisecond, headers, identity, "")
	if !errors.Is(err, proxy.ErrWebsocketLocalCapacity) {
		t.Fatalf("saturated acquire error = %v, want ErrWebsocketLocalCapacity", err)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("physical handshakes = %d, want 1 without overflow socket", got)
	}
}

func TestSafePoolPendingDialsRespectOwnerSlotLimit(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	t.Setenv(safePoolMaxSlotsEnv, "1")
	var handshakes atomic.Int32
	firstHandshake := make(chan struct{})
	releaseHandshake := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHandshake) }) }
	defer release()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if handshakes.Add(1) == 1 {
			close(firstHandshake)
		}
		<-releaseHandshake
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4206, DynamicConcurrencyLimit: 8}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	firstDone := make(chan struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}, 1)
	go func() {
		identity := candidateSafeIdentity(manager, account.ID(), "pending-owner-1", http.Header{})
		baseKey := safePoolOwnedRouteKey("shared", "pending-owner-1", http.Header{})
		wc, pending, _, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 500*time.Millisecond, http.Header{}, identity, "")
		firstDone <- struct {
			wc      *WsConnection
			pending *PendingRequest
			err     error
		}{wc: wc, pending: pending, err: err}
	}()
	select {
	case <-firstHandshake:
	case <-time.After(time.Second):
		t.Fatal("first pending dial did not reach the server")
	}

	secondIdentity := candidateSafeIdentity(manager, account.ID(), "pending-owner-2", http.Header{})
	secondBaseKey := safePoolOwnedRouteKey("shared", "pending-owner-2", http.Header{})
	_, _, _, secondErr := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, secondBaseKey, 1, 35*time.Millisecond, http.Header{}, secondIdentity, "")
	if !errors.Is(secondErr, proxy.ErrWebsocketLocalCapacity) {
		t.Fatalf("second pending owner error = %v, want local capacity", secondErr)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("parallel cold dials = %d, want exactly 1 at a one-owner limit", got)
	}

	release()
	select {
	case result := <-firstDone:
		if result.err != nil {
			t.Fatalf("first pending dial failed: %v", result.err)
		}
		if result.pending != nil && result.wc != nil && result.wc.session != nil {
			result.wc.session.RemovePendingRequest(result.pending.RequestID)
		}
		manager.DiscardConnection(result.wc)
	case <-time.After(2 * time.Second):
		t.Fatal("first pending dial did not finish")
	}
	if pending := manager.safePoolPendingCreateCount(account.ID()); pending != 0 {
		t.Fatalf("safe pending dial reservations leaked: %d", pending)
	}
}

func TestSafePoolKillSwitchDuringDialPreventsPublication(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	handshakeStarted := make(chan struct{})
	releaseHandshake := make(chan struct{})
	var handshakeOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHandshake) }) }
	defer release()
	var requestFrames atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handshakeOnce.Do(func() { close(handshakeStarted) })
		<-releaseHandshake
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			requestFrames.Add(1)
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4207, DynamicConcurrencyLimit: 8}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	identity := candidateSafeIdentity(manager, account.ID(), "dial-kill-owner", http.Header{})
	baseKey := safePoolOwnedRouteKey("shared", "dial-kill-owner", http.Header{})
	resultCh := make(chan error, 1)
	go func() {
		_, _, _, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 2, 500*time.Millisecond, http.Header{}, identity, "")
		resultCh <- err
	}()
	select {
	case <-handshakeStarted:
	case <-time.After(time.Second):
		t.Fatal("safe dial did not start")
	}
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	release()
	select {
	case err := <-resultCh:
		if !errors.Is(err, proxy.ErrWebsocketSafePoolFallback) {
			t.Fatalf("hot-disabled dial error = %v, want typed safe-pool fallback", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hot-disabled dial did not finish")
	}
	if requestFrames.Load() != 0 || manager.ConnectionCount() != 0 || manager.safePoolPendingCreateCount(account.ID()) != 0 {
		t.Fatalf("hot-disabled dial side effects: frames=%d connections=%d pending=%d", requestFrames.Load(), manager.ConnectionCount(), manager.safePoolPendingCreateCount(account.ID()))
	}
}

func TestSafePoolDelayedOldFrameAfterNewLeaseTripsFuseBeforeForward(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		handshakes.Add(1)

		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		for _, frame := range [][]byte{
			[]byte(`{"type":"response.created","sequence_number":0,"response":{"id":"resp_first"}}`),
			[]byte(`{"type":"response.completed","sequence_number":1,"response":{"id":"resp_first"}}`),
		} {
			if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
				return
			}
		}

		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
		// Fault injection: an old response frame arrives only after the next
		// request owns the physical socket. It must never reach request two.
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","sequence_number":2,"response_id":"resp_first","delta":"LEAK"}`)); err != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","sequence_number":0,"response":{"id":"resp_second"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","sequence_number":1,"response":{"id":"resp_second"}}`))
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4202, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{}
	identity := candidateSafeIdentity(manager, account.ID(), "owner", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner", headers)

	wc, firstPending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 200*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first := &WsResponse{conn: wc, pendingReq: firstPending, sessionID: slot, manager: manager, safePool: true, reuseFence: 5 * time.Millisecond}
	if err := first.ReadStream(func([]byte) bool { return true }); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	reused, secondPending, secondSlot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 200*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if reused != wc {
		t.Fatal("test did not exercise the same physical connection")
	}
	if err := reused.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("second write: %v", err)
	}
	forwarded := 0
	second := &WsResponse{conn: reused, pendingReq: secondPending, sessionID: secondSlot, manager: manager, safePool: true, reuseFence: 5 * time.Millisecond}
	err = second.ReadStream(func([]byte) bool {
		forwarded++
		return true
	})
	if !errors.Is(err, proxy.ErrWebsocketIsolationViolation) {
		t.Fatalf("second read error = %v, want isolation violation", err)
	}
	if forwarded != 0 {
		t.Fatalf("forwarded delayed frames = %d, want 0", forwarded)
	}
	if !manager.IsSafePoolFused(account.ID()) {
		t.Fatal("delayed old frame did not trip account-local safe-pool fuse")
	}
	_ = second.Close()
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("physical handshakes = %d, want 1 for the injected reuse race", got)
	}
}

// Turn-scoped state is carried in response.create and must not fragment the
// pool. A genuinely connection-scoped identity change still requires a fresh
// physical connection.
func TestCandidateHandshakeIdentityChangeForcesFreshConnection(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		connectionNumber := handshakes.Add(1)
		requestNumber := 0
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			requestNumber++
			responseID := fmt.Sprintf("resp_%d_%d", connectionNumber, requestNumber)
			frames := [][]byte{
				[]byte(fmt.Sprintf(`{"type":"response.created","sequence_number":0,"response":{"id":%q}}`, responseID)),
				[]byte(fmt.Sprintf(`{"type":"response.completed","sequence_number":1,"response":{"id":%q}}`, responseID)),
			}
			for _, frame := range frames {
				if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	runTurn := func(clientRequestID, turnState string) {
		t.Helper()
		headers := http.Header{
			"X-Client-Request-Id": {clientRequestID},
			"X-Codex-Turn-State":  {turnState},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		stableHeaders := safePoolHandshakeHeaders(headers)
		identity := candidateSafeIdentity(manager, account.ID(), "owner-A", stableHeaders)
		baseKey := safePoolOwnedRouteKey("shared-api-key", "owner-A", stableHeaders)
		wc, pending, slot, err := manager.AcquireSafeReusableConnection(
			ctx,
			account,
			wsURL,
			baseKey,
			1,
			100*time.Millisecond,
			stableHeaders,
			identity,
			"",
		)
		if err != nil {
			t.Fatalf("AcquireReusableConnection(%s/%s): %v", clientRequestID, turnState, err)
		}
		if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
			t.Fatalf("WriteMessage(%s/%s): %v", clientRequestID, turnState, err)
		}
		response := &WsResponse{
			conn:        wc,
			pendingReq:  pending,
			sessionID:   slot,
			manager:     manager,
			apiKey:      "api-key-A",
			readErrChan: make(chan error, 1),
			safePool:    true,
			reuseFence:  10 * time.Millisecond,
		}
		if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
			t.Fatalf("ReadStream(%s/%s): %v", clientRequestID, turnState, err)
		}
		if err := response.Close(); err != nil {
			t.Fatalf("Close(%s/%s): %v", clientRequestID, turnState, err)
		}
	}

	runTurn("thread-A", "turn-A")
	runTurn("thread-A", "turn-B")
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("physical handshakes = %d, want 1 when only turn state changes", got)
	}
	runTurn("thread-B", "turn-C")
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("physical handshakes = %d, want 2 after connection identity changes", got)
	}
}

func TestSafePoolContinuationWaitsForFenceAndPreservesIdentity(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for turn := 1; ; turn++ {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			responseID := fmt.Sprintf("resp_fence_%d", turn)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","sequence_number":0,"response":{"id":%q}}`, responseID))); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","sequence_number":1,"response":{"id":%q,"status":"completed"}}`, responseID))); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4301, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"X-Client-Request-Id": {"thread-A"}}
	identity := candidateSafeIdentity(manager, account.ID(), "owner-A", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner-A", headers)

	wc, pending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 200*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	t.Cleanup(func() { manager.DiscardConnection(wc) })
	if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	response := &WsResponse{conn: wc, pendingReq: pending, sessionID: slot, manager: manager, apiKey: "key-A", safePool: true, reuseFence: 80 * time.Millisecond}
	if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
		t.Fatalf("initial read: %v", err)
	}
	if got := wc.session.PendingCount(); got != 1 {
		t.Fatalf("pending before response Close = %d, want 1", got)
	}

	wrongIdentity := candidateSafeIdentity(manager, account.ID(), "owner-B", headers)
	if _, _, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_fence_1", account.ID(), "key-A", wrongIdentity); !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("owner mismatch error = %v, want continuation unavailable", err)
	}
	if got := wc.session.PendingCount(); got != 1 {
		t.Fatalf("identity mismatch changed pending leases to %d, want 1", got)
	}
	if current, ok := manager.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("identity mismatch discarded the healthy owner socket")
	}

	type acquireResult struct {
		conn    *WsConnection
		pending *PendingRequest
		err     error
	}
	resultCh := make(chan acquireResult, 1)
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelAcquire()
	go func() {
		reused, nextPending, _, acquireErr := manager.AcquirePreferredConnection(acquireCtx, "resp_fence_1", account.ID(), "key-A", identity)
		resultCh <- acquireResult{conn: reused, pending: nextPending, err: acquireErr}
	}()
	select {
	case early := <-resultCh:
		t.Fatalf("continuation returned before the prior response Close: %+v", early)
	case <-time.After(25 * time.Millisecond):
	}

	closeStarted := time.Now()
	if err := response.Close(); err != nil {
		t.Fatalf("initial close: %v", err)
	}
	var result acquireResult
	select {
	case result = <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("continuation did not resume after the prior response Close")
	}
	if result.err != nil {
		t.Fatalf("matching continuation acquire: %v", result.err)
	}
	if result.conn != wc {
		t.Fatal("continuation did not return to its exact physical socket")
	}
	if elapsed := time.Since(closeStarted); elapsed < 50*time.Millisecond {
		t.Fatalf("continuation crossed the 80ms post-Close reuse fence after only %s", elapsed)
	}
	if result.pending == nil || wc.session.PendingCount() != 1 {
		t.Fatalf("matching continuation pending=%v count=%d", result.pending, wc.session.PendingCount())
	}
}

func TestSafePoolTerminalCallbackFailureCannotWakeContinuationBeforeDiscard(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp_callback_fail"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp_callback_fail","status":"completed"}}`))
		<-req.Context().Done()
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4305, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"X-Client-Request-Id": {"thread-callback"}}
	identity := candidateSafeIdentity(manager, account.ID(), "owner-callback", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner-callback", headers)
	wc, pending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 200*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	response := &WsResponse{conn: wc, pendingReq: pending, sessionID: slot, manager: manager, apiKey: "key-A", safePool: true, reuseFence: 20 * time.Millisecond}

	callbackEntered := make(chan struct{})
	allowCallbackFailure := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readErr := response.ReadStream(func(frame []byte) bool {
			if gjson.GetBytes(frame, "type").String() != "response.completed" {
				return true
			}
			close(callbackEntered)
			<-allowCallbackFailure
			return false
		})
		if closeErr := response.Close(); readErr == nil {
			readErr = closeErr
		}
		readDone <- readErr
	}()
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("terminal callback was not reached")
	}

	type acquireResult struct {
		conn *WsConnection
		err  error
	}
	acquireDone := make(chan acquireResult, 1)
	acquireCtx, cancelAcquire := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelAcquire()
	go func() {
		got, _, _, acquireErr := manager.AcquirePreferredConnection(acquireCtx, "resp_callback_fail", account.ID(), "key-A", identity)
		acquireDone <- acquireResult{conn: got, err: acquireErr}
	}()
	select {
	case early := <-acquireDone:
		t.Fatalf("continuation escaped while terminal callback was still active: %+v", early)
	case <-time.After(25 * time.Millisecond):
	}

	close(allowCallbackFailure)
	select {
	case readErr := <-readDone:
		if readErr != nil {
			t.Fatalf("read/close after callback failure: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("response Close did not finish")
	}
	select {
	case result := <-acquireDone:
		if result.conn != nil || !errors.Is(result.err, proxy.ErrWebsocketContinuationUnavailable) {
			t.Fatalf("continuation after callback failure = (%p, %v), want unavailable", result.conn, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("continuation waiter was not released by discard")
	}
	if _, exists := manager.connections.Load(wc.PoolKey); exists {
		t.Fatal("callback-failed socket remained in the pool")
	}
}

func TestSafePoolAcquireProbeTimeoutIsPreSendAndSideEffectFree(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var requestFrames atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetPingHandler(func(string) error { return nil })
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			turn := requestFrames.Add(1)
			responseID := fmt.Sprintf("resp_probe_%d", turn)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","sequence_number":0,"response":{"id":%q}}`, responseID))); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","sequence_number":1,"response":{"id":%q,"status":"completed"}}`, responseID))); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4302, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{}
	identity := candidateSafeIdentity(manager, account.ID(), "owner-probe", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner-probe", headers)
	wc, pending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 100*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	t.Cleanup(func() { manager.DiscardConnection(wc) })
	if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	response := &WsResponse{conn: wc, pendingReq: pending, sessionID: slot, manager: manager, safePool: true, reuseFence: 5 * time.Millisecond}
	if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
		t.Fatalf("initial read: %v", err)
	}
	if err := response.Close(); err != nil {
		t.Fatalf("initial close: %v", err)
	}

	// Force an actual Ping/Pong probe instead of the recent-inbound fast path.
	wc.lastInbound.Store(time.Now().Add(-2 * probeRecencyWindow).UnixNano())
	started := time.Now()
	_, _, _, err = manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 40*time.Millisecond, headers, identity, "")
	if !errors.Is(err, proxy.ErrWebsocketLocalCapacity) {
		t.Fatalf("probe timeout error = %v, want local capacity", err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("40ms acquire budget took %s", elapsed)
	}
	if requestFrames.Load() != 1 {
		t.Fatalf("probe timeout sent %d business requests, want exactly the initial request", requestFrames.Load())
	}
	if wc.session.PendingCount() != 0 || manager.IsSafePoolFused(account.ID()) {
		t.Fatalf("probe timeout side effects: pending=%d fused=%v", wc.session.PendingCount(), manager.IsSafePoolFused(account.ID()))
	}
	if current, ok := manager.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("bounded probe timeout discarded the possibly healthy shared socket")
	}
}

func TestSafePoolImmediateIdleBusinessFrameTripsFuse(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","sequence_number":17,"response":{"id":"resp_unsolicited"}}`))
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4303, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	identity := candidateSafeIdentity(manager, account.ID(), "owner-immediate", http.Header{})
	wc, err := manager.createConnectionWithIdentity(context.Background(), account, wsURL, "immediate", http.Header{}, identity, "")
	if err != nil {
		t.Fatalf("create safe connection: %v", err)
	}
	t.Cleanup(func() { manager.DiscardConnection(wc) })
	deadline := time.Now().Add(time.Second)
	for !manager.IsSafePoolFused(account.ID()) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !manager.IsSafePoolFused(account.ID()) {
		t.Fatal("immediate idle business frame did not trip the account-local fuse")
	}
	if isolationErr := wc.safePoolReadIsolationFailure(); !errors.Is(isolationErr, errReadPumpIdleFrame) {
		t.Fatalf("isolation failure = %v, want idle-frame violation", isolationErr)
	}
}

func TestSafePoolPostTerminalControlsCannotCrossIntoNextLease(t *testing.T) {
	for index, extra := range []string{
		`{"type":"response.metadata","response_id":"resp_post_terminal"}`,
		`{"type":"codex.rate_limits","limits":[]}`,
	} {
		t.Run(fmt.Sprintf("control-%d", index), func(t *testing.T) {
			t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
			t.Setenv(safePoolScopeEnv, "all")
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				conn, err := upgrader.Upgrade(w, req, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp_post_terminal"}}`))
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp_post_terminal","status":"completed"}}`))
				_ = conn.WriteMessage(websocket.TextMessage, []byte(extra))
				time.Sleep(100 * time.Millisecond)
			}))
			t.Cleanup(server.Close)

			manager := NewManager()
			t.Cleanup(manager.Stop)
			account := &auth.Account{DBID: int64(4310 + index), DynamicConcurrencyLimit: 4}
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
			identity := candidateSafeIdentity(manager, account.ID(), fmt.Sprintf("post-terminal-%d", index), http.Header{})
			baseKey := safePoolOwnedRouteKey("shared", fmt.Sprintf("post-terminal-%d", index), http.Header{})
			wc, pending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 100*time.Millisecond, http.Header{}, identity, "")
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
				t.Fatalf("write: %v", err)
			}
			forwarded := 0
			response := &WsResponse{conn: wc, pendingReq: pending, sessionID: slot, manager: manager, apiKey: "key-A", safePool: true, reuseFence: 5 * time.Millisecond}
			_ = response.ReadStream(func([]byte) bool { forwarded++; return true })
			_ = response.Close()
			deadline := time.Now().Add(time.Second)
			for !manager.IsSafePoolFused(account.ID()) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if !manager.IsSafePoolFused(account.ID()) {
				t.Fatal("post-terminal control did not trip the isolation fuse")
			}
			if forwarded != 2 {
				t.Fatalf("forwarded frames = %d, want only created+terminal", forwarded)
			}
			if _, exists := manager.connections.Load(wc.PoolKey); exists {
				t.Fatal("post-terminal control socket remained reusable")
			}
		})
	}
}

func TestSafePoolKillSwitchBlocksContinuationAndRetiresIdleSocket(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","sequence_number":4,"response":{"id":"resp_kill"}}`)); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","sequence_number":5,"response":{"id":"resp_kill","status":"completed"}}`)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4304, Name: "renamable", Tags: []string{"business-tag"}, DynamicConcurrencyLimit: 9}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{}
	identity := candidateSafeIdentity(manager, account.ID(), "owner-kill", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner-kill", headers)
	wc, pending, slot, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 100*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	response := &WsResponse{conn: wc, pendingReq: pending, sessionID: slot, manager: manager, apiKey: "key-kill", safePool: true, reuseFence: 5 * time.Millisecond}
	if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
		t.Fatalf("initial read: %v", err)
	}
	if err := response.Close(); err != nil {
		t.Fatalf("initial close: %v", err)
	}

	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	if _, _, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_kill", account.ID(), "key-kill", identity); !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("kill-switch continuation error = %v, want continuation unavailable", err)
	}
	if wc.IsConnected() {
		t.Fatal("kill switch left the idle safe-pool socket connected")
	}
	if _, ok := manager.connections.Load(wc.PoolKey); ok {
		t.Fatal("kill switch left the idle safe-pool socket published")
	}
	if account.Name != "renamable" || account.DynamicConcurrencyLimit != 9 || len(account.Tags) != 1 || account.Tags[0] != "business-tag" {
		t.Fatalf("kill switch mutated account state: %+v", account)
	}
}

func TestSafePoolRetireLetsActiveLeaseFinishButNeverReturn(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 4305, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{}
	identity := candidateSafeIdentity(manager, account.ID(), "owner-active", headers)
	baseKey := safePoolOwnedRouteKey("shared", "owner-active", headers)
	wc, pending, _, err := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 100*time.Millisecond, headers, identity, "")
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	manager.BindResponseConn("resp_retired_generation", wc, baseKey, account.ID(), "key-active")
	if _, ok := manager.lookupResponseBinding("resp_retired_generation", account.ID(), "key-active"); !ok {
		t.Fatal("failed to publish old-generation continuation binding")
	}
	manager.RetireSafePoolAccount(account.ID())
	if !wc.IsConnected() || !wc.retireAfterLease.Load() {
		t.Fatal("policy retirement interrupted the active lease instead of marking it for close")
	}
	if _, _, _, preferredErr := manager.AcquirePreferredConnection(context.Background(), "resp_retired_generation", account.ID(), "key-active", identity); !errors.Is(preferredErr, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("old-generation continuation error=%v, want continuation unavailable", preferredErr)
	}
	reacquired, reacquiredPending, _, reacquireErr := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 20*time.Millisecond, headers, identity, "")
	if reacquired != nil || reacquiredPending != nil || !errors.Is(reacquireErr, proxy.ErrWebsocketSafePoolFallback) {
		t.Fatalf("concurrent reacquire = conn:%v pending:%v err:%v, want stale-generation fallback while retired lease finishes", reacquired, reacquiredPending, reacquireErr)
	}
	if !wc.IsConnected() || wc.session.PendingCount() != 1 {
		t.Fatalf("concurrent reacquire interrupted active retired socket: connected=%v pending=%d", wc.IsConnected(), wc.session.PendingCount())
	}
	wc.session.RemovePendingRequest(pending.RequestID)
	manager.ReleaseConnection(wc)
	if wc.IsConnected() {
		t.Fatal("retired active socket returned to the pool after its lease ended")
	}
	newIdentity := candidateSafeIdentity(manager, account.ID(), "owner-active", headers)
	if newIdentity.generation <= identity.generation {
		t.Fatalf("re-add generation=%d, want newer than %d", newIdentity.generation, identity.generation)
	}
	newConn, newPending, _, newErr := manager.AcquireSafeReusableConnection(context.Background(), account, wsURL, baseKey, 1, 100*time.Millisecond, headers, newIdentity, "")
	if newErr != nil || newConn == nil || newPending == nil {
		t.Fatalf("new-generation acquire conn=%v pending=%v err=%v", newConn, newPending, newErr)
	}
	if newConn == wc {
		t.Fatal("new generation reacquired the retired physical socket")
	}
	newConn.session.RemovePendingRequest(newPending.RequestID)
	manager.DiscardConnection(newConn)
}

func TestSafePoolRuntimeSnapshotReportsAggregateState(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "tagged")
	t.Setenv(safePoolMaxSlotsEnv, "71")
	t.Setenv(safePoolWaitMillisEnv, "333")
	t.Setenv(safePoolFenceMillisEnv, "111")
	t.Setenv(safePoolOwnerSampleBPSEnv, "10000")
	t.Setenv(safePoolOwnerBudgetPerAccountEnv, "2")
	t.Setenv(continuationGlobalLimitEnv, "17")
	t.Setenv(continuationPerAccountLimitEnv, "3")

	manager := NewManager()
	t.Cleanup(manager.Stop)
	admission := currentSafePoolOwnerAdmissionConfig()
	if admitOwnerDecision(manager, 4401, "runtime-owner-A", admission) != safePoolOwnerAdmittedNew ||
		admitOwnerDecision(manager, 4401, "runtime-owner-B", admission) != safePoolOwnerAdmittedNew {
		t.Fatal("failed to seed runtime owner admission gauges")
	}
	t.Setenv(safePoolOwnerSampleBPSEnv, "7")
	account := &auth.Account{DBID: 4401, Tags: []string{safePoolAccountTag}}
	idle, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "runtime-idle")
	idleGeneration, idleCurrent := manager.safePoolOwnerGeneration(account.ID(), "runtime-owner-A")
	if !idleCurrent {
		t.Fatal("runtime owner A generation is missing")
	}
	idle.safeOwnerKey = "runtime-owner-A"
	idle.handshakeFingerprint = safePoolHeaderFingerprint(http.Header{})
	idle.safeGeneration = idleGeneration
	idle.safeReusable.Store(true)
	manager.BindResponseConn("resp_runtime", idle, "runtime-idle", account.ID(), "sk-runtime")

	active, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "runtime-active")
	activeGeneration, activeCurrent := manager.safePoolOwnerGeneration(account.ID(), "runtime-owner-B")
	if !activeCurrent {
		t.Fatal("runtime owner B generation is missing")
	}
	active.safeOwnerKey = "runtime-owner-B"
	active.handshakeFingerprint = safePoolHeaderFingerprint(http.Header{})
	active.safeGeneration = activeGeneration
	active.safeReusable.Store(true)
	active.retireAfterLease.Store(true)
	pending := active.session.AddPendingRequest("runtime-active")
	t.Cleanup(func() { active.session.RemovePendingRequest(pending.RequestID) })

	manager.reserveSafePoolPendingCreate(account.ID())
	manager.reserveSafePoolPendingCreate(account.ID())
	t.Cleanup(func() {
		manager.releaseSafePoolPendingCreate(account.ID())
		manager.releaseSafePoolPendingCreate(account.ID())
	})
	manager.safePoolAccounts.Store(account.ID(), struct{}{})
	manager.safePoolFuses.Store(account.ID(), safePoolFuseState{compatibility: true, reason: "test"})
	manager.safePoolDialAttempts.Add(3)
	manager.safePoolReuseHits.Add(2)

	snapshot := manager.SafePoolRuntimeSnapshot()
	if snapshot.GlobalOneShot || snapshot.Scope != "tagged" {
		t.Fatalf("rollout snapshot = oneshot:%v scope:%q, want false/tagged", snapshot.GlobalOneShot, snapshot.Scope)
	}
	if snapshot.ConfiguredMaxSlots != 71 || snapshot.WaitMillis != 333 || snapshot.ReuseFenceMillis != 111 {
		t.Fatalf("tuning snapshot = slots:%d wait:%d fence:%d, want 71/333/111", snapshot.ConfiguredMaxSlots, snapshot.WaitMillis, snapshot.ReuseFenceMillis)
	}
	if snapshot.OwnerSampleBPS != 7 || snapshot.OwnerBudgetPerAccount != 2 ||
		!snapshot.OwnerAdmissionConfigValid || !snapshot.OwnerAdmissionSaltReady {
		t.Fatalf("owner guard config snapshot = sample:%d budget:%d valid:%v salt:%v", snapshot.OwnerSampleBPS, snapshot.OwnerBudgetPerAccount, snapshot.OwnerAdmissionConfigValid, snapshot.OwnerAdmissionSaltReady)
	}
	if snapshot.AdmittedOwners != 2 || snapshot.AdmittedOwnerAccounts != 1 || snapshot.OwnerBudgetOvercommitted != 0 {
		t.Fatalf("owner guard gauges = owners:%d accounts:%d over:%d, want 2/1/0", snapshot.AdmittedOwners, snapshot.AdmittedOwnerAccounts, snapshot.OwnerBudgetOvercommitted)
	}
	if snapshot.ContinuationGlobalLimit != 17 || snapshot.ContinuationPerAccountLimit != 3 {
		t.Fatalf("continuation limits = global:%d account:%d, want 17/3", snapshot.ContinuationGlobalLimit, snapshot.ContinuationPerAccountLimit)
	}
	if snapshot.Connections != 2 || snapshot.ActiveConnections != 1 || snapshot.IdleConnections != 1 || snapshot.BoundIdleConnections != 1 {
		t.Fatalf("connection snapshot = total:%d active:%d idle:%d bound-idle:%d, want 2/1/1/1", snapshot.Connections, snapshot.ActiveConnections, snapshot.IdleConnections, snapshot.BoundIdleConnections)
	}
	if snapshot.RetiringConnections != 1 || snapshot.PendingDials != 2 || snapshot.ResponseBindings != 1 {
		t.Fatalf("lifecycle snapshot = retiring:%d pending:%d bindings:%d, want 1/2/1", snapshot.RetiringConnections, snapshot.PendingDials, snapshot.ResponseBindings)
	}
	if snapshot.FusedAccounts != 1 || snapshot.CompatibilityFusedAccounts != 1 || snapshot.TrackedAccounts != 1 {
		t.Fatalf("account snapshot = fused:%d compatibility:%d tracked:%d, want 1/1/1", snapshot.FusedAccounts, snapshot.CompatibilityFusedAccounts, snapshot.TrackedAccounts)
	}
	if snapshot.Metrics.DialAttempts != 3 || snapshot.Metrics.ReuseHits != 2 || snapshot.Metrics.OwnerAdmittedNew != 2 {
		t.Fatalf("metrics snapshot = %+v, want dial_attempts=3 reuse_hits=2 owner_admitted_new=2", snapshot.Metrics)
	}
}
