package proxy

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestStreamFlushWriterImmediateOperationsPropagateUnderlyingFlushError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	operations := []struct {
		name string
		run  func(*streamFlushWriter) error
	}{
		{name: "string", run: func(w *streamFlushWriter) error { return w.WriteString("terminal") }},
		{name: "bytes", run: func(w *streamFlushWriter) error { return w.WriteBytes([]byte("terminal")) }},
		{name: "sse", run: func(w *streamFlushWriter) error { return w.WriteSSEData([]byte(`{"type":"response.completed"}`)) }},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			flushErr := errors.New("underlying flush failed")
			underlying := &auditFlushErrorHTTPWriter{flushErr: flushErr}
			outer := &auditUnwrapAndFlushGinWriter{ResponseWriter: c.Writer, target: underlying}
			writer := &streamFlushWriter{
				writer:  outer,
				flusher: outer,
				policy:  StreamFlushPolicyImmediate,
			}

			err := operation.run(writer)
			if !errors.Is(err, flushErr) {
				t.Fatalf("operation error = %v, want %v", err, flushErr)
			}
			if outer.flushCalls != 0 {
				t.Fatalf("outer legacy Flush called %d times, want 0", outer.flushCalls)
			}
			if underlying.flushCalls != 1 {
				t.Fatalf("underlying FlushError called %d times, want 1", underlying.flushCalls)
			}
			if !writer.lastFlush.IsZero() {
				t.Fatal("failed flush must not advance lastFlush")
			}
		})
	}
}

func TestStreamFlushWriterCoalescedFlushPropagatesUnderlyingFlushError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	flushErr := errors.New("underlying flush failed")
	underlying := &auditFlushErrorHTTPWriter{flushErr: flushErr}
	outer := &auditUnwrapAndFlushGinWriter{ResponseWriter: c.Writer, target: underlying}
	writer := &streamFlushWriter{
		writer:  outer,
		flusher: outer,
		policy:  StreamFlushPolicyCoalesce,
	}
	writer.buffer.WriteString("terminal")

	err := writer.Flush()
	if !errors.Is(err, flushErr) {
		t.Fatalf("Flush error = %v, want %v", err, flushErr)
	}
	if outer.flushCalls != 0 {
		t.Fatalf("outer legacy Flush called %d times, want 0", outer.flushCalls)
	}
	if underlying.flushCalls != 1 {
		t.Fatalf("underlying FlushError called %d times, want 1", underlying.flushCalls)
	}
	if !writer.lastFlush.IsZero() {
		t.Fatal("failed flush must not advance lastFlush")
	}
}

func TestStreamFlushWriterKeepsFirstFlushErrorSticky(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	flushErr := errors.New("one-shot flush failure")
	underlying := &auditFlushErrorHTTPWriter{flushErr: flushErr}
	outer := &auditUnwrapAndFlushGinWriter{ResponseWriter: c.Writer, target: underlying}
	writer := &streamFlushWriter{
		writer:  outer,
		flusher: outer,
		policy:  StreamFlushPolicyImmediate,
	}

	if err := writer.WriteBytes([]byte("first")); !errors.Is(err, flushErr) {
		t.Fatalf("first write error = %v, want %v", err, flushErr)
	}
	underlying.flushErr = nil
	if err := writer.WriteBytes([]byte("second")); !errors.Is(err, flushErr) {
		t.Fatalf("second write error = %v, want sticky %v", err, flushErr)
	}
	if underlying.flushCalls != 1 {
		t.Fatalf("underlying FlushError called %d times, want 1", underlying.flushCalls)
	}
	if got := recorder.Body.String(); got != "first" {
		t.Fatalf("body = %q, want only first write", got)
	}
	if !writer.lastFlush.IsZero() {
		t.Fatal("sticky failed flush must not advance lastFlush")
	}
}

func TestStreamFlushWriterSkipsRedundantFlushAfterSuccessfulImmediateWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	underlying := &auditFlushErrorHTTPWriter{}
	outer := &auditUnwrapAndFlushGinWriter{ResponseWriter: c.Writer, target: underlying}
	writer := &streamFlushWriter{
		writer:  outer,
		flusher: outer,
		policy:  StreamFlushPolicyImmediate,
	}

	if err := writer.WriteBytes([]byte("terminal")); err != nil {
		t.Fatalf("terminal write: %v", err)
	}
	if writer.lastFlush.IsZero() || writer.dirty {
		t.Fatalf("successful flush state = last:%v dirty:%t", writer.lastFlush, writer.dirty)
	}
	underlying.flushErr = errors.New("redundant flush must not run")
	if err := writer.Flush(); err != nil {
		t.Fatalf("redundant Flush error = %v, want nil", err)
	}
	if underlying.flushCalls != 1 {
		t.Fatalf("underlying FlushError called %d times, want 1", underlying.flushCalls)
	}
	if writer.terminalErr != nil {
		t.Fatalf("redundant flush contaminated terminal state: %v", writer.terminalErr)
	}
}
