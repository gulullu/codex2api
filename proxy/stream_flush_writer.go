package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"time"
)

const pendingFirstTokenFlushBytes = 1024 * 1024

var (
	sseDataPrefix = []byte("data: ")
	sseDataSuffix = []byte("\n\n")
)

type streamFlushWriter struct {
	writer      io.Writer
	flusher     http.Flusher
	policy      string
	interval    time.Duration
	lastFlush   time.Time
	buffer      bytes.Buffer
	terminalErr error
	dirty       bool
}

func (h *Handler) newStreamFlushWriter(writer io.Writer, flusher http.Flusher) *streamFlushWriter {
	return newStreamFlushWriter(writer, flusher)
}

func (w *streamFlushWriter) scanOutput(data []byte) ([]byte, error) {
	// Output moderation is owned by sub2. codex2api must preserve the upstream
	// SSE bytes even if an older database row still says output scanning is
	// enabled.
	return data, nil
}

func newStreamFlushWriter(writer io.Writer, flusher http.Flusher) *streamFlushWriter {
	settings := CurrentRuntimeSettings()
	return &streamFlushWriter{
		writer:   writer,
		flusher:  flusher,
		policy:   settings.StreamFlushPolicy,
		interval: currentStreamFlushInterval(),
	}
}

func appendSSEData(buf *bytes.Buffer, data []byte) {
	if buf == nil {
		return
	}
	buf.Write(sseDataPrefix)
	buf.Write(data)
	buf.Write(sseDataSuffix)
}

func writeDeferredSSEData(streamWriter *streamFlushWriter, pending *bytes.Buffer, data []byte, shouldDefer bool) (bool, error) {
	if streamWriter == nil {
		return false, nil
	}
	if shouldDefer {
		appendSSEData(pending, data)
		if pending != nil && pending.Len() <= pendingFirstTokenFlushBytes {
			return false, nil
		}
	}
	if pending != nil && pending.Len() > 0 {
		if !shouldDefer {
			appendSSEData(pending, data)
		}
		if err := streamWriter.WriteBytes(pending.Bytes()); err != nil {
			return false, err
		}
		pending.Reset()
		return true, nil
	}
	if shouldDefer {
		return false, nil
	}
	if err := streamWriter.WriteSSEData(data); err != nil {
		return false, err
	}
	return true, nil
}

func (w *streamFlushWriter) WriteString(data string) error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}
	if w.writer == nil {
		return nil
	}
	filtered, err := w.scanOutput([]byte(data))
	if err != nil || len(filtered) == 0 {
		return err
	}
	data = string(filtered)
	if w.policy != StreamFlushPolicyCoalesce {
		if err := w.writeString(data); err != nil {
			return err
		}
		return w.flushTransport()
	}
	if _, err := w.buffer.WriteString(data); err != nil {
		return w.rememberTerminalError(err)
	}
	if w.lastFlush.IsZero() || time.Since(w.lastFlush) >= w.interval {
		return w.Flush()
	}
	return nil
}

func (w *streamFlushWriter) WriteBytes(data []byte) error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}
	if w.writer == nil || len(data) == 0 {
		return nil
	}
	var err error
	data, err = w.scanOutput(data)
	if err != nil || len(data) == 0 {
		return err
	}
	if w.policy != StreamFlushPolicyCoalesce {
		if err := w.writeBytes(data); err != nil {
			return err
		}
		return w.flushTransport()
	}
	if _, err := w.buffer.Write(data); err != nil {
		return w.rememberTerminalError(err)
	}
	if w.lastFlush.IsZero() || time.Since(w.lastFlush) >= w.interval {
		return w.Flush()
	}
	return nil
}

func (w *streamFlushWriter) WriteSSEData(data []byte) error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}
	if w.writer == nil {
		return nil
	}
	framed := make([]byte, 0, len(sseDataPrefix)+len(data)+len(sseDataSuffix))
	framed = append(framed, sseDataPrefix...)
	framed = append(framed, data...)
	framed = append(framed, sseDataSuffix...)
	var err error
	framed, err = w.scanOutput(framed)
	if err != nil || len(framed) == 0 {
		return err
	}
	if w.policy != StreamFlushPolicyCoalesce {
		if err := w.writeBytes(framed); err != nil {
			return err
		}
		return w.flushTransport()
	}
	w.buffer.Write(framed)
	if w.lastFlush.IsZero() || time.Since(w.lastFlush) >= w.interval {
		return w.Flush()
	}
	return nil
}

func (w *streamFlushWriter) Flush() error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}
	if w.buffer.Len() == 0 && !w.dirty && !w.lastFlush.IsZero() {
		return nil
	}
	if w.buffer.Len() > 0 {
		if err := w.writeBytes(w.buffer.Bytes()); err != nil {
			return err
		}
		w.buffer.Reset()
	}
	return w.flushTransport()
}

// Finalize flushes any coalesced bytes at a real semantic end-of-stream.
func (w *streamFlushWriter) Finalize() error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}
	if w.buffer.Len() > 0 {
		if err := w.writeBytes(w.buffer.Bytes()); err != nil {
			return err
		}
		w.buffer.Reset()
	}
	return w.flushTransport()
}

func (w *streamFlushWriter) flushTransport() error {
	if w == nil {
		return nil
	}
	if w.terminalErr != nil {
		return w.terminalErr
	}

	// Gin implements the legacy error-less http.Flusher itself, so invoking the
	// flusher interface directly can hide an underlying FlushError. Reuse the
	// terminal publication helper, which explicitly unwraps Gin and tracking
	// writers before selecting the strongest available flush contract.
	var target http.ResponseWriter
	if responseWriter, ok := w.writer.(http.ResponseWriter); ok {
		target = responseWriter
	} else if responseWriter, ok := w.flusher.(http.ResponseWriter); ok {
		target = responseWriter
	}
	if target != nil {
		err := flushTerminalHTTPResponse(target)
		if err == nil {
			w.dirty = false
			w.lastFlush = time.Now()
			return nil
		}
		if !errors.Is(err, http.ErrNotSupported) {
			return w.rememberTerminalError(err)
		}
		if w.flusher == nil {
			return w.rememberTerminalError(err)
		}
	}

	if w.flusher == nil {
		return nil
	}
	w.flusher.Flush()
	w.dirty = false
	w.lastFlush = time.Now()
	return nil
}

func (w *streamFlushWriter) rememberTerminalError(err error) error {
	if w == nil || err == nil {
		return err
	}
	if w.terminalErr == nil {
		w.terminalErr = err
	}
	return w.terminalErr
}

func (w *streamFlushWriter) writeBytes(data []byte) error {
	n, err := w.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.rememberTerminalError(err)
	}
	w.dirty = true
	return nil
}

func (w *streamFlushWriter) writeString(data string) error {
	n, err := io.WriteString(w.writer, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.rememberTerminalError(err)
	}
	w.dirty = true
	return nil
}
