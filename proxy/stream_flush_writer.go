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
	if w.policy != StreamFlushPolicyCoalesce {
		if err := w.writeBytes(sseDataPrefix); err != nil {
			return err
		}
		if err := w.writeBytes(data); err != nil {
			return err
		}
		if err := w.writeBytes(sseDataSuffix); err != nil {
			return err
		}
		return w.flushTransport()
	}
	appendSSEData(&w.buffer, data)
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
