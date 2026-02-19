package testutil

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
)

// TestUpstream is a simple HTTP server that records requests for verification.
type TestUpstream struct {
	server      *httptest.Server
	count       int64
	mu          sync.RWMutex
	lastHeaders http.Header
}

// NewTestUpstream starts an upstream server that always responds with statusCode and body.
func NewTestUpstream(statusCode int, body string) *TestUpstream {
	tu := &TestUpstream{}
	tu.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tu.count, 1)
		h := make(http.Header)
		for k, v := range r.Header {
			h[k] = v
		}
		tu.mu.Lock()
		tu.lastHeaders = h
		tu.mu.Unlock()
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body) //nolint:errcheck
	}))
	return tu
}

// URL returns the upstream server URL.
func (t *TestUpstream) URL() string { return t.server.URL }

// RequestCount returns the total number of requests received.
func (t *TestUpstream) RequestCount() int { return int(atomic.LoadInt64(&t.count)) }

// LastHeader returns the value of a header from the most recent request.
func (t *TestUpstream) LastHeader(name string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.lastHeaders == nil {
		return ""
	}
	return t.lastHeaders.Get(name)
}

// Close shuts down the upstream server.
func (t *TestUpstream) Close() { t.server.Close() }
