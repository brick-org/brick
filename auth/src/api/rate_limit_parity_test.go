package api

import (
	"context"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// stubRateLimitContext is a minimal huma.Context for IP/resolution unit
type stubRateLimitContext struct {
	headers    http.Header
	remoteAddr string
	url        url.URL
}

func (s *stubRateLimitContext) Operation() *huma.Operation { return nil }
func (s *stubRateLimitContext) Context() context.Context   { return context.Background() }
func (s *stubRateLimitContext) TLS() *tls.ConnectionState  { return nil }
func (s *stubRateLimitContext) Version() huma.ProtoVersion {
	return huma.ProtoVersion{}
}
func (s *stubRateLimitContext) Method() string      { return http.MethodPost }
func (s *stubRateLimitContext) Host() string        { return "example.com" }
func (s *stubRateLimitContext) RemoteAddr() string  { return s.remoteAddr }
func (s *stubRateLimitContext) URL() url.URL        { return s.url }
func (s *stubRateLimitContext) Param(string) string { return "" }
func (s *stubRateLimitContext) Query(string) string { return "" }
func (s *stubRateLimitContext) Header(name string) string {
	return s.headers.Get(name)
}
func (s *stubRateLimitContext) EachHeader(cb func(name, value string)) {
	for name, values := range s.headers {
		for _, value := range values {
			cb(name, value)
		}
	}
}
func (s *stubRateLimitContext) BodyReader() io.Reader { return nil }
func (s *stubRateLimitContext) GetMultipartForm() (*multipart.Form, error) {
	return nil, http.ErrNotMultipart
}
func (s *stubRateLimitContext) SetReadDeadline(time.Time) error { return nil }
func (s *stubRateLimitContext) SetStatus(int)                   {}
func (s *stubRateLimitContext) Status() int                     { return 0 }
func (s *stubRateLimitContext) SetHeader(string, string)        {}
func (s *stubRateLimitContext) AppendHeader(string, string)     {}
func (s *stubRateLimitContext) BodyWriter() io.Writer           { return io.Discard }
func (s *stubRateLimitContext) Unwrap() huma.Context            { return nil }

func testRateLimitOptions() types.Options {
	return types.Options{Secret: "test-secret"}
}

func TestRequestIP_SingleValueForwardedHeaderTrusted(t *testing.T) {
	ctx := &stubRateLimitContext{
		headers:    http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
		remoteAddr: "9.9.9.9:1234",
	}
	if got := requestIP(ctx, testRateLimitOptions()); got != "1.2.3.4" {
		t.Fatalf("single X-Forwarded-For must be trusted, got %q", got)
	}
}

func TestRequestIP_MultiHopChainUntrustedWithoutProxyOptIn(t *testing.T) {
	ctx := &stubRateLimitContext{
		headers:    http.Header{"X-Forwarded-For": []string{"1.2.3.4, 10.0.0.1"}},
		remoteAddr: "9.9.9.9:1234",
	}
	if got := requestIP(ctx, testRateLimitOptions()); got != "9.9.9.9" {
		t.Fatalf("multi-hop chain must fall through to RemoteAddr, got %q", got)
	}
}

func TestRequestIP_TrustedProxyOptInUsesLeftmostHop(t *testing.T) {
	opts := testRateLimitOptions()
	trusted := true
	opts.Advanced.TrustedProxyHeaders = &trusted
	ctx := &stubRateLimitContext{
		headers:    http.Header{"X-Forwarded-For": []string{"1.2.3.4, 10.0.0.1"}},
		remoteAddr: "9.9.9.9:1234",
	}
	if got := requestIP(ctx, opts); got != "1.2.3.4" {
		t.Fatalf("trusted proxy chain must resolve leftmost hop, got %q", got)
	}
}

func TestRequestIP_CustomIPAddressHeadersHonored(t *testing.T) {
	opts := testRateLimitOptions()
	opts.Advanced.IPAddress.IPAddressHeaders = []string{"X-Real-IP"}
	ctx := &stubRateLimitContext{
		headers: http.Header{
			"X-Forwarded-For": []string{"1.2.3.4, 10.0.0.1"},
			"X-Real-Ip":       []string{"5.6.7.8"},
		},
		remoteAddr: "9.9.9.9:1234",
	}
	if got := requestIP(ctx, opts); got != "5.6.7.8" {
		t.Fatalf("configured IP headers must win, got %q", got)
	}
}

func TestRequestIP_DisableIPTrackingSkipsLimiting(t *testing.T) {
	opts := testRateLimitOptions()
	opts.Advanced.IPAddress.DisableIPTracking = true
	enabled := true
	opts.RateLimit.Enabled = &enabled
	ctx := &stubRateLimitContext{remoteAddr: "9.9.9.9:1234"}
	if got := requestIP(ctx, opts); got != "" {
		t.Fatalf("disabled IP tracking must resolve no IP, got %q", got)
	}
	if _, ok := resolveRateLimit(ctx, "/api/auth/get-session", opts); ok {
		t.Fatal("disabled IP tracking must skip rate limiting")
	}
}

func TestResolveRateLimit_DefaultDisabled(t *testing.T) {
	ctx := &stubRateLimitContext{remoteAddr: "127.0.0.1:1234"}
	if _, ok := resolveRateLimit(ctx, "/api/auth/get-session", testRateLimitOptions()); ok {
		t.Fatal("rate limiting must be disabled by default")
	}
}

func TestMemoryRateLimitStorage_ConsumeEnforcesMaxThenSlides(t *testing.T) {
	rateLimitMu.Lock()
	original := rateLimitMemory
	rateLimitMemory = map[string]memoryRateLimitEntry{}
	rateLimitMu.Unlock()
	t.Cleanup(func() {
		rateLimitMu.Lock()
		rateLimitMemory = original
		rateLimitMu.Unlock()
	})

	storage := MemoryRateLimitStorage{}
	window := 60 * time.Millisecond
	if _, limited := storage.Consume("parity-key", window, 2); limited {
		t.Fatal("first request must pass")
	}
	if _, limited := storage.Consume("parity-key", window, 2); limited {
		t.Fatal("second request must pass")
	}
	retryAfter, limited := storage.Consume("parity-key", window, 2)
	if !limited {
		t.Fatal("third request must be limited")
	}
	if retryAfter < 1 {
		t.Fatalf("retryAfter must be positive, got %d", retryAfter)
	}
	rateLimitMu.Lock()
	entries := len(rateLimitMemory)
	rateLimitMu.Unlock()
	if entries != 1 {
		t.Fatalf("expected 1 bounded entry, got %d", entries)
	}
	time.Sleep(70 * time.Millisecond)
	if _, limited := storage.Consume("parity-key", window, 2); limited {
		t.Fatal("request after window expiry must pass")
	}
}

func TestSetRateLimitStorage_SwapAndRestore(t *testing.T) {
	restore := SetRateLimitStorage(MemoryRateLimitStorage{})
	restore()
	if _, ok := rateLimitStorage.(MemoryRateLimitStorage); !ok {
		t.Fatalf("restore must reinstate the memory backend, got %T", rateLimitStorage)
	}
}
