// Package speedtest measures latency and download/upload throughput over HTTP.
// The agent uses it twice: against an internet speed-test host (outside the
// tunnel) and against the control server (through the tunnel).
package speedtest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result of one test.
type Result struct {
	DownBps   float64 `json:"down_bps"`
	UpBps     float64 `json:"up_bps"`
	LatencyMs int     `json:"latency_ms"`
}

// Target says where to test.
type Target struct {
	DownURL func(bytes int) string // URL that returns `bytes` bytes
	UpURL   string                 // URL that accepts a POST body
	Header  http.Header            // added to every request (e.g. Authorization)
}

// Cloudflare returns the target for a Cloudflare-style speed-test host
// (speed.cloudflare.com exposes /__down?bytes=N and /__up).
func Cloudflare(host string) Target {
	return Target{
		DownURL: func(n int) string { return fmt.Sprintf("https://%s/__down?bytes=%d", host, n) },
		UpURL:   "https://" + host + "/__up",
	}
}

// Run measures latency (best of 3 small requests), then download, then upload.
func Run(ctx context.Context, c *http.Client, t Target, downBytes, upBytes int) (Result, error) {
	var r Result
	best := time.Duration(0)
	for i := 0; i < 3; i++ {
		d, err := timeGet(ctx, c, t, t.DownURL(0), nil)
		if err != nil {
			return r, fmt.Errorf("latency: %w", err)
		}
		if best == 0 || d < best {
			best = d
		}
	}
	r.LatencyMs = int(best / time.Millisecond)

	var got int64
	start := time.Now()
	if _, err := timeGet(ctx, c, t, t.DownURL(downBytes), &got); err != nil {
		return r, fmt.Errorf("download: %w", err)
	}
	if el := time.Since(start).Seconds(); el > 0 {
		r.DownBps = float64(got) * 8 / el
	}

	start = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.UpURL, io.LimitReader(randReader{}, int64(upBytes)))
	if err != nil {
		return r, err
	}
	req.ContentLength = int64(upBytes)
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range t.Header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		return r, fmt.Errorf("upload: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return r, fmt.Errorf("upload: server returned %d", resp.StatusCode)
	}
	if el := time.Since(start).Seconds(); el > 0 {
		r.UpBps = float64(upBytes) * 8 / el
	}
	return r, nil
}

// timeGet does a GET, reads the body, and returns the time to the first
// response byte. If n is non-nil it receives the body length.
func timeGet(ctx context.Context, c *http.Client, t Target, url string, n *int64) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range t.Header {
		req.Header[k] = v
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	ttfb := time.Since(start)
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	read, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 200<<20))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if n != nil {
		*n = read
	}
	return ttfb, nil
}

// PublicIP asks a Cloudflare-fronted host which IP the request came from,
// via its /cdn-cgi/trace page ("ip=203.0.113.9").
func PublicIP(ctx context.Context, c *http.Client, host string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return "", err
	}
	return ParseTraceIP(string(b))
}

// ParseTraceIP extracts the ip= line from a Cloudflare trace response.
func ParseTraceIP(trace string) (string, error) {
	for _, line := range strings.Split(trace, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			if ip := net.ParseIP(v); ip != nil {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("no ip in trace response")
}

// randReader yields random bytes (incompressible upload data).
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }
