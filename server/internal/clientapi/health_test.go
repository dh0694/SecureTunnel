package clientapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProbeHealthRequiresHealthyReply(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		wantOK     bool
	}{
		{"healthy", `{"status":"ok"}`, http.StatusOK, true},
		{"unhealthy", `{"error":"db_unavailable"}`, http.StatusServiceUnavailable, false},
		{"missing status", `{}`, http.StatusOK, false},
		{"proxy page", `<html>Sign in</html>`, http.StatusOK, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "" {
					t.Errorf("want unauthenticated GET /healthz, got %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client := &Client{Base: server.URL, HTTP: server.Client()}
			if err := client.ProbeHealth(context.Background()); (err == nil) != test.wantOK {
				t.Fatalf("ProbeHealth: %v, want success %v", err, test.wantOK)
			}
		})
	}
}

func TestProbeHealthStaysOnActiveServer(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer backup.Close()
	client := &Client{Base: primary.URL, Fallbacks: []*Client{{Base: backup.URL}}, active: 1}

	if err := client.ProbeHealth(context.Background()); !HasStatus(err, http.StatusBadGateway) {
		t.Fatalf("ProbeHealth: %v, want active server's 502", err)
	}
	if calls := primaryCalls.Load(); calls != 0 || client.Active() != backup.URL {
		t.Fatalf("sample changed active address to %s or contacted primary %d time(s)", client.Active(), calls)
	}
}
