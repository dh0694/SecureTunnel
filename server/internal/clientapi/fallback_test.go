package clientapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFallbackWhenPrimaryUnreachable(t *testing.T) {
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backup.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	downURL := down.URL
	down.Close() // connection refused

	c := &Client{Base: downURL, Fallbacks: []*Client{{Base: backup.URL}}}
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("health via backup: %v", err)
	}
	if c.Active() != backup.URL {
		t.Fatalf("active = %s, want backup", c.Active())
	}
}

func TestNoFallbackOnRealAnswer(t *testing.T) {
	calls := 0
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer backup.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"country_blocked","message":"no"}`))
	}))
	defer primary.Close()
	c := &Client{Base: primary.URL, Fallbacks: []*Client{{Base: backup.URL}}}
	err := c.Health(context.Background())
	if !HasCode(err, "country_blocked") || calls != 0 {
		t.Fatalf("err=%v calls=%d: a SecureTunnel answer must not fail over", err, calls)
	}
}

func TestUnreachable(t *testing.T) {
	cases := map[error]bool{
		errors.New("dial tcp: connection refused"):              true,
		&APIError{Status: 502, Message: "Bad gateway"}:            true,
		&APIError{Status: 530}:                                    true,
		&APIError{Status: 503, Code: "db_unavailable"}:            false,
		&APIError{Status: 401, Code: "reauth_required"}:           false,
		context.Canceled:                                          false,
	}
	for err, want := range cases {
		if got := Unreachable(err); got != want {
			t.Errorf("Unreachable(%v) = %v, want %v", err, got, want)
		}
	}
}
