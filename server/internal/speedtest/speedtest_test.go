package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestRunMeasuresAllThree(t *testing.T) {
	var uploaded int64
	mux := http.NewServeMux()
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		_, _ = w.Write(make([]byte, n))
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		uploaded, _ = io.Copy(io.Discard, r.Body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	target := Target{
		DownURL: func(n int) string { return fmt.Sprintf("%s/down?bytes=%d", srv.URL, n) },
		UpURL:   srv.URL + "/up",
		Header:  http.Header{"Authorization": {"Bearer tok"}},
	}
	r, err := Run(context.Background(), srv.Client(), target, 2<<20, 512<<10)
	if err != nil {
		t.Fatal(err)
	}
	if r.DownBps <= 0 || r.UpBps <= 0 {
		t.Errorf("result = %+v, want positive rates", r)
	}
	if uploaded != 512<<10 {
		t.Errorf("server received %d bytes, want %d", uploaded, 512<<10)
	}
}

func TestCloudflareURLs(t *testing.T) {
	cf := Cloudflare("speed.cloudflare.com")
	if got := cf.DownURL(1000); got != "https://speed.cloudflare.com/__down?bytes=1000" {
		t.Errorf("down URL = %s", got)
	}
	if cf.UpURL != "https://speed.cloudflare.com/__up" {
		t.Errorf("up URL = %s", cf.UpURL)
	}
}

func TestParseTraceIP(t *testing.T) {
	trace := "fl=123\nh=speed.cloudflare.com\nip=47.32.2.7\nts=1795334000\nloc=US\n"
	if ip, err := ParseTraceIP(trace); err != nil || ip != "47.32.2.7" {
		t.Fatalf("ip=%q err=%v", ip, err)
	}
	if _, err := ParseTraceIP("fl=1\nh=x\n"); err == nil {
		t.Error("expected an error with no ip line")
	}
}

func TestRunReportsServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	_, err := Run(context.Background(), srv.Client(), Target{DownURL: func(int) string { return srv.URL }, UpURL: srv.URL}, 1000, 1000)
	if err == nil {
		t.Fatal("expected an error for a 403")
	}
}
