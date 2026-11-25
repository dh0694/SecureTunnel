package clienttls

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func get(t *testing.T, srv *httptest.Server, tr *Trust) error {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tr.Config()}}
	resp, err := c.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func host(srv *httptest.Server) string {
	u, _ := url.Parse(srv.URL)
	return u.Hostname()
}

func TestFirstUsePinsThenAccepts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pins := &MemoryPins{}
	tr := &Trust{Host: host(srv), Pins: pins}
	if err := get(t, srv, tr); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	if pins.GetPin() == "" || tr.LastMode() != ModeFirst {
		t.Fatalf("pin=%q mode=%s, want a saved pin and first-use", pins.GetPin(), tr.LastMode())
	}
	if err := get(t, srv, tr); err != nil || tr.LastMode() != ModePinned {
		t.Fatalf("second connection: err=%v mode=%s", err, tr.LastMode())
	}
}

func TestChangedCertificateRejected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pins := &MemoryPins{Pin: "AB:CD:" + "00112233445566778899aabbccddeeff00112233445566778899aabbcc"}
	err := get(t, srv, &Trust{Host: host(srv), Pins: pins})
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
}

func TestPresetPinAccepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pin := SPKIHash(srv.Certificate())
	// Format the way an admin might paste it: upper case with colons.
	pretty := ""
	for i := 0; i < len(pin); i += 2 {
		if i > 0 {
			pretty += ":"
		}
		pretty += pin[i : i+2]
	}
	tr := &Trust{Host: host(srv), Pins: &MemoryPins{Pin: pretty}}
	if err := get(t, srv, tr); err != nil || tr.LastMode() != ModePinned {
		t.Fatalf("err=%v mode=%s", err, tr.LastMode())
	}
}

func TestNoPinStoreRequiresTrustedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if err := get(t, srv, &Trust{Host: host(srv)}); err == nil {
		t.Fatal("self-signed certificate accepted with no pin store")
	}
	tr := &Trust{Host: host(srv), Roots: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	if err := get(t, srv, tr); err != nil || tr.LastMode() != ModeSystem {
		t.Fatalf("trusted CA: err=%v mode=%s", err, tr.LastMode())
	}
}
