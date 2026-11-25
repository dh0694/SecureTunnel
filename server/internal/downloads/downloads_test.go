package downloads

import (
	"archive/zip"
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) *http.ServeMux {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"stclient.exe": "MZ-fake-exe", "stclient-linux": "ELF-fake", "securetunnel-ca.crt": "secret-ish"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	(&Handler{Dir: dir, PublicURL: "https://vpn.example.com", Log: slog.Default()}).Register(mux)
	return mux
}

func get(mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestBundleContainsConfiguredConnectScript(t *testing.T) {
	mux := setup(t)
	rec := get(mux, "/downloads/"+bundleName)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("X-Content-SHA256") == "" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") ||
		rec.Header().Get("Cloudflare-CDN-Cache-Control") != "no-store" {
		t.Errorf("missing checksum or no-cache headers: %v", rec.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	cmd := files["SecureTunnel/Connect.cmd"]
	if !strings.Contains(cmd, "-server https://vpn.example.com") || !strings.Contains(cmd, `%~dp0`) || !strings.Contains(cmd, "\r\n") {
		t.Errorf("Connect.cmd not configured correctly:\n%s", cmd)
	}
	if files["SecureTunnel/stclient.exe"] != "MZ-fake-exe" {
		t.Error("bundle is missing stclient.exe")
	}
	if !strings.Contains(files["SecureTunnel/README.txt"], "https://vpn.example.com") {
		t.Error("README missing server URL")
	}
}

func TestPageListsFilesAndHidesCert(t *testing.T) {
	mux := setup(t)
	rec := get(mux, "/downloads/")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, bundleName) || !strings.Contains(body, "stclient-linux") {
		t.Fatalf("page status %d missing downloads:\n%s", rec.Code, body)
	}
	if strings.Contains(body, ".crt") {
		t.Error("page lists the certificate file")
	}
	if get(mux, "/downloads/files/securetunnel-ca.crt").Code != http.StatusNotFound {
		t.Error("certificate file is downloadable")
	}
	if get(mux, "/downloads/files/..%2f..%2fetc%2fpasswd").Code == http.StatusOK {
		t.Error("path traversal served a file")
	}
}
