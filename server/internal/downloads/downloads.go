// Package downloads serves the client downloads page (/downloads/): a
// ready-to-run Windows bundle with the server address filled in, plus the raw
// client binaries with SHA-256 checksums. Responses carry cache headers so a
// CDN in front (e.g. Cloudflare) can serve them from its edge.
package downloads

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/macagent"
	"securetunnel/server/internal/macpkg"
)

// Handler serves the downloads page and files.
type Handler struct {
	Dir       string // directory holding the client binaries
	PublicURL string // e.g. https://vpn.example.com; falls back to the request host
	Log       *slog.Logger
	// Offer decides, per PC, whether the latest version is offered now (pause
	// and staged rollout) and gives the install policy to send along. force is
	// set when the admin site pushed the update. nil: always offer, no policy.
	Offer func(r *http.Request, deviceID, latest string, force bool) (offer bool, held string, policy any)

	mu      sync.Mutex
	bundles map[string]cached // keyed by server URL
	sums    map[string]cached // keyed by file name
}

type cached struct {
	data    []byte
	sum     string
	modTime time.Time
}

type fileInfo struct {
	Name, Label, OS, Size, SHA256, URL string
}

// bundleName is the Windows test-client bundle's file name.
const bundleName = "SecureTunnel-Windows.zip"

// installerName is the Windows agent installer's file name.
const installerName = "SecureTunnel-Setup.exe"

// Register adds /downloads/ routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /downloads/{$}", h.page)
	mux.HandleFunc("GET /downloads", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/downloads/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /downloads/"+bundleName, h.bundle)
	mux.HandleFunc("GET /downloads/"+macZipName, h.macZip)
	mux.HandleFunc("GET /downloads/"+macPkgName, h.macPkg)
	mux.HandleFunc("GET /downloads/files/{name}", h.file)
	mux.HandleFunc("GET /v1/client/version", h.version)
}

// ClientVersion tells agents which installer is current, for self-updates.
type ClientVersion struct {
	Version string `json:"version"` // "" when this PC isn't offered an update right now
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
	Size    int    `json:"size"`
	// Held says why a newer version isn't offered yet ("paused" or "rollout");
	// Latest is that version.
	Held   string `json:"held,omitempty"`
	Latest string `json:"latest,omitempty"`
	Policy any    `json:"policy,omitempty"` // how and when to install (model.UpdatePolicy)
}

// LatestVersion returns the Windows agent version on this server ("" if none).
func (h *Handler) LatestVersion() string {
	v, err := os.ReadFile(filepath.Join(h.Dir, "windows-version.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(v))
}

// version returns the current Windows agent version (written at build time to
// windows-version.txt next to the installer) and the installer's checksum.
func (h *Handler) version(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("platform") == "macos" {
		h.macVersion(w, r)
		return
	}
	v, err := os.ReadFile(filepath.Join(h.Dir, "windows-version.txt"))
	c, err2 := h.fileSum(installerName)
	if err != nil || err2 != nil {
		http.Error(w, `{"error":"not_available","message":"no Windows installer on this server"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	resp := ClientVersion{
		Version: strings.TrimSpace(string(v)), SHA256: c.sum,
		URL: "/downloads/files/" + installerName, Size: len(c.data),
	}
	if h.Offer != nil {
		q := r.URL.Query()
		offer, held, policy := h.Offer(r, q.Get("device_id"), resp.Version, q.Get("force") == "1")
		resp.Policy = policy
		if !offer { // paused, or not in this rollout yet: nothing newer for this PC
			resp.Held, resp.Latest = held, resp.Version
			resp.Version, resp.SHA256, resp.URL, resp.Size = "", "", "", 0
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) serverURL(r *http.Request) string {
	if h.PublicURL != "" {
		return strings.TrimRight(h.PublicURL, "/")
	}
	return "https://" + r.Host
}

// binaries lists the client binaries in Dir.
func (h *Handler) binaries() []fileInfo {
	entries, err := os.ReadDir(h.Dir)
	if err != nil {
		return nil
	}
	var out []fileInfo
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".crt") || strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		c, err := h.fileSum(e.Name())
		if err != nil {
			continue
		}
		f := fileInfo{Name: e.Name(), Size: human(int64(len(c.data))), SHA256: c.sum, URL: "files/" + e.Name()}
		switch {
		case e.Name() == installerName:
			f.Label, f.OS = "Installer", "Windows x64"
		case e.Name() == "securetunnel.exe":
			f.Label, f.OS = "Agent (exe only, for troubleshooting)", "Windows x64"
		case strings.HasSuffix(e.Name(), ".exe"):
			f.Label, f.OS = "Test client (exe only)", "Windows x64"
		case strings.Contains(e.Name(), "linux"):
			f.Label, f.OS = "Test client", "Linux x64"
		default:
			f.Label, f.OS = e.Name(), ""
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OS > out[j].OS })
	return out
}

func (h *Handler) fileSum(name string) (cached, error) {
	path := filepath.Join(h.Dir, filepath.Base(name))
	st, err := os.Stat(path)
	if err != nil {
		return cached{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sums == nil {
		h.sums = map[string]cached{}
	}
	if c, ok := h.sums[name]; ok && c.modTime.Equal(st.ModTime()) {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cached{}, err
	}
	s := sha256.Sum256(b)
	c := cached{data: b, sum: hex.EncodeToString(s[:]), modTime: st.ModTime()}
	h.sums[name] = c
	return c, nil
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	if strings.HasSuffix(name, ".crt") || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	c, err := h.fileSum(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	serve(w, r, name, c)
}

func (h *Handler) bundle(w http.ResponseWriter, r *http.Request) {
	c, err := h.buildBundle(h.serverURL(r))
	if err != nil {
		h.Log.Error("build windows bundle", "err", err)
		http.Error(w, "Windows client not available on this server", http.StatusNotFound)
		return
	}
	serve(w, r, bundleName, c)
}

// noStore tells browsers and CDNs (including Cloudflare) not to cache.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
}

func serve(w http.ResponseWriter, r *http.Request, name string, c cached) {
	etag := `"` + c.sum[:32] + `"`
	w.Header().Set("ETag", etag)
	// No caching anywhere for now (browser or Cloudflare), so a rebuild is
	// visible immediately. Re-enable edge caching once releases settle down.
	noStore(w)
	w.Header().Set("X-Content-SHA256", c.sum)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctype := "application/octet-stream"
	if strings.HasSuffix(name, ".zip") {
		ctype = "application/zip"
	}
	w.Header().Set("Content-Type", ctype)
	http.ServeContent(w, r, "", c.modTime, bytes.NewReader(c.data))
}

// buildBundle makes the Windows zip with the server URL baked into Connect.cmd.
func (h *Handler) buildBundle(server string) (cached, error) {
	exe, err := h.fileSum("stclient.exe")
	if err != nil {
		return cached{}, err
	}
	h.mu.Lock()
	if c, ok := h.bundles[server]; ok && !exe.modTime.After(c.modTime) {
		h.mu.Unlock()
		return c, nil
	}
	h.mu.Unlock()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: "SecureTunnel/" + name, Method: zip.Deflate, Modified: exe.modTime})
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	crlf := func(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }
	if err := add("stclient.exe", exe.data); err != nil {
		return cached{}, err
	}
	if err := add("Connect.cmd", crlf(fmt.Sprintf(connectCmd, server))); err != nil {
		return cached{}, err
	}
	if err := add("README.txt", crlf(fmt.Sprintf(readme, server, exe.sum))); err != nil {
		return cached{}, err
	}
	if err := zw.Close(); err != nil {
		return cached{}, err
	}
	s := sha256.Sum256(buf.Bytes())
	c := cached{data: buf.Bytes(), sum: hex.EncodeToString(s[:]), modTime: exe.modTime}
	h.mu.Lock()
	if h.bundles == nil {
		h.bundles = map[string]cached{}
	}
	h.bundles[server] = c
	h.mu.Unlock()
	return c, nil
}

func (h *Handler) page(w http.ResponseWriter, r *http.Request) {
	server := h.serverURL(r)
	data := struct {
		Server     string
		ServerHost string
		Installer  *fileInfo
		Bundle     *fileInfo
		MacPkg     *fileInfo
		MacZip     *fileInfo
		MacVersion string
		Files      []fileInfo
		Missing    bool
	}{Server: server, ServerHost: strings.TrimPrefix(server, "https://"), Files: h.binaries()}
	if m, ok := h.macMeta(); ok {
		data.MacVersion = m.Version
		if c, err := h.buildMacZip(server); err == nil {
			data.MacZip = &fileInfo{Name: macZipName, Size: human(int64(len(c.data))), SHA256: c.sum, URL: macZipName}
		}
		if c, err := h.buildMacPkg(server); err == nil {
			data.MacPkg = &fileInfo{Name: macPkgName, Size: human(int64(len(c.data))), SHA256: c.sum, URL: macPkgName}
		}
	}
	for i := range data.Files {
		if data.Files[i].Name == installerName {
			f := data.Files[i]
			data.Installer = &f
		}
	}
	if c, err := h.buildBundle(server); err == nil {
		data.Bundle = &fileInfo{Name: bundleName, Size: human(int64(len(c.data))), SHA256: c.sum, URL: bundleName}
	}
	data.Missing = data.Bundle == nil && len(data.Files) == 0
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	noStore(w)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'")
	if err := pageTmpl.Execute(w, data); err != nil {
		h.Log.Error("render downloads page", "err", err)
	}
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

const connectCmd = `@echo off
title SecureTunnel
cd /d "%%~dp0"
echo SecureTunnel test client
echo Server: %[1]s
echo.
stclient.exe -server %[1]s -out "%%USERPROFILE%%\Desktop\SecureTunnel.conf"
echo.
pause
`

const readme = `SecureTunnel test client
========================

Server: %[1]s

1. Install WireGuard for Windows: https://www.wireguard.com/install/
2. Unzip this folder anywhere (for example your Desktop).
3. Double-click Connect.cmd and sign in with your SecureTunnel username and
   password (and authenticator code, if your account has one).
4. It writes SecureTunnel.conf to your Desktop. In WireGuard choose
   "Import tunnel(s) from file", pick that file, then click Activate.
5. Leave the Connect window open: it keeps your session alive. Close it (or
   press Ctrl+C) to disconnect, then deactivate the tunnel in WireGuard.

Your session survives network drops of up to 15 minutes without signing in
again. After a disconnect, a reboot, or 12 hours, run Connect.cmd again.

Windows may warn that stclient.exe is from an unknown publisher: it is not
code-signed yet. Choose "More info" then "Run anyway".

stclient.exe SHA-256: %[2]s
`

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><title>SecureTunnel downloads</title>
<style>
:root{--bg:#f5f6f8;--s:#fff;--s2:#f1f3f6;--t:#16191f;--m:#6b7280;--b:#e3e6eb;--a:#2557d6;--ah:#1d47b3;--wb:#fff3db;--w:#9a5b00}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--s:#171a20;--s2:#1e222a;--t:#e8eaee;--m:#8b93a1;--b:#262b34;--a:#6d95ff;--ah:#8aaaff;--wb:#3a2a0d;--w:#f2b14c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:40px 16px 60px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:17px;margin-bottom:28px}
.logo{width:30px;height:30px;border-radius:8px;background:var(--a);display:inline-block}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.01em}h2{font-size:16px;margin:0 0 12px}
.muted{color:var(--m)}.card{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:22px 24px;margin-top:20px}
.hero{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.hero .grow{flex:1;min-width:220px}
.btn{display:inline-flex;align-items:center;gap:8px;background:var(--a);color:#fff;text-decoration:none;font-weight:600;padding:11px 20px;border-radius:8px}
.btn:hover{background:var(--ah)}
ol{margin:0;padding-left:20px}li{margin:6px 0}code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
code{background:var(--s2);padding:1px 6px;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid var(--b);vertical-align:top}
th{color:var(--m);font-weight:500;font-size:13px}tr:last-child td{border-bottom:0}a{color:var(--a)}
.sha{word-break:break-all;color:var(--m);font-size:12px}.note{background:var(--wb);color:var(--w);border-radius:8px;padding:10px 14px;font-size:14px;margin-top:14px}
</style></head><body><div class="wrap">
<div class="brand"><span class="logo"></span>SecureTunnel</div>
<h1>Download the client</h1>
<p class="muted">Server: <span class="mono">{{.Server}}</span></p>
{{if .Missing}}<div class="card"><p>No client downloads are available on this server yet.</p></div>{{end}}
{{with .Installer}}<div class="card hero">
  <div class="grow"><h2>SecureTunnel for Windows</h2><div class="muted">Windows 10 and 11, 64-bit · {{.Size}}</div></div>
  <a class="btn" href="{{.URL}}" download>Download installer</a>
</div>
<div class="card"><h2>Install</h2><ol>
  <li>Run <code>SecureTunnel-Setup.exe</code> and follow the steps.</li>
  <li>SecureTunnel opens and asks for the server: enter <code>{{$.ServerHost}}</code>.</li>
  <li>Sign in with your SecureTunnel username and password, then click <b>Connect</b>.</li>
</ol>
<p class="muted" style="margin-top:12px">Silent install (Intune or a script), with the server already set:</p>
<p><code>SecureTunnel-Setup.exe /S /SERVER={{$.ServerHost}}</code></p>
<div class="note">The installer isn't code-signed yet, so Windows may say it's from an unknown publisher. Choose <b>More info</b>, then <b>Run anyway</b>.</div></div>{{end}}
{{if or .MacPkg .MacZip}}<div class="card hero">
  <div class="grow"><h2>SecureTunnel for Mac</h2><div class="muted">macOS 12 or later, Apple silicon and Intel · version {{.MacVersion}}</div></div>
  {{with .MacPkg}}<a class="btn" href="{{.URL}}" download>Download installer (.pkg)</a>{{end}}
  {{with .MacZip}}<a class="btn" href="{{.URL}}" download {{if $.MacPkg}}style="background:var(--s2);color:var(--t)"{{end}}>Download zip</a>{{end}}
</div>
<div class="card"><h2>Install on a Mac</h2><ol>
  {{if .MacPkg}}<li>Open <code>SecureTunnel.pkg</code>. If macOS says it can't check it, open <b>System Settings → Privacy &amp; Security</b> and choose <b>Open Anyway</b>.</li>{{else}}<li>Unzip the download, open Terminal in the folder and run <code>sudo ./install.sh</code>.</li>{{end}}
  <li>SecureTunnel opens with the server <code>{{.ServerHost}}</code> already set. Sign in to connect.</li>
</ol>
<p class="muted" style="margin-top:12px">MDM (Intune, Jamf): deploy the .pkg, and set the server with a configuration profile for <code>com.securetunnel.agent</code>, key <code>Server</code>.</p>
<div class="note">The Mac app isn't signed or notarized by Apple yet, so macOS warns the first time.</div></div>{{end}}
{{with .Bundle}}<div class="card hero">
  <div class="grow"><h2>Test client (no install)</h2><div class="muted">Console client that uses the WireGuard app · {{.Size}}</div></div>
  <a class="btn" href="{{.URL}}" download>Download test client</a>
</div>
{{if not $.Installer}}<div class="card"><h2>Set up the test client</h2><ol>
  <li>Install <a href="https://www.wireguard.com/install/" rel="noopener noreferrer">WireGuard for Windows</a>.</li>
  <li>Unzip the download and double-click <code>Connect.cmd</code>.</li>
  <li>Sign in with your SecureTunnel username and password.</li>
  <li>In WireGuard, choose <b>Import tunnel(s) from file</b>, pick <code>SecureTunnel.conf</code> from your Desktop, then <b>Activate</b>.</li>
  <li>Leave the Connect window open while you're connected. Close it to disconnect.</li>
</ol></div>{{end}}{{end}}
{{if or .Bundle .Files}}<div class="card"><h2>All files</h2><table><thead><tr><th>File</th><th>Platform</th><th>Size</th></tr></thead><tbody>
{{with .Bundle}}<tr><td><a href="{{.URL}}" download>{{.Name}}</a> <span class="muted">Test client bundle</span><div class="sha">SHA-256 {{.SHA256}}</div></td><td>Windows x64</td><td>{{.Size}}</td></tr>{{end}}
{{range .Files}}<tr><td><a href="{{.URL}}" download>{{.Name}}</a> <span class="muted">{{.Label}}</span><div class="sha">SHA-256 {{.SHA256}}</div></td><td>{{.OS}}</td><td>{{.Size}}</td></tr>{{end}}
</tbody></table></div>{{end}}
</div></body></html>`))

// ---- Mac agent ----

const (
	macZipName = "SecureTunnel-macOS.zip"
	macPkgName = "SecureTunnel.pkg"
)

type macMeta struct {
	Version string `json:"version"`
	Files   int    `json:"files"`
	KBytes  int    `json:"kbytes"`
	Built   int64  `json:"built"`
	Pkg     bool   `json:"pkg"`
}

func (h *Handler) macDir() string { return filepath.Join(h.Dir, "macos") }

func (h *Handler) macMeta() (macMeta, bool) {
	var m macMeta
	b, err := os.ReadFile(filepath.Join(h.macDir(), "meta.json"))
	if err != nil || json.Unmarshal(b, &m) != nil || m.Version == "" {
		return m, false
	}
	return m, true
}

func (h *Handler) macCached(key string, build func() ([]byte, error)) (cached, error) {
	m, ok := h.macMeta()
	if !ok {
		return cached{}, os.ErrNotExist
	}
	built := time.Unix(m.Built, 0)
	h.mu.Lock()
	if c, ok := h.bundles[key]; ok && !built.After(c.modTime) {
		h.mu.Unlock()
		return c, nil
	}
	h.mu.Unlock()
	b, err := build()
	if err != nil {
		return cached{}, err
	}
	s := sha256.Sum256(b)
	c := cached{data: b, sum: hex.EncodeToString(s[:]), modTime: built}
	h.mu.Lock()
	if h.bundles == nil {
		h.bundles = map[string]cached{}
	}
	h.bundles[key] = c
	h.mu.Unlock()
	return c, nil
}

// buildMacZip makes the zip installer with this server baked into it.
func (h *Handler) buildMacZip(server string) (cached, error) {
	return h.macCached("maczip|"+server, func() ([]byte, error) {
		m, _ := h.macMeta()
		arm, err := os.ReadFile(filepath.Join(h.macDir(), "securetunnel-arm64"))
		if err != nil {
			return nil, err
		}
		amd, err := os.ReadFile(filepath.Join(h.macDir(), "securetunnel-x86_64"))
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		mod := time.Unix(m.Built, 0)
		for _, f := range macagent.ZipFiles(arm, amd, m.Version, server) {
			hdr := &zip.FileHeader{Name: "SecureTunnel/" + f.Name, Method: zip.Deflate, Modified: mod}
			hdr.SetMode(os.FileMode(f.Mode))
			w, err := zw.CreateHeader(hdr)
			if err != nil {
				return nil, err
			}
			if _, err := w.Write(f.Data); err != nil {
				return nil, err
			}
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	})
}

// buildMacPkg makes the .pkg with this server baked into its postinstall.
func (h *Handler) buildMacPkg(server string) (cached, error) {
	m, ok := h.macMeta()
	if !ok || !m.Pkg {
		return cached{}, os.ErrNotExist
	}
	return h.macCached("macpkg|"+server, func() ([]byte, error) {
		payload, err := os.ReadFile(filepath.Join(h.macDir(), "Payload"))
		if err != nil {
			return nil, err
		}
		bom, err := os.ReadFile(filepath.Join(h.macDir(), "Bom"))
		if err != nil {
			return nil, err
		}
		built := time.Unix(m.Built, 0)
		scripts, err := macagent.Scripts(server, built)
		if err != nil {
			return nil, err
		}
		info := macagent.Info(m.Version, m.Files, m.KBytes)
		return macpkg.Build(macpkg.Parts{Distribution: macpkg.Distribution(info), PkgName: macagent.PkgName,
			PackageInfo: macpkg.PackageInfo(info), Bom: bom, Payload: payload, Scripts: scripts}, built)
	})
}

func (h *Handler) macZip(w http.ResponseWriter, r *http.Request) {
	c, err := h.buildMacZip(h.serverURL(r))
	if err != nil {
		http.Error(w, "Mac client not available on this server", http.StatusNotFound)
		return
	}
	serve(w, r, macZipName, c)
}

func (h *Handler) macPkg(w http.ResponseWriter, r *http.Request) {
	c, err := h.buildMacPkg(h.serverURL(r))
	if err != nil {
		http.Error(w, "Mac installer package not available on this server", http.StatusNotFound)
		return
	}
	serve(w, r, macPkgName, c)
}

// macVersion tells Mac agents about the current package, for self-updates.
func (h *Handler) macVersion(w http.ResponseWriter, r *http.Request) {
	m, ok := h.macMeta()
	c, err := h.buildMacPkg(h.serverURL(r))
	if !ok || err != nil {
		http.Error(w, `{"error":"not_available","message":"no Mac installer package on this server"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	_ = json.NewEncoder(w).Encode(ClientVersion{Version: m.Version, SHA256: c.sum, URL: "/downloads/" + macPkgName, Size: len(c.data)})
}
