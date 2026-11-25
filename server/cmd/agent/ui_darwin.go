//go:build darwin

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Mac app window. The app shown in the Dock (SecureTunnel.app) opens the
// same web UI as the Windows app in a browser window. It's served on
// 127.0.0.1 by a per-user helper (LaunchAgent com.securetunnel.ui), which
// forwards requests to the root daemon and runs the Microsoft sign-in in
// the user's session. Every request needs a random token, and the Host
// header must be 127.0.0.1, so other websites and local users can't drive it.

//go:embed web/index.html web/app.css web/app.js
var webFS embed.FS

type uiState struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

func uiStatePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "SecureTunnel", "ui.json")
}

const shim = `<script>
(() => {
  const T = %q;
  const post = (path, body) => fetch(path, { method: "POST", headers: { "X-ST-Token": T, "Content-Type": "application/json" }, body });
  window.stCall = (req) => post("/api/call", req).then((r) => r.text());
  window.stEntra = (seq) => { post("/api/entra?seq=" + seq, "{}").then(() => {
      const poll = async () => {
        const r = await fetch("/api/entra/result?seq=" + seq, { headers: { "X-ST-Token": T } });
        if (r.status === 204) { setTimeout(poll, 1000); return; }
        const res = await r.json();
        if (window.stEntraDone) window.stEntraDone(res, seq);
      };
      setTimeout(poll, 1000);
    }); return Promise.resolve(true); };
  window.stEntraCancel = () => post("/api/entra/cancel", "{}").then(() => true);
})();
</script>
<style>body{max-width:460px;margin:0 auto;box-shadow:0 0 0 1px var(--border)}</style>`

func pageHTML(token string) string {
	html, _ := webFS.ReadFile("web/index.html")
	css, _ := webFS.ReadFile("web/app.css")
	js, _ := webFS.ReadFile("web/app.js")
	page := strings.Replace(string(html), "<!--CSS-->", "<style>"+string(css)+"</style>", 1)
	page = strings.Replace(page, "<!--JS-->", fmt.Sprintf(shim, token)+"<script>"+string(js)+"</script>", 1)
	page = strings.Replace(page, "<title>SecureTunnel</title>", "<title>SecureTunnel</title>", 1)
	return strings.Replace(page, "{{VERSION}}", version, 1)
}

type entraJob struct {
	seq  string
	done bool
	resp map[string]any
}

// runUI is the per-user helper (LaunchAgent): serves the window's page.
func runUI() error {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	// A stable port per user keeps the window's saved settings (theme);
	// fall back to any free port.
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(47000+os.Getuid()%1000))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	port := ln.Addr().(*net.TCPAddr).Port
	host := "127.0.0.1:" + strconv.Itoa(port)
	_ = os.MkdirAll(filepath.Dir(uiStatePath()), 0o700)
	sb, _ := json.Marshal(uiState{Port: port, Token: token})
	if err := os.WriteFile(uiStatePath(), sb, 0o600); err != nil {
		return err
	}

	var mu sync.Mutex
	jobs := map[string]*entraJob{}
	authed := func(r *http.Request) bool {
		return r.Host == host && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-ST-Token")), []byte(token)) == 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(token)) != 1 {
			http.Error(w, "Open SecureTunnel from Applications.", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = io.WriteString(w, pageHTML(token))
	})
	mux.HandleFunc("POST /api/call", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req ipcRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Cmd == "connect" {
			addUserProof(&req)
		}
		timeout := 15 * time.Second
		if req.Cmd == "connect" || req.Cmd == "disconnect" || req.Cmd == "diagnose" || req.Cmd == "send_logs" {
			timeout = 200 * time.Second
		}
		resp, err := pipeCall(req, timeout)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "service_down": true,
				"error": "The SecureTunnel background service isn't running. Restart the Mac or reinstall SecureTunnel."})
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST /api/entra", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		seq := r.URL.Query().Get("seq")
		job := &entraJob{seq: seq}
		mu.Lock()
		jobs = map[string]*entraJob{seq: job} // only the latest attempt matters
		mu.Unlock()
		go func() {
			resp := runEntraConnect()
			mu.Lock()
			job.done, job.resp = true, resp
			mu.Unlock()
		}()
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /api/entra/result", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mu.Lock()
		job := jobs[r.URL.Query().Get("seq")]
		mu.Unlock()
		if job == nil || !job.done {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job.resp)
	})
	mux.HandleFunc("POST /api/entra/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		cancelEntra()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// openApp is what SecureTunnel.app runs: open the window, starting the
// helper first if needed.
func openApp() error {
	st, ok := readUIState()
	if !ok {
		uid := strconv.Itoa(os.Getuid())
		_ = exec.Command("/bin/launchctl", "kickstart", "gui/"+uid+"/com.securetunnel.ui").Run()
		for i := 0; i < 20 && !ok; i++ {
			time.Sleep(250 * time.Millisecond)
			st, ok = readUIState()
		}
		if !ok {
			// No LaunchAgent (e.g. run from a build folder): serve in the background.
			exe, _ := os.Executable()
			cmd := exec.Command(exe, "ui")
			if err := cmd.Start(); err != nil {
				return err
			}
			for i := 0; i < 20 && !ok; i++ {
				time.Sleep(250 * time.Millisecond)
				st, ok = readUIState()
			}
			if !ok {
				return errors.New("couldn't start the SecureTunnel window")
			}
		}
	}
	return openWindow(fmt.Sprintf("http://127.0.0.1:%d/?t=%s", st.Port, st.Token))
}

func readUIState() (uiState, bool) {
	var st uiState
	b, err := os.ReadFile(uiStatePath())
	if err != nil || json.Unmarshal(b, &st) != nil || st.Port == 0 {
		return st, false
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(st.Port), 500*time.Millisecond)
	if err != nil {
		return st, false
	}
	c.Close()
	return st, true
}

// openWindow opens the page as an app window in Chrome or Edge when one is
// installed (no tabs or address bar), otherwise in the default browser.
func openWindow(url string) error {
	for _, app := range []string{"Google Chrome", "Microsoft Edge"} {
		if _, err := os.Stat("/Applications/" + app + ".app"); err == nil {
			return exec.Command("/usr/bin/open", "-na", app, "--args", "--app="+url, "--window-size=460,760").Run()
		}
	}
	return exec.Command("/usr/bin/open", url).Run()
}

// ---- Microsoft sign-in (runs in the user's session) ----

func openBrowser(u string) error {
	// Microsoft Edge passes the device identity to Entra (Platform SSO /
	// Company Portal); otherwise the default browser.
	if _, err := os.Stat("/Applications/Microsoft Edge.app"); err == nil {
		if exec.Command("/usr/bin/open", "-a", "Microsoft Edge", u).Run() == nil {
			return nil
		}
	}
	return exec.Command("/usr/bin/open", u).Run()
}

func addUserProof(req *ipcRequest) {
	resp, err := pipeCall(ipcRequest{Cmd: "challenge"}, 15*time.Second)
	if err != nil || !resp.OK || resp.Challenge == nil {
		return
	}
	req.Challenge = resp.Challenge
}

func runEntraConnect() map[string]any {
	fail := func(err error) map[string]any { return map[string]any{"ok": false, "error": err.Error()} }
	resp, err := pipeCall(ipcRequest{Cmd: "auth_config"}, 15*time.Second)
	if err != nil {
		return map[string]any{"ok": false, "service_down": true,
			"error": "The SecureTunnel background service isn't running. Restart the Mac or reinstall SecureTunnel."}
	}
	if !resp.OK || resp.Auth == nil {
		if resp.Error == "" {
			resp.Error = "couldn't get the sign-in settings from the server"
		}
		return fail(errors.New(resp.Error))
	}
	r, err := entraSignIn(context.Background(), *resp.Auth)
	if err != nil {
		return fail(err)
	}
	creq := ipcRequest{Cmd: "connect_token", Token: r.Token, Username: r.User}
	addUserProof(&creq)
	cresp, err := pipeCall(creq, 200*time.Second)
	if err != nil {
		return fail(errors.New("the SecureTunnel background service isn't running"))
	}
	b, _ := json.Marshal(cresp)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// signedInNote is shown on the success page.
const signedInNote = "SecureTunnel is connecting. You can close this tab."

// closeSignInWindow: on the Mac the browser tab stays (it says it can be closed).
func closeSignInWindow() {}
