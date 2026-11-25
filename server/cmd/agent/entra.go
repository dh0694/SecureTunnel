//go:build windows || darwin

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/clientapi"
)

// Sign in with Microsoft, run by the GUI (it runs as the signed-in user, so
// it can open their browser). OAuth 2.0 authorization code flow with PKCE
// for a public client: the browser comes back to http://localhost:<port>,
// we swap the code for an access token at Entra, and hand only that token to
// the service, which connects with it. Conditional Access applies as usual
// (MFA, compliant/hybrid-joined device, sign-in frequency).

type entraResult struct {
	Token string
	User  string
	Name  string
}

var (
	entraMu     sync.Mutex
	entraCancel context.CancelFunc
)

// cancelEntra stops a sign-in that is waiting for the browser.
func cancelEntra() {
	entraMu.Lock()
	defer entraMu.Unlock()
	if entraCancel != nil {
		entraCancel()
		entraCancel = nil
	}
}

func b64url(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// entraSignIn runs the browser sign-in and returns an access token for the VPN.
func entraSignIn(parent context.Context, cfg clientapi.AuthConfig) (entraResult, error) {
	if cfg.Entra == nil {
		return entraResult{}, errors.New("Microsoft sign-in isn't turned on for this server")
	}
	e := cfg.Entra
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	entraMu.Lock()
	if entraCancel != nil {
		entraCancel()
	}
	entraCancel = cancel
	entraMu.Unlock()
	defer cancel()

	// Loopback listener on a random port. Entra accepts any port for a
	// registered http://localhost redirect URI. Browsers may resolve
	// localhost to ::1 first, so listen there too when possible.
	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return entraResult{}, fmt.Errorf("couldn't start the sign-in listener: %w", err)
	}
	port := ln4.Addr().(*net.TCPAddr).Port
	listeners := []net.Listener{ln4}
	if ln6, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", port)); err == nil {
		listeners = append(listeners, ln6)
	}
	redirect := fmt.Sprintf("http://localhost:%d", port)

	state, verifier, nonce := b64url(24), b64url(48), b64url(24)
	sum := sha256.Sum256([]byte(verifier))
	// Without "ask every time", send no prompt: Edge then signs in silently
	// with the Windows account (single sign-on).
	prompt := ""
	if e.PromptLogin {
		prompt = "login"
	}
	scope := e.Scope + " openid profile"
	q := url.Values{
		"client_id":             {e.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"response_mode":         {"query"},
		"scope":                 {scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	authURL := strings.TrimRight(e.Authority, "/") + "/oauth2/v2.0/authorize?" + q.Encode()

	type cb struct {
		code string
		err  error
	}
	done := make(chan cb, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		v := r.URL.Query()
		var res cb
		switch {
		case v.Get("state") != state:
			res.err = errors.New("the sign-in response didn't match; try again")
		case v.Get("error") != "":
			desc := v.Get("error_description")
			if i := strings.IndexAny(desc, "\r\n"); i > 0 {
				desc = desc[:i]
			}
			if v.Get("error") == "access_denied" && desc == "" {
				desc = "sign-in was cancelled"
			}
			res.err = fmt.Errorf("Microsoft sign-in failed: %s", strings.TrimSpace(v.Get("error")+" "+desc))
		case v.Get("code") == "":
			res.err = errors.New("Microsoft didn't return a sign-in code")
		default:
			res.code = v.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		title, msg := "You're signed in", signedInNote
		pageTitle := signedInTitle
		if res.err != nil {
			title, msg = "Sign-in didn't finish", res.err.Error()
			pageTitle = "SecureTunnel - sign-in failed"
		}
		_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>`+pageTitle+`</title>`+
			`<style>body{font:15px/1.5 "Segoe UI",system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f6f8;color:#16191f}`+
			`div{background:#fff;border:1px solid #e3e6eb;border-radius:12px;padding:28px 32px;max-width:420px;text-align:center}h1{font-size:19px;margin:0 0 6px}p{margin:0;color:#4b5260}</style>`+
			`<div><h1>`+html.EscapeString(title)+`</h1><p>`+html.EscapeString(msg)+`</p></div>`)
		select {
		case done <- res:
		default:
		}
		if res.err == nil {
			// Close the sign-in window once the page has shown.
			go func() {
				time.Sleep(1500 * time.Millisecond)
				closeSignInWindow()
			}()
		}
	})}
	for _, l := range listeners {
		go func(l net.Listener) { _ = srv.Serve(l) }(l)
	}
	defer func() {
		sctx, c := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(sctx)
		c()
	}()

	if err := openBrowser(authURL); err != nil {
		return entraResult{}, fmt.Errorf("couldn't open your browser: %w", err)
	}

	var res cb
	select {
	case res = <-done:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return entraResult{}, errors.New("sign-in timed out; try again")
		}
		return entraResult{}, errors.New("sign-in cancelled")
	}
	if res.err != nil {
		return entraResult{}, res.err
	}
	return redeemCode(ctx, e.Authority, e.ClientID, res.code, redirect, verifier, scope, nonce)
}

var tokenHTTP = &http.Client{Timeout: 20 * time.Second}

func redeemCode(ctx context.Context, authority, clientID, code, redirect, verifier, scope, nonce string) (entraResult, error) {
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"scope":         {scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authority, "/")+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return entraResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tokenHTTP.Do(req)
	if err != nil {
		return entraResult{}, fmt.Errorf("couldn't reach Microsoft: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Desc        string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return entraResult{}, fmt.Errorf("unexpected answer from Microsoft: %w", err)
	}
	if out.Error != "" {
		d := out.Desc
		if i := strings.IndexAny(d, "\r\n"); i > 0 {
			d = d[:i]
		}
		return entraResult{}, fmt.Errorf("Microsoft sign-in failed: %s %s", out.Error, d)
	}
	if out.AccessToken == "" {
		return entraResult{}, errors.New("Microsoft didn't return an access token")
	}
	// The ID token came straight from Entra over TLS; we read it only for the
	// name shown in the app. The server verifies the access token itself.
	r := entraResult{Token: out.AccessToken}
	if parts := strings.Split(out.IDToken, "."); len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var c struct {
				UPN   string `json:"preferred_username"`
				Name  string `json:"name"`
				Nonce string `json:"nonce"`
			}
			if json.Unmarshal(b, &c) == nil && c.Nonce == nonce {
				r.User, r.Name = strings.ToLower(c.UPN), c.Name
			}
		}
	}
	return r, nil
}

// signedInTitle is the success page's title; the Windows app finds the
// sign-in window by it and closes it.
const signedInTitle = "SecureTunnel - signed in"
