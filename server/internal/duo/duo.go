// Package duo sends Duo Push (or phone call) sign-in approvals through the
// Duo Auth API, for policy groups that require Duo as an extra factor.
//
// Duo admin panel: Applications → Protect an Application → "Auth API".
// Copy the integration key, secret key and API hostname into the admin site
// (Policies → Duo).
package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/store"
)

const settingKey = "duo_settings"

// Settings are saved on the admin site. The secret key is never returned.
type Settings struct {
	APIHost        string `json:"api_host"`        // api-xxxxxxxx.duosecurity.com
	IntegrationKey string `json:"integration_key"` // DI...
	SecretKey      string `json:"secret_key,omitempty"`
	// UsernameFormat maps the VPN user to the Duo username: "upn" (whole
	// sign-in name) or "prefix" (the part before @, like sAMAccountName).
	UsernameFormat string `json:"username_format"`
}

var hostRE = regexp.MustCompile(`^api-[a-z0-9]+\.duosecurity\.com$`)

// Normalize validates the settings.
func (s *Settings) Normalize() error {
	s.APIHost = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s.APIHost, "https://"), "http://")))
	s.APIHost = strings.TrimRight(s.APIHost, "/")
	s.IntegrationKey = strings.ToUpper(strings.TrimSpace(s.IntegrationKey))
	s.SecretKey = strings.TrimSpace(s.SecretKey)
	if s.UsernameFormat != "prefix" {
		s.UsernameFormat = "upn"
	}
	if s.APIHost == "" && s.IntegrationKey == "" {
		return nil // turning Duo off
	}
	if !hostRE.MatchString(s.APIHost) {
		return errors.New("the API hostname looks like api-1a2b3c4d.duosecurity.com")
	}
	if len(s.IntegrationKey) != 20 || !strings.HasPrefix(s.IntegrationKey, "DI") {
		return errors.New("the integration key is 20 characters and starts with DI")
	}
	return nil
}

// Ready reports whether Duo is configured.
func (s Settings) Ready() bool { return s.APIHost != "" && s.IntegrationKey != "" && s.SecretKey != "" }

// Username maps a VPN user to their Duo username.
func (s Settings) Username(upn string) string {
	upn = strings.ToLower(strings.TrimSpace(upn))
	if s.UsernameFormat == "prefix" {
		if i := strings.IndexByte(upn, '@'); i > 0 {
			return upn[:i]
		}
	}
	return upn
}

// Service talks to Duo with the saved settings.
type Service struct {
	Store store.Store
	Key   []byte // signs pending-transaction tokens
	HTTP  *http.Client
	Now   func() time.Time

	mu   sync.Mutex
	used map[string]time.Time // approved transactions already used for a connect
}

func (d *Service) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Settings returns the saved settings (secret included; never send to browsers).
func (d *Service) Settings(ctx context.Context) Settings {
	var s Settings
	_, _ = d.Store.GetSetting(ctx, settingKey, &s)
	if s.UsernameFormat == "" {
		s.UsernameFormat = "upn"
	}
	return s
}

// Save stores new settings; an empty secret keeps the saved one.
func (d *Service) Save(ctx context.Context, s Settings) (Settings, error) {
	if err := s.Normalize(); err != nil {
		return s, err
	}
	if s.SecretKey == "" && s.APIHost != "" {
		s.SecretKey = d.Settings(ctx).SecretKey
	}
	if s.APIHost == "" {
		s.SecretKey = ""
	}
	if s.APIHost != "" && s.SecretKey == "" {
		return s, errors.New("paste the secret key")
	}
	return s, d.Store.SetSetting(ctx, settingKey, s)
}

// ---- Auth API ----

// sign builds the Duo v2 request signature (HMAC-SHA512).
func sign(s Settings, method, path, date string, params url.Values) string {
	canon := strings.Join([]string{date, strings.ToUpper(method), strings.ToLower(s.APIHost), path, canonParams(params)}, "\n")
	m := hmac.New(sha512.New, []byte(s.SecretKey))
	m.Write([]byte(canon))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(s.IntegrationKey+":"+hex.EncodeToString(m.Sum(nil))))
}

func canonParams(p url.Values) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range p[k] {
			parts = append(parts, escape(k)+"="+escape(v))
		}
	}
	return strings.Join(parts, "&")
}

func escape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

type duoResp struct {
	Stat     string          `json:"stat"`
	Response json.RawMessage `json:"response"`
	Code     int             `json:"code"`
	Message  string          `json:"message"`
	Detail   string          `json:"message_detail"`
}

func (d *Service) call(ctx context.Context, s Settings, method, path string, params url.Values, out any) error {
	if !s.Ready() {
		return errors.New("Duo isn't set up (Settings → Duo)")
	}
	if params == nil {
		params = url.Values{}
	}
	date := d.now().UTC().Format(time.RFC1123Z)
	u := "https://" + s.APIHost + path
	var body io.Reader
	if method == http.MethodGet {
		if len(params) > 0 {
			u += "?" + canonParams(params)
		}
	} else {
		body = strings.NewReader(canonParams(params))
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", sign(s, method, path, date, params))
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	hc := d.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach Duo: %w", err)
	}
	defer resp.Body.Close()
	var r duoResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("unexpected answer from Duo (%d)", resp.StatusCode)
	}
	if r.Stat != "OK" {
		msg := strings.TrimSpace(r.Message + " " + r.Detail)
		if r.Code == 40101 || r.Code == 40102 || r.Code == 40103 {
			msg = "Duo rejected the integration key or secret key (" + msg + ")"
		}
		return fmt.Errorf("Duo: %s", msg)
	}
	if out != nil {
		return json.Unmarshal(r.Response, out)
	}
	return nil
}

// Check verifies the settings (GET /auth/v2/check).
func (d *Service) Check(ctx context.Context) error {
	return d.call(ctx, d.Settings(ctx), http.MethodGet, "/auth/v2/check", nil, nil)
}

// Result of starting or checking a Duo sign-in.
type Result struct {
	Status  string // "allow", "deny" or "waiting"
	Message string // shown to the user
	TxID    string // Duo transaction, while waiting
}

// Start runs preauth and, when needed, sends a push (or call) to the user's
// phone without waiting for the answer.
func (d *Service) Start(ctx context.Context, upn, clientIP, device string) (Result, error) {
	s := d.Settings(ctx)
	user := s.Username(upn)
	var pre struct {
		Result    string `json:"result"`
		StatusMsg string `json:"status_msg"`
	}
	p := url.Values{"username": {user}}
	if ip := strings.TrimSpace(clientIP); ip != "" {
		p.Set("ipaddr", ip)
	}
	if err := d.call(ctx, s, http.MethodPost, "/auth/v2/preauth", p, &pre); err != nil {
		return Result{}, err
	}
	switch pre.Result {
	case "allow":
		return Result{Status: "allow", Message: "Duo allowed this sign-in."}, nil
	case "deny":
		return Result{Status: "deny", Message: "Duo denied this sign-in: " + pre.StatusMsg}, nil
	case "enroll":
		return Result{Status: "deny", Message: "You aren't set up in Duo yet (" + user + "). Contact IT."}, nil
	}
	a := url.Values{"username": {user}, "factor": {"auto"}, "device": {"auto"}, "async": {"1"},
		"type": {"VPN sign-in"}, "display_username": {upn}}
	if device != "" {
		a.Set("pushinfo", "Computer="+url.QueryEscape(device))
	}
	if ip := strings.TrimSpace(clientIP); ip != "" {
		a.Set("ipaddr", ip)
	}
	var auth struct {
		TxID string `json:"txid"`
	}
	if err := d.call(ctx, s, http.MethodPost, "/auth/v2/auth", a, &auth); err != nil {
		return Result{}, err
	}
	return Result{Status: "waiting", TxID: auth.TxID, Message: "Approve the Duo Push on your phone to finish connecting."}, nil
}

// Status checks a pending transaction.
func (d *Service) Status(ctx context.Context, txid string) (Result, error) {
	var st struct {
		Result    string `json:"result"`
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	if err := d.call(ctx, d.Settings(ctx), http.MethodGet, "/auth/v2/auth_status", url.Values{"txid": {txid}}, &st); err != nil {
		return Result{}, err
	}
	switch st.Result {
	case "allow":
		return Result{Status: "allow", Message: st.StatusMsg}, nil
	case "deny":
		msg := "Duo denied the sign-in."
		if st.Status == "timeout" {
			msg = "The Duo Push timed out. Connect again to get a new one."
		} else if st.StatusMsg != "" {
			msg = "Duo denied the sign-in: " + st.StatusMsg
		}
		return Result{Status: "deny", Message: msg}, nil
	}
	return Result{Status: "waiting", TxID: txid, Message: firstNonEmpty(st.StatusMsg, "Waiting for you to approve the Duo Push…")}, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ---- pending transaction tokens ----
//
// The agent gets a signed token naming the Duo transaction and the user; it
// polls with it and presents it again on connect. Any control server can
// check it (no shared state), and Duo is asked for the result each time.

type txToken struct {
	TxID string `json:"t"`
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

// Token returns a signed token for a pending transaction (valid 3 minutes).
func (d *Service) Token(txid, upn string) string {
	b, _ := json.Marshal(txToken{TxID: txid, User: strings.ToLower(upn), Exp: d.now().Add(3 * time.Minute).Unix()})
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, d.Key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ParseToken checks a token and returns the transaction ID and user.
func (d *Service) ParseToken(tok string) (txid, upn string, ok bool) {
	p, sig, found := strings.Cut(tok, ".")
	if !found {
		return "", "", false
	}
	m := hmac.New(sha256.New, d.Key)
	m.Write([]byte(p))
	if !hmac.Equal([]byte(sig), []byte(base64.RawURLEncoding.EncodeToString(m.Sum(nil)))) {
		return "", "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", "", false
	}
	var t txToken
	if json.Unmarshal(b, &t) != nil || d.now().Unix() > t.Exp || t.TxID == "" {
		return "", "", false
	}
	return t.TxID, t.User, true
}

// Use marks an approved transaction as used; false if it was already used
// on this server (a token is good for one connect).
func (d *Service) Use(txid string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.used == nil {
		d.used = map[string]time.Time{}
	}
	for k, at := range d.used {
		if time.Since(at) > 10*time.Minute {
			delete(d.used, k)
		}
	}
	if _, ok := d.used[txid]; ok {
		return false
	}
	d.used[txid] = time.Now()
	return true
}
