package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/session"
	"securetunnel/server/internal/store"
)

const (
	wgKey   = "YAnz2ldbyfkLT6tBkM0OC3m6/NiGdpdvq9eCnsSxk2A="
	wgKey2  = "aAnz2ldbyfkLT6tBkM0OC3m6/NiGdpdvq9eCnsSxk2A="
	gwToken = "gateway-token"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Contoso Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// proof signs nonce with a fresh device certificate for computer cn.
func (ca testCA) proof(t *testing.T, cn, nonce string) model.DeviceProof {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(model.ProofMessage(nonce, "device_cert"))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return model.DeviceProof{Kind: "device_cert", Alg: "ES256", Sig: base64.StdEncoding.EncodeToString(sig),
		Chain: []string{base64.StdEncoding.EncodeToString(der)}}
}

type rig struct {
	t   *testing.T
	srv *Server
	st  *store.Memory
	mux *http.ServeMux
	ca  testCA
}

type tokenValidatorFunc func(context.Context, string) (model.Identity, error)

func (f tokenValidatorFunc) Validate(ctx context.Context, raw string) (model.Identity, error) {
	return f(ctx, raw)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	now := time.Now()
	gw := model.Gateway{ID: "gw1", Site: "dc", Endpoint: "vpn1.example.com:51820", PublicKey: wgKey,
		Pool: netip.MustParsePrefix("10.200.0.0/24"), Capacity: 100, Enabled: true,
		TokenHash: session.HashGatewayToken(gwToken)}
	if err := st.UpsertGateway(ctx, gw); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordGatewayHealth(ctx, gw.ID, 0, now); err != nil {
		t.Fatal(err)
	}
	ca := newCA(t)
	trust := &devicetrust.Checker{Store: st, Key: []byte("challenge-key")}
	if _, err := trust.SavePolicy(ctx, model.DeviceTrustPolicy{CertMode: model.CertOff, TrustedCAs: ca.pem}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := session.New(st, session.Config{Grace: 15 * time.Minute, SuspendAfter: 90 * time.Second,
		Heartbeat: 30 * time.Second, MaxLifetime: 12 * time.Hour, GatewayHealthTTL: time.Hour}, nil, log)
	srv := &Server{Sessions: svc, Store: st, Trust: trust, Log: log,
		Tunnel: TunnelDefaults{DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420, Keepalive: 25}}
	mux := http.NewServeMux()
	srv.Register(mux)
	// One approved PC, one waiting for approval.
	for _, d := range []model.Device{
		{ID: "guid-approved", Name: "LT-4100", Platform: "windows", LastUser: "jane@contoso.com"},
		{ID: "guid-pending", Name: "LT-4200", Platform: "windows"},
	} {
		status := model.DeviceApproved
		if d.ID == "guid-pending" {
			status = model.DevicePending
		}
		d.FirstSeen, d.LastSeen = now, now
		if _, err := st.SeeDevice(ctx, d, status); err != nil {
			t.Fatal(err)
		}
	}
	return &rig{t: t, srv: srv, st: st, mux: mux, ca: ca}
}

func (r *rig) setTunnel(p model.DeviceTunnelPolicy) {
	r.t.Helper()
	if err := p.Normalize(); err != nil {
		r.t.Fatal(err)
	}
	if err := r.st.SetSetting(context.Background(), session.DeviceTunnelKey, p); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) do(method, path, bearer string, body any) (int, map[string]any) {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("User-Agent", "SecureTunnel-Agent/1.326.1000")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (r *rig) nonce() string {
	r.t.Helper()
	code, ch := r.do("GET", "/v1/auth/challenge", "", nil)
	if code != 200 {
		r.t.Fatalf("challenge: %d %v", code, ch)
	}
	return ch["nonce"].(string)
}

// connectDevice asks for a device tunnel for deviceID, signing with a
// certificate issued to certName.
func (r *rig) connectDevice(deviceID, certName, boot string) (int, map[string]any) {
	n := r.nonce()
	return r.do("POST", "/v1/sessions/device", "", deviceConnectBody{WGPublicKey: wgKey, DeviceID: deviceID,
		BootID: boot, Platform: "windows", DeviceName: certName, Nonce: n,
		Proofs: []model.DeviceProof{r.ca.proof(r.t, certName, n)}})
}

func (r *rig) audits(action string) []model.AuditEntry {
	r.t.Helper()
	all, err := r.st.ListAudit(context.Background(), 1000)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []model.AuditEntry
	for _, a := range all {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

var dcPolicy = model.DeviceTunnelPolicy{Enabled: true, Subnets: []string{"10.0.0.10", "10.0.5.0/24"}, DNS: []string{"10.0.0.10"}}

func TestDeviceTunnelOffByDefault(t *testing.T) {
	r := newRig(t)
	if code, body := r.connectDevice("guid-approved", "LT-4100", "boot-1"); code != 403 || body["error"] != "device_tunnel_off" {
		t.Fatalf("got %d %v, want 403 device_tunnel_off", code, body)
	}
}

func TestDeviceTunnelConnect(t *testing.T) {
	r := newRig(t)
	r.setTunnel(dcPolicy)
	code, body := r.connectDevice("guid-approved", "LT-4100.contoso.com", "boot-1")
	if code != 201 {
		t.Fatalf("connect: %d %v", code, body)
	}
	if body["kind"] != "device" {
		t.Errorf("kind = %v, want device", body["kind"])
	}
	tun := body["tunnel"].(map[string]any)
	if got := strings.Join(strs(tun["allowed_ips"]), ","); got != "10.0.0.10/32,10.0.5.0/24,10.200.0.1/32" {
		t.Errorf("allowed_ips = %s, want the device subnets plus the gateway's own address (never 0.0.0.0/0)", got)
	}
	if got := strings.Join(strs(tun["dns"]), ","); got != "10.0.0.10" {
		t.Errorf("dns = %s, want the device tunnel's DNS", got)
	}

	sess, err := r.st.GetSession(context.Background(), body["session_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !sess.IsDevice() || sess.UPN != "device:lt-4100" || sess.DeviceName != "LT-4100" {
		t.Errorf("session = kind %q upn %q name %q", sess.Kind, sess.UPN, sess.DeviceName)
	}
	if a := r.audits("device_tunnel.connect"); len(a) != 1 || a[0].Actor != "device:lt-4100" {
		t.Errorf("audit = %+v, want one device_tunnel.connect by device:lt-4100", a)
	}
	// The device record keeps its last real user.
	devs, _ := r.st.ListDevices(context.Background(), "")
	for _, d := range devs {
		if d.ID == "guid-approved" && d.LastUser != "jane@contoso.com" {
			t.Errorf("last user = %q, want it kept", d.LastUser)
		}
	}

	// The gateway is told to restrict this peer to the subnets.
	code, peers := r.do("GET", "/v1/gateway/peers", gwToken, nil)
	if code != 200 {
		t.Fatalf("peers: %d %v", code, peers)
	}
	list := peers["peers"].([]any)
	if len(list) != 1 {
		t.Fatalf("peers = %v", list)
	}
	pv := list[0].(map[string]any)
	if pv["device"] != true || strings.Join(strs(pv["restrict_to"]), ",") != "10.0.0.10/32,10.0.5.0/24" {
		t.Errorf("peer = %v, want device=true restrict_to=the subnets", pv)
	}
}

func TestDeviceTunnelRefusals(t *testing.T) {
	r := newRig(t)
	r.setTunnel(dcPolicy)
	other := newCA(t)
	cases := []struct {
		name, device, cert, code string
		ca                       *testCA
	}{
		{"pending device", "guid-pending", "LT-4200", "device_not_approved", nil},
		{"unknown device", "guid-nobody", "LT-9999", "device_not_approved", nil},
		{"certificate for another PC", "guid-approved", "LT-4200", "device_untrusted", nil},
		{"certificate from an untrusted CA", "guid-approved", "LT-4100", "device_untrusted", &other},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.ca != nil {
				saved := r.ca
				r.ca = *c.ca
				defer func() { r.ca = saved }()
			}
			code, body := r.connectDevice(c.device, c.cert, "boot-1")
			if code != 403 || body["error"] != c.code {
				t.Fatalf("got %d %v, want 403 %s", code, body, c.code)
			}
		})
	}
	if n := len(r.audits("device_tunnel.refused")); n != len(cases) {
		t.Errorf("%d refusals audited, want %d", n, len(cases))
	}

	// No proof at all.
	code, body := r.do("POST", "/v1/sessions/device", "", deviceConnectBody{WGPublicKey: wgKey, DeviceID: "guid-approved",
		BootID: "boot-1", Nonce: r.nonce()})
	if code != 400 {
		t.Fatalf("no proof: %d %v, want 400", code, body)
	}
	// Forged nonce.
	n := r.nonce()
	code, body = r.do("POST", "/v1/sessions/device", "", deviceConnectBody{WGPublicKey: wgKey, DeviceID: "guid-approved",
		BootID: "boot-1", Nonce: strings.Repeat("A", len(n)), Proofs: []model.DeviceProof{r.ca.proof(t, "LT-4100", n)}})
	if code != 403 || body["error"] != "device_untrusted" {
		t.Fatalf("forged nonce: %d %v, want 403 device_untrusted", code, body)
	}
}

func TestDeviceTunnelHandover(t *testing.T) {
	r := newRig(t)
	r.setTunnel(dcPolicy)
	ctx := context.Background()
	_, body := r.connectDevice("guid-approved", "LT-4100", "boot-1")
	devID := body["session_id"].(string)

	// The user signs in: their session replaces the device tunnel.
	user, err := r.srv.Sessions.Connect(ctx, model.Identity{UserOID: "oid", UPN: "jane@contoso.com", TenantID: "t"},
		session.ConnectRequest{WGPublicKey: wgKey2, DeviceID: "guid-approved", BootID: "boot-1", Platform: "windows"})
	if err != nil {
		t.Fatal(err)
	}
	if old, _ := r.st.GetSession(ctx, devID); old.State.Live() || old.EndReason != model.ReasonReplaced {
		t.Errorf("device session = %s/%s, want replaced", old.State, old.EndReason)
	}
	if a := r.audits("device_tunnel.handover"); len(a) != 1 || a[0].Target != devID {
		t.Errorf("handover audit = %+v", a)
	}

	// While the user is connected (same boot), no device tunnel.
	if code, body := r.connectDevice("guid-approved", "LT-4100", "boot-1"); code != 409 || body["error"] != "user_session_active" {
		t.Fatalf("with user connected: %d %v, want 409", code, body)
	}
	// After a reboot the old user session doesn't block it.
	if code, body := r.connectDevice("guid-approved", "LT-4100", "boot-2"); code != 201 {
		t.Fatalf("after reboot: %d %v", code, body)
	}
	if u, _ := r.st.GetSession(ctx, user.Session.ID); u.State.Live() {
		t.Error("stale user session from before the reboot is still live")
	}
	// The user signs out of SecureTunnel; the device tunnel can come back.
	r2 := newRig(t)
	r2.setTunnel(dcPolicy)
	p, err := r2.srv.Sessions.Connect(ctx, model.Identity{UserOID: "oid", UPN: "jane@contoso.com", TenantID: "t"},
		session.ConnectRequest{WGPublicKey: wgKey2, DeviceID: "guid-approved", BootID: "boot-1", Platform: "windows"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.srv.Sessions.Disconnect(ctx, p.Session.ID, p.ResumeToken); err != nil {
		t.Fatal(err)
	}
	if code, body := r2.connectDevice("guid-approved", "LT-4100", "boot-1"); code != 201 {
		t.Fatalf("after sign-out: %d %v", code, body)
	}
}

func TestDeviceTunnelEndsWhenTurnedOff(t *testing.T) {
	r := newRig(t)
	r.setTunnel(dcPolicy)
	_, body := r.connectDevice("guid-approved", "LT-4100", "boot-1")
	id, tok := body["session_id"].(string), body["resume_token"].(string)
	hb := map[string]any{"boot_id": "boot-1"}

	if code, b := r.do("POST", "/v1/sessions/"+id+"/heartbeat", tok, hb); code != 200 {
		t.Fatalf("heartbeat: %d %v", code, b)
	}
	off := dcPolicy
	off.Enabled = false
	r.setTunnel(off)
	if code, b := r.do("POST", "/v1/sessions/"+id+"/heartbeat", tok, hb); code != 401 || b["error"] != "reauth_required" {
		t.Fatalf("heartbeat after turning off: %d %v, want 401 reauth_required", code, b)
	}
	if s, _ := r.st.GetSession(context.Background(), id); s.State.Live() {
		t.Error("device session still live after the device tunnel was turned off")
	}
	if len(r.audits("device_tunnel.end")) != 1 {
		t.Error("end not audited")
	}
}

func TestDeviceTunnelEndsWhenDeviceBlocked(t *testing.T) {
	r := newRig(t)
	r.setTunnel(dcPolicy)
	_, body := r.connectDevice("guid-approved", "LT-4100", "boot-1")
	id, tok := body["session_id"].(string), body["resume_token"].(string)
	if err := r.st.SetDeviceStatus(context.Background(), "guid-approved", model.DeviceBlocked, "admin", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s, err := r.st.GetSession(context.Background(), id); err != nil || s.State.Live() {
		t.Fatalf("blocking must end the session before the next heartbeat: state %s, error %v", s.State, err)
	}
	if err := r.st.SetDeviceStatus(context.Background(), "guid-approved", model.DeviceApproved, "helpdesk", false, time.Now()); err != store.ErrDeviceBlocked {
		t.Fatalf("helpdesk tried to unblock a device: %v, want %v", err, store.ErrDeviceBlocked)
	}
	if code, b := r.do("POST", "/v1/sessions/"+id+"/heartbeat", tok, map[string]any{"boot_id": "boot-1"}); code != 401 {
		t.Fatalf("heartbeat for a blocked device: %d %v, want 401", code, b)
	}
}

func TestConnectCountryPolicyUsesIdentityAndDevice(t *testing.T) {
	r := newRig(t)
	identity := model.Identity{UPN: "jane@contoso.com", TenantID: "entra-tenant", UserOID: "entra-user"}
	r.srv.Tokens = tokenValidatorFunc(func(context.Context, string) (model.Identity, error) {
		return identity, nil
	})
	called := false
	r.srv.Sessions.CountryFor = func(_ context.Context, id model.Identity, platform, name string) (model.CountryPolicy, error) {
		called = true
		if id.TenantID != identity.TenantID || id.UserOID != identity.UserOID || platform != "windows" || name != "LT-4100" {
			t.Errorf("country policy received identity %+v, platform %q, device %q", id, platform, name)
		}
		return model.CountryPolicy{Enabled: true, BlockUnknown: true}, nil
	}
	code, body := r.do(http.MethodPost, "/v1/sessions", "token", connectBody{
		WGPublicKey: wgKey, DeviceID: "guid-approved", BootID: "boot-1", Platform: "windows", DeviceName: "LT-4100",
	})
	if !called || code != http.StatusForbidden || body["error"] != "country_blocked" {
		t.Fatalf("country policy called %v, response %d %v", called, code, body)
	}
}

func TestDeviceTunnelPolicyValidation(t *testing.T) {
	for _, c := range []struct {
		p  model.DeviceTunnelPolicy
		ok bool
	}{
		{model.DeviceTunnelPolicy{Enabled: true, Subnets: []string{"10.0.0.10"}}, true},
		{model.DeviceTunnelPolicy{Enabled: true}, false},                                               // on with no subnets
		{model.DeviceTunnelPolicy{Enabled: true, Subnets: []string{"0.0.0.0/0"}}, false},               // whole internet
		{model.DeviceTunnelPolicy{Enabled: true, Subnets: []string{"10.0.0.0/33"}}, false},             // bad CIDR
		{model.DeviceTunnelPolicy{Subnets: []string{"10.0.0.0/24"}, DNS: []string{"10.9.9.9"}}, false}, // DNS outside
		{model.DeviceTunnelPolicy{Subnets: []string{"10.0.0.0/24"}, DNS: []string{"10.0.0.53"}}, true},
	} {
		if err := c.p.Normalize(); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v, want ok=%v", c.p, err, c.ok)
		}
	}
}
