// Package localauth implements local accounts: password + optional TOTP sign-in,
// short-lived VPN connect tokens, and a validator that accepts either those
// tokens or Entra tokens.
package localauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1; authenticator apps expect it
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"securetunnel/server/internal/auth"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

var (
	// ErrBadCredentials: unknown user or wrong password (deliberately the same error).
	ErrBadCredentials = errors.New("wrong username or password")
	// ErrTOTPRequired: the password was right; an authenticator code is needed.
	ErrTOTPRequired = errors.New("authenticator code required")
	// ErrBadTOTP: the authenticator code was wrong or already used.
	ErrBadTOTP = errors.New("wrong authenticator code")
	// ErrTOTPNotEnrolled: policy requires MFA but this account has no authenticator.
	ErrTOTPNotEnrolled = errors.New("this account must have an authenticator app set up first")
	// ErrLocked: too many failed attempts.
	ErrLocked = errors.New("too many failed attempts; try again later")
	// ErrDisabled: the account is disabled.
	ErrDisabled = errors.New("account disabled")
)

const (
	tokenIssuer   = TokenIssuer
	tokenAudience = "securetunnel-vpn"
)

// DeriveKey derives a purpose-specific key from the server's master secret.
func DeriveKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}

// HashPassword returns a bcrypt hash.
func HashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

// dummyHash is compared against when the user doesn't exist, so response time
// doesn't reveal whether a username is valid.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password-just-timing"), 12)

// Authenticator signs local users in and issues VPN connect tokens.
type Authenticator struct {
	Store       store.Store
	TokenKey    []byte
	TokenTTL    time.Duration // connect token lifetime (default 5m)
	RequireTOTP bool
	Now         func() time.Time

	limiter limiter
	usedMu  sync.Mutex
	used    map[string]int64 // username -> last TOTP step used (replay protection)
}

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Login checks a username, password and (if the account has one) TOTP code.
func (a *Authenticator) Login(ctx context.Context, username, password, code, clientIP string) (model.User, bool, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	key := username + "|" + clientIP
	if a.limiter.locked(key, a.now()) {
		return model.User{}, false, ErrLocked
	}
	u, err := a.Store.GetUser(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		a.limiter.fail(key, a.now())
		return model.User{}, false, ErrBadCredentials
	}
	if err != nil {
		return model.User{}, false, err
	}
	if u.Source == "entra" || u.PasswordHash == "" { // Entra users sign in with Microsoft
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		a.limiter.fail(key, a.now())
		return model.User{}, false, ErrBadCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		a.limiter.fail(key, a.now())
		return model.User{}, false, ErrBadCredentials
	}
	if u.Disabled {
		return model.User{}, false, ErrDisabled
	}
	usedTOTP := false
	switch {
	case u.TOTPSecret != "":
		if strings.TrimSpace(code) == "" {
			return model.User{}, false, ErrTOTPRequired
		}
		if !a.checkTOTP(u.Username, u.TOTPSecret, code) {
			a.limiter.fail(key, a.now())
			return model.User{}, false, ErrBadTOTP
		}
		usedTOTP = true
	case a.RequireTOTP:
		return model.User{}, false, ErrTOTPNotEnrolled
	}
	a.limiter.reset(key)
	u.LastLogin = a.now()
	_ = a.Store.UpdateUser(ctx, u)
	return u, usedTOTP, nil
}

// IssueToken returns a short-lived VPN connect token for a user who just signed in.
func (a *Authenticator) IssueToken(u model.User, usedTOTP bool) (string, time.Time, error) {
	ttl := a.TokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := a.now()
	amr := []string{"pwd"}
	if usedTOTP {
		amr = append(amr, "otp", "mfa")
	}
	exp := now.Add(ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       tokenIssuer,
		"aud":       tokenAudience,
		"sub":       u.Username,
		"name":      u.DisplayName,
		"amr":       amr,
		"auth_time": now.Unix(),
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
	})
	s, err := tok.SignedString(a.TokenKey)
	return s, exp, err
}

// Validate implements api.TokenValidator for local connect tokens.
func (a *Authenticator) Validate(ctx context.Context, raw string) (model.Identity, error) {
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(tokenAudience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now),
	).Parse(raw, func(*jwt.Token) (any, error) { return a.TokenKey, nil })
	if err != nil {
		return model.Identity{}, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	c, _ := tok.Claims.(jwt.MapClaims)
	sub, _ := c["sub"].(string)
	u, err := a.Store.GetUser(ctx, sub)
	if err != nil || u.Disabled {
		return model.Identity{}, fmt.Errorf("%w: account missing or disabled", auth.ErrInvalidToken)
	}
	at, _ := c["auth_time"].(float64)
	return model.Identity{
		UserOID:  "local:" + u.Username,
		UPN:      u.Username,
		Name:     u.DisplayName,
		TenantID: "local",
		AuthTime: time.Unix(int64(at), 0),
	}, nil
}

// TokenValidator matches api.TokenValidator.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (model.Identity, error)
}

// TokenIssuer is the "iss" of connect tokens issued for local accounts.
const TokenIssuer = "securetunnel-local"

// IsLocalToken reports whether raw (unverified) was issued for a local account.
func IsLocalToken(raw string) bool {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return false
	}
	iss, _ := claims["iss"].(string)
	return iss == TokenIssuer
}

// Chain routes a token to the local validator or to Entra based on its issuer.
type Chain struct {
	Local *Authenticator // nil disables local accounts for VPN
	Entra TokenValidator // nil disables Entra
}

// Validate implements api.TokenValidator.
func (c Chain) Validate(ctx context.Context, raw string) (model.Identity, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return model.Identity{}, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	iss, _ := claims["iss"].(string)
	switch {
	case iss == tokenIssuer && c.Local != nil:
		return c.Local.Validate(ctx, raw)
	case iss != tokenIssuer && c.Entra != nil:
		return c.Entra.Validate(ctx, raw)
	}
	return model.Identity{}, fmt.Errorf("%w: token issuer not accepted", auth.ErrInvalidToken)
}

// ---- TOTP (RFC 6238: 30 s steps, 6 digits, HMAC-SHA1) ----

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random base32 secret.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI returns the otpauth:// URI authenticator apps import (also as a QR code).
func TOTPURI(issuer, username, secret string) string {
	label := url.PathEscape(issuer + ":" + username)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode returns the code for a secret at a time step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// VerifyTOTP checks a code against the current step ±1 (clock drift). It does
// not track replay; Authenticator.checkTOTP does.
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	step := now.Unix() / 30
	for _, s := range []int64{step, step - 1, step + 1} {
		want, err := TOTPCode(secret, s)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}

func (a *Authenticator) checkTOTP(username, secret, code string) bool {
	step, ok := VerifyTOTP(secret, code, a.now())
	if !ok {
		return false
	}
	a.usedMu.Lock()
	defer a.usedMu.Unlock()
	if a.used == nil {
		a.used = map[string]int64{}
	}
	if a.used[username] >= step {
		return false // code already used
	}
	a.used[username] = step
	return true
}

// ---- failed-attempt limiter: 5 failures in 15 minutes locks for 15 minutes ----

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

const (
	maxFailures = 5
	lockWindow  = 15 * time.Minute
)

func (l *limiter) prune(key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.hits[key] {
		if now.Sub(t) < lockWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = keep
	}
	return keep
}

func (l *limiter) locked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		return false
	}
	return len(l.prune(key, now)) >= maxFailures
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	l.hits[key] = append(l.prune(key, now), now)
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}
