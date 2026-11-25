// Package auth validates Entra ID access tokens presented on connect.
//
// Conditional Access (MFA + sign-in frequency "Every time") is the primary control.
// These checks are defence in depth: if the CA policy is ever loosened, the server
// still refuses tokens that are not fresh or not MFA-backed.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"securetunnel/server/internal/model"
)

var (
	// ErrInvalidToken: signature, issuer, audience, tenant, scope or expiry check failed.
	ErrInvalidToken = errors.New("invalid token")
	// ErrMFARequired: the token does not show an MFA sign-in.
	ErrMFARequired = errors.New("mfa required")
	// ErrStaleAuth: the sign-in behind the token is older than MaxAuthAge.
	ErrStaleAuth = errors.New("sign-in too old; fresh sign-in required")
)

// Config controls which tokens are accepted.
type Config struct {
	TenantID      string
	Audiences     []string // the VPN API's app ID URI and/or client ID
	RequiredScope string   // e.g. "access_as_user"
	// RequireMFA requires "mfa" in the token's amr claim.
	RequireMFA bool
	// MaxAuthAge rejects tokens whose auth_time is older than this. 0 disables.
	MaxAuthAge time.Duration
	// RequireAuthTime rejects tokens with no auth_time claim when MaxAuthAge is set.
	RequireAuthTime bool
}

// Validator verifies Entra access tokens.
type Validator struct {
	cfg  Config
	keys KeySource
	now  func() time.Time
}

// NewValidator returns a Validator. now may be nil (uses time.Now).
func NewValidator(cfg Config, keys KeySource, now func() time.Time) *Validator {
	if now == nil {
		now = time.Now
	}
	return &Validator{cfg: cfg, keys: keys, now: now}
}

// Validate verifies the token's signature and claims and returns the user's identity.
func (v *Validator) Validate(ctx context.Context, raw string) (model.Identity, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(2*time.Minute),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)
	tok, err := parser.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		return v.keys.Key(ctx, kid)
	})
	if err != nil {
		return model.Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return model.Identity{}, ErrInvalidToken
	}
	return checkClaims(claims, v.cfg, v.now())
}

func checkClaims(c jwt.MapClaims, cfg Config, now time.Time) (model.Identity, error) {
	str := func(k string) string { s, _ := c[k].(string); return s }

	tid := str("tid")
	if tid == "" || !strings.EqualFold(tid, cfg.TenantID) {
		return model.Identity{}, fmt.Errorf("%w: wrong tenant", ErrInvalidToken)
	}
	iss := str("iss")
	if iss != "https://login.microsoftonline.com/"+tid+"/v2.0" && iss != "https://sts.windows.net/"+tid+"/" {
		return model.Identity{}, fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	}
	aud, _ := c.GetAudience()
	if !slices.ContainsFunc(aud, func(a string) bool { return slices.Contains(cfg.Audiences, a) }) {
		return model.Identity{}, fmt.Errorf("%w: wrong audience", ErrInvalidToken)
	}
	if cfg.RequiredScope != "" && !slices.Contains(strings.Fields(str("scp")), cfg.RequiredScope) {
		return model.Identity{}, fmt.Errorf("%w: missing scope %q", ErrInvalidToken, cfg.RequiredScope)
	}
	oid := str("oid")
	if oid == "" {
		return model.Identity{}, fmt.Errorf("%w: no oid", ErrInvalidToken)
	}

	if cfg.RequireMFA && !hasString(c["amr"], "mfa") {
		return model.Identity{}, ErrMFARequired
	}

	authTime, hasAuthTime := numericTime(c["auth_time"])
	if cfg.MaxAuthAge > 0 {
		if !hasAuthTime && cfg.RequireAuthTime {
			return model.Identity{}, fmt.Errorf("%w: token has no auth_time", ErrStaleAuth)
		}
		if hasAuthTime && now.Sub(authTime) > cfg.MaxAuthAge {
			return model.Identity{}, ErrStaleAuth
		}
	}
	if !hasAuthTime {
		authTime, _ = numericTime(c["iat"])
	}

	upn := str("preferred_username")
	if upn == "" {
		upn = str("upn")
	}
	return model.Identity{
		UserOID:  oid,
		UPN:      upn,
		Name:     str("name"),
		TenantID: tid,
		AuthTime: authTime,
	}, nil
}

func hasString(v any, want string) bool {
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

func numericTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		return time.Unix(i, 0), err == nil
	}
	return time.Time{}, false
}
