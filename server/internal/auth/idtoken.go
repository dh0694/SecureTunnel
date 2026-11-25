package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDClaims are the parts of an Entra ID token the admin site uses.
type IDClaims struct {
	OID      string
	TenantID string
	UPN      string
	Name     string
	Roles    []string
}

// ValidateIDToken verifies an Entra v2.0 ID token from the admin site's
// authorization-code sign-in: signature, issuer, audience (our client ID),
// tenant, expiry and nonce.
func ValidateIDToken(ctx context.Context, keys KeySource, raw, tenantID, clientID, nonce string, now time.Time) (IDClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(2*time.Minute),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	tok, err := parser.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		return keys.Key(ctx, kid)
	})
	if err != nil {
		return IDClaims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	c, _ := tok.Claims.(jwt.MapClaims)
	return checkIDClaims(c, tenantID, clientID, nonce)
}

func checkIDClaims(c jwt.MapClaims, tenantID, clientID, nonce string) (IDClaims, error) {
	str := func(k string) string { s, _ := c[k].(string); return s }
	tid := str("tid")
	if tid == "" || !strings.EqualFold(tid, tenantID) {
		return IDClaims{}, fmt.Errorf("%w: wrong tenant", ErrInvalidToken)
	}
	if str("iss") != "https://login.microsoftonline.com/"+tid+"/v2.0" {
		return IDClaims{}, fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	}
	aud, _ := c.GetAudience()
	if !slices.ContainsFunc(aud, func(a string) bool { return strings.EqualFold(a, clientID) }) {
		return IDClaims{}, fmt.Errorf("%w: wrong audience", ErrInvalidToken)
	}
	if nonce == "" || str("nonce") != nonce {
		return IDClaims{}, fmt.Errorf("%w: wrong nonce", ErrInvalidToken)
	}
	out := IDClaims{OID: str("oid"), TenantID: tid, Name: str("name")}
	if out.OID == "" {
		return IDClaims{}, fmt.Errorf("%w: no oid", ErrInvalidToken)
	}
	out.UPN = str("preferred_username")
	if out.UPN == "" {
		out.UPN = str("upn")
	}
	if out.UPN == "" {
		out.UPN = str("email")
	}
	out.UPN = strings.ToLower(out.UPN)
	if list, ok := c["roles"].([]any); ok {
		for _, r := range list {
			if s, ok := r.(string); ok {
				out.Roles = append(out.Roles, s)
			}
		}
	}
	return out, nil
}
