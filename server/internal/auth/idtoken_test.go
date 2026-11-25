package auth

import (
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCheckIDClaims(t *testing.T) {
	const tid, cid = "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	good := func() jwt.MapClaims {
		return jwt.MapClaims{
			"tid": tid, "iss": "https://login.microsoftonline.com/" + tid + "/v2.0", "aud": cid,
			"nonce": "n1", "oid": "o1", "preferred_username": "Jane@Contoso.com", "name": "Jane",
			"roles": []any{"SecureTunnel.Helpdesk"},
		}
	}
	c, err := checkIDClaims(good(), tid, cid, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if c.UPN != "jane@contoso.com" || c.Name != "Jane" || len(c.Roles) != 1 {
		t.Fatalf("claims = %+v", c)
	}
	for name, mod := range map[string]func(jwt.MapClaims){
		"tenant":   func(m jwt.MapClaims) { m["tid"] = "other" },
		"issuer":   func(m jwt.MapClaims) { m["iss"] = "https://sts.windows.net/" + tid + "/" },
		"audience": func(m jwt.MapClaims) { m["aud"] = "api://" + cid },
		"nonce":    func(m jwt.MapClaims) { m["nonce"] = "n2" },
		"oid":      func(m jwt.MapClaims) { delete(m, "oid") },
	} {
		m := good()
		mod(m)
		if _, err := checkIDClaims(m, tid, cid, "n1"); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}
	if _, err := checkIDClaims(good(), tid, cid, ""); err == nil {
		t.Error("empty expected nonce must fail")
	}
}
