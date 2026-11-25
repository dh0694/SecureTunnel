package localauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"securetunnel/server/internal/auth"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 appendix B, SHA1 secret "12345678901234567890", T=59s -> 94287082 (8 digits).
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	got, err := TOTPCode(secret, 59/30)
	if err != nil || got != "287082" {
		t.Fatalf("code = %q, %v; want 287082", got, err)
	}
}

func setup(t *testing.T) (*Authenticator, *store.Memory, *time.Time) {
	t.Helper()
	st := store.NewMemory()
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(context.Background(), model.User{Username: "TestUser", PasswordHash: hash, Role: model.RoleUser}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	a := &Authenticator{Store: st, TokenKey: []byte("0123456789abcdef0123456789abcdef"), Now: func() time.Time { return now }}
	return a, st, &now
}

func TestLoginAndTokenRoundTrip(t *testing.T) {
	a, _, _ := setup(t)
	ctx := context.Background()
	u, _, err := a.Login(ctx, "testuser", "correct horse battery", "", "1.2.3.4")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	tok, _, err := a.IssueToken(u, false)
	if err != nil {
		t.Fatal(err)
	}
	id, err := (Chain{Local: a}).Validate(ctx, tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.UPN != "testuser" || id.UserOID != "local:testuser" {
		t.Errorf("identity = %+v", id)
	}
}

func TestWrongPasswordAndLockout(t *testing.T) {
	a, _, _ := setup(t)
	ctx := context.Background()
	for i := 0; i < maxFailures; i++ {
		if _, _, err := a.Login(ctx, "testuser", "wrong password!!", "", "1.2.3.4"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := a.Login(ctx, "testuser", "correct horse battery", "", "1.2.3.4"); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked after %d failures", err, maxFailures)
	}
	if _, _, err := a.Login(ctx, "nobody", "whatever-password", "", "5.6.7.8"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("unknown user: %v, want ErrBadCredentials", err)
	}
}

func TestTOTPRequiredAndReplayRejected(t *testing.T) {
	a, st, now := setup(t)
	ctx := context.Background()
	u, _ := st.GetUser(ctx, "testuser")
	u.TOTPSecret, _ = NewTOTPSecret()
	_ = st.UpdateUser(ctx, u)

	if _, _, err := a.Login(ctx, "testuser", "correct horse battery", "", "ip"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("err = %v, want ErrTOTPRequired", err)
	}
	code, _ := TOTPCode(u.TOTPSecret, now.Unix()/30)
	if _, used, err := a.Login(ctx, "testuser", "correct horse battery", code, "ip"); err != nil || !used {
		t.Fatalf("login with code: used=%v err=%v", used, err)
	}
	if _, _, err := a.Login(ctx, "testuser", "correct horse battery", code, "ip"); !errors.Is(err, ErrBadTOTP) {
		t.Errorf("replayed code: %v, want ErrBadTOTP", err)
	}
}

func TestRequireTOTPBlocksUnenrolled(t *testing.T) {
	a, _, _ := setup(t)
	a.RequireTOTP = true
	if _, _, err := a.Login(context.Background(), "testuser", "correct horse battery", "", "ip"); !errors.Is(err, ErrTOTPNotEnrolled) {
		t.Errorf("err = %v, want ErrTOTPNotEnrolled", err)
	}
}

func TestDisabledUserTokenRejected(t *testing.T) {
	a, st, _ := setup(t)
	ctx := context.Background()
	u, _, _ := a.Login(ctx, "testuser", "correct horse battery", "", "ip")
	tok, _, _ := a.IssueToken(u, false)
	u.Disabled = true
	_ = st.UpdateUser(ctx, u)
	if _, err := a.Validate(ctx, tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken for disabled user", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	a, _, now := setup(t)
	ctx := context.Background()
	u, _, _ := a.Login(ctx, "testuser", "correct horse battery", "", "ip")
	tok, _, _ := a.IssueToken(u, false)
	*now = now.Add(6 * time.Minute)
	if _, err := a.Validate(ctx, tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken after 5-minute expiry", err)
	}
}

func TestChainRejectsEntraWhenDisabled(t *testing.T) {
	a, _, _ := setup(t)
	// A token claiming a foreign issuer must not be accepted when Entra is off.
	foreign := "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZSJ9.c2ln"
	if _, err := (Chain{Local: a}).Validate(context.Background(), foreign); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}
