package model

import "testing"

func TestWindowsSessionDefaults(t *testing.T) {
	var p WindowsSessionPolicy
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p != DefaultWindowsSessions() {
		t.Fatalf("empty policy should get the defaults: %+v", p)
	}
	bad := WindowsSessionPolicy{OnSwitch: "maybe"}
	if bad.Normalize() == nil {
		t.Fatal("unknown option should be refused")
	}
	if (&WindowsSessionPolicy{LockMinutes: -1}).Normalize() == nil {
		t.Fatal("negative lock minutes should be refused")
	}
}

func TestWindowsUserMatches(t *testing.T) {
	cases := []struct {
		win, vpn string
		want     bool
	}{
		{"jsmith@contoso.com", "JSmith@contoso.com", true},
		{`CONTOSO\jsmith`, "jsmith@contoso.com", true},
		{`CONTOSO\jsmith`, "jsmith", true},
		{`LAPTOP-1\admin`, "jsmith@contoso.com", false},
		{"adoe@contoso.com", "jsmith@contoso.com", false},
		{"", "jsmith@contoso.com", true}, // unknown: nothing to compare
	}
	for _, c := range cases {
		if got := WindowsUserMatches(c.win, c.vpn); got != c.want {
			t.Errorf("WindowsUserMatches(%q, %q) = %v, want %v", c.win, c.vpn, got, c.want)
		}
	}
}
