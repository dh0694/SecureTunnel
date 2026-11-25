package model

import (
	"errors"
	"testing"
)

const (
	gIT  = "11111111-1111-1111-1111-111111111111"
	gCon = "22222222-2222-2222-2222-222222222222"
)

func testGroups(t *testing.T) []PolicyGroup {
	gs, err := NormalizeGroups([]PolicyGroup{
		{ID: "default", Name: "Default", AllowMicrosoft: true, Platforms: []string{"windows"}}, // conditions ignored on Default
		{ID: "it", Name: "IT", Platforms: []string{"Windows"}, EntraGroups: []EntraRef{{ID: gIT}}, AllowMicrosoft: true},
		{ID: "mac", Name: "Mac", Platforms: []string{"macos"}, AllowMicrosoft: true, MFA: MFADuo},
		{ID: "contractors", Name: "Contractors", EntraGroups: []EntraRef{{ID: gCon}}, AllowMicrosoft: true, MFA: MFADuo},
		{ID: "manual", Name: "Manual only", AllowLocal: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gs
}

func TestNormalizeGroups(t *testing.T) {
	gs := testGroups(t)
	if gs[len(gs)-1].ID != DefaultGroupID || len(gs[len(gs)-1].Platforms) != 0 {
		t.Fatalf("default must be last with no conditions: %+v", gs[len(gs)-1])
	}
	if gs[0].Platforms[0] != "windows" || gs[0].MFA != MFANone || gs[0].CertMode != CertOff {
		t.Fatalf("not normalized: %+v", gs[0])
	}
	// Default is added when missing.
	if gs, _ := NormalizeGroups([]PolicyGroup{{ID: "x", Name: "X", AllowLocal: true}}); gs[len(gs)-1].ID != DefaultGroupID {
		t.Fatal("default not added")
	}
	bad := []PolicyGroup{
		{ID: "a", Name: "", AllowLocal: true},
		{ID: "A B", Name: "x", AllowLocal: true},
		{ID: "a", Name: "x"}, // no sign-in method
		{ID: "a", Name: "x", AllowLocal: true, Platforms: []string{"linux"}},
		{ID: "a", Name: "x", AllowLocal: true, EntraGroups: []EntraRef{{ID: "not-a-guid"}}},
		{ID: "a", Name: "x", AllowLocal: true, MFA: "sms"},
	}
	for i, g := range bad {
		if _, err := NormalizeGroups([]PolicyGroup{g}); err == nil {
			t.Errorf("bad group %d accepted", i)
		}
	}
	if _, err := NormalizeGroups([]PolicyGroup{{ID: "a", Name: "x", AllowLocal: true}, {ID: "a", Name: "y", AllowLocal: true}}); err == nil {
		t.Error("duplicate IDs accepted")
	}
}

func TestResolveGroup(t *testing.T) {
	gs := testGroups(t)
	cases := []struct {
		name, assigned, platform string
		member                   []string
		known                    bool
		want                     string
		err                      bool
	}{
		{"IT on Windows", "", "windows", []string{gIT}, true, "it", false},
		{"IT on Mac falls to Mac", "", "macos", []string{gIT}, true, "mac", false},
		{"Mac user", "", "macos", nil, true, "mac", false},
		{"contractor on Windows", "", "windows", []string{gCon}, true, "contractors", false},
		{"nobody special", "", "windows", nil, true, "default", false},
		{"manual pick wins", "manual", "macos", []string{gIT}, true, "manual", false},
		{"unknown pick falls back", "gone", "windows", nil, true, "default", false},
		{"groups unknown fails closed", "", "windows", nil, false, "", true},
		{"pick needs no groups", "contractors", "windows", nil, false, "contractors", false},
	}
	for _, c := range cases {
		g, err := ResolveGroup(gs, c.assigned, c.platform, c.member, c.known)
		if c.err {
			if !errors.Is(err, ErrGroupsUnknown) {
				t.Errorf("%s: err = %v, want ErrGroupsUnknown", c.name, err)
			}
			continue
		}
		if err != nil || g.ID != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.name, g.ID, err, c.want)
		}
	}
}
