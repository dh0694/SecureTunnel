package model

import (
	"errors"
	"testing"
)

func testSet(t *testing.T) PolicySet {
	t.Helper()
	ps := PolicySet{
		Groups: []Group{
			{ID: "it", Name: "IT staff", Kind: "users", EntraGroups: []EntraRef{{ID: "11111111-2222-3333-4444-555555555555"}}},
			{ID: "macs", Name: "Macs", Kind: "devices", Platforms: []string{"macos"}},
			{ID: "pilot", Name: "Pilot PCs", Kind: "devices", NamePatterns: []string{"LT-1*", "it-lab"}},
			{ID: "picked", Name: "Picked", Kind: "users", Users: []string{"JSmith@Contoso.com"}},
		},
		Policies: []Policy{
			{ID: "mac-signin", Name: "Mac sign-in", Type: PolicySignIn, Groups: []string{"macs"}, SignIn: &SignInPolicy{AllowMicrosoft: true, MFA: MFADuo}},
			{ID: "it-signin", Name: "IT sign-in", Type: PolicySignIn, Groups: []string{"it", "picked"}, SignIn: &SignInPolicy{AllowMicrosoft: true, CertMode: CertDevice}},
			{ID: "pilot-updates", Name: "Pilot ring", Type: PolicyUpdates, Groups: []string{"pilot"}, Updates: &UpdatePolicy{InstallWhen: InstallAnytime}},
		},
	}
	if err := ps.Normalize(); err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestPolicyPick(t *testing.T) {
	ps := testSet(t)
	pick := func(typ string, s Subject) string {
		p, _, err := ps.Pick(typ, s)
		if err != nil {
			return "error: " + err.Error()
		}
		return p.ID
	}
	itUser := Subject{User: "adoe@contoso.com", MemberOf: []string{"11111111-2222-3333-4444-555555555555"}, GroupsKnown: true, Platform: "windows", DeviceName: "LT-4100"}
	if got := pick(PolicySignIn, itUser); got != "it-signin" {
		t.Errorf("IT user on Windows: %s", got)
	}
	// Order matters: on a Mac, the Mac policy comes first.
	onMac := itUser
	onMac.Platform = "macos"
	if got := pick(PolicySignIn, onMac); got != "mac-signin" {
		t.Errorf("IT user on a Mac: %s", got)
	}
	// Picked by hand (case-insensitive).
	if got := pick(PolicySignIn, Subject{User: "jsmith@contoso.com", GroupsKnown: true, Platform: "windows"}); got != "it-signin" {
		t.Errorf("picked user: %s", got)
	}
	// Nobody special: Default.
	if got := pick(PolicySignIn, Subject{User: "x@contoso.com", GroupsKnown: true, Platform: "windows"}); got != "default-signin" {
		t.Errorf("other user: %s", got)
	}
	// Fails closed when Entra membership is unknown and could decide it.
	if _, _, err := ps.Pick(PolicySignIn, Subject{User: "x@contoso.com", Platform: "windows"}); !errors.Is(err, ErrGroupsUnknown) {
		t.Errorf("unknown membership should fail closed, got %v", err)
	}
	// Device policies by name pattern, without a user.
	if got := pick(PolicyUpdates, Subject{Platform: "windows", DeviceName: "lt-1042"}); got != "pilot-updates" {
		t.Errorf("pilot PC: %s", got)
	}
	if got := pick(PolicyUpdates, Subject{Platform: "windows", DeviceName: "IT-LAB"}); got != "pilot-updates" {
		t.Errorf("exact name: %s", got)
	}
	if got := pick(PolicyUpdates, Subject{Platform: "windows", DeviceName: "LT-2000"}); got != "default-updates" {
		t.Errorf("other PC: %s", got)
	}
}

func TestPolicyNormalize(t *testing.T) {
	ps := testSet(t)
	// Built-ins added; one Default per type, last of its type.
	if ps.Groups[0].ID != GroupAllUsers || ps.Groups[1].ID != GroupAllDevices {
		t.Fatalf("built-in groups missing: %+v", ps.Groups[:2])
	}
	last := map[string]string{}
	for _, p := range ps.Policies {
		last[p.Type] = p.ID
	}
	for _, typ := range PolicyTypes {
		if last[typ] != "default-"+typ {
			t.Errorf("%s: Default should be last, got %s", typ, last[typ])
		}
	}
	bad := []PolicySet{
		{Policies: []Policy{{ID: "x", Name: "X", Type: PolicySignIn, Groups: []string{"nope"}}}},
		{Policies: []Policy{{ID: "x", Name: "X", Type: PolicySignIn, SignIn: &SignInPolicy{}}}},
		{Groups: []Group{{ID: "g", Name: "Empty"}}},
		{Groups: []Group{{ID: "g", Name: "G", NamePatterns: []string{"bad name!"}}}},
		{Policies: []Policy{{ID: "x", Name: "X", Type: "nope"}}},
	}
	for i, b := range bad {
		if err := b.Normalize(); err == nil {
			t.Errorf("case %d should be refused", i)
		}
	}
}

func TestMigratePolicyGroups(t *testing.T) {
	old := []PolicyGroup{
		{ID: "macs", Name: "Mac users", Platforms: []string{"macos"}, AllowMicrosoft: true, MFA: MFADuo, CertMode: CertOff, Windows: DefaultWindowsSessions()},
		{ID: "unassigned", Name: "Unassigned manual group", AllowMicrosoft: true, MFA: MFANone, CertMode: CertOff, Windows: DefaultWindowsSessions()},
		{ID: DefaultGroupID, Name: "Default", AllowMicrosoft: true, AllowLocal: true, MFA: MFANone, CertMode: CertOff, Windows: DefaultWindowsSessions()},
	}
	up := DefaultUpdatePolicy()
	up.InstallWhen = InstallWindow
	ps := MigratePolicyGroups(old, map[string][]string{}, &up)
	if err := ps.Normalize(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ps.groupMap()["unassigned"]; ok {
		t.Fatal("unassigned manual group cannot match and should be omitted")
	}
	p, _, err := ps.Pick(PolicySignIn, Subject{User: "a@b.c", GroupsKnown: true, Platform: "macos"})
	if err != nil || p.SignIn.MFA != MFADuo {
		t.Fatalf("Mac users keep Duo: %+v %v", p, err)
	}
	u, _, _ := ps.Pick(PolicyUpdates, Subject{Platform: "windows"})
	if u.Updates.InstallWhen != InstallWindow {
		t.Fatalf("update policy carried over: %+v", u.Updates)
	}
}
