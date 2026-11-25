package model

import (
	"testing"
	"time"
)

func TestOfficeNetworkMatch(t *testing.T) {
	p := OfficeNetworkPolicy{Enabled: true, DNSSuffixes: []string{" CB-Sisco.com. "}, LocalSubnets: []string{"10.20.0.0/16"}, PublicIPs: []string{"203.0.113.10"}}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		dns, local []string
		public     string
		want       bool
	}{
		{[]string{"cb-sisco.com"}, nil, "", true},
		{[]string{"hq.cb-sisco.com"}, nil, "", true},
		{[]string{"notcb-sisco.com"}, nil, "", false},
		{nil, []string{"10.20.4.7"}, "", true},
		{nil, []string{"192.168.1.20"}, "", false},
		{nil, nil, "203.0.113.10", true},
		{nil, nil, "203.0.113.11", false},
		{[]string{"home.lan"}, []string{"192.168.1.5"}, "47.32.2.7", false},
	}
	for i, c := range cases {
		if got, why := p.Match(c.dns, c.local, c.public); got != c.want {
			t.Errorf("case %d: got %v (%s), want %v", i, got, why, c.want)
		}
	}
	p.Enabled = false
	if got, _ := p.Match([]string{"cb-sisco.com"}, nil, ""); got {
		t.Error("matched while disabled")
	}
}

func TestOfficeNetworkValidation(t *testing.T) {
	for _, bad := range []OfficeNetworkPolicy{
		{Enabled: true},
		{DNSSuffixes: []string{"bad domain"}},
		{LocalSubnets: []string{"10.0.0.0/99"}},
		{PublicIPs: []string{"nope"}},
	} {
		if err := bad.Normalize(); err == nil {
			t.Errorf("%+v: expected an error", bad)
		}
	}
	p := OfficeNetworkPolicy{LocalSubnets: []string{"10.20.3.4/16, 10.20.0.0/16"}, PublicIPs: []string{"203.0.113.10"}}
	if err := p.Normalize(); err != nil || len(p.LocalSubnets) != 1 || p.LocalSubnets[0] != "10.20.0.0/16" || p.PublicIPs[0] != "203.0.113.10/32" {
		t.Errorf("normalized = %+v, err %v", p, err)
	}
}

func TestCountryAllowed(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	p := CountryPolicy{Enabled: true, Default: []string{"us"}}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	u := &User{AllowedCountries: []string{"CA"}, TravelCountries: []string{"FR"}, TravelUntil: now.Add(48 * time.Hour)}
	cases := []struct {
		country string
		user    *User
		at      time.Time
		want    bool
	}{
		{"US", nil, now, true},
		{"CA", nil, now, false},
		{"CA", u, now, true},
		{"FR", u, now, true},
		{"FR", u, now.Add(72 * time.Hour), false}, // trip over
		{"CN", u, now, false},
		{"", u, now, true}, // unknown allowed unless BlockUnknown
	}
	for _, c := range cases {
		if got, _ := CountryAllowed(p, c.user, c.country, c.at); got != c.want {
			t.Errorf("country %q user %v: got %v, want %v", c.country, c.user != nil, got, c.want)
		}
	}
	p.BlockUnknown = true
	if ok, _ := CountryAllowed(p, u, "", now); ok {
		t.Error("unknown country allowed with BlockUnknown")
	}
	if ok, _ := CountryAllowed(CountryPolicy{}, nil, "CN", now); !ok {
		t.Error("blocked while disabled")
	}
	if _, err := NormalizeCountries([]string{"USA"}); err == nil {
		t.Error("three-letter code accepted")
	}
}
