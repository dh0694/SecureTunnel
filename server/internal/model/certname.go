package model

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strings"
)

// Certificate name rules (Policies → Certificates): patterns a device or user
// certificate's name must match, e.g. "$hostname.cb-sisco.com" or
// "*.cb-sisco.com". Shared by the server (enforces) and the app (picks a
// matching certificate and explains why others don't fit).
//
//	*          any characters (including dots)
//	$hostname  this computer's name (e.g. LAPTOP-7Q2)
//	$upn       the signed-in user's UPN (jsmith@contoso.com)
//	$user      the UPN's user part (jsmith)
//
// Matching ignores case. Device certificates are matched on the subject CN
// and DNS names; user certificates on email, UPN and CN.

var patternRE = regexp.MustCompile(`^[a-z0-9.*@_$-]+$`)

// NormalizeNamePatterns cleans and checks a pattern list.
func NormalizeNamePatterns(in []string) ([]string, error) {
	out := []string{}
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if len(p) > 200 || !patternRE.MatchString(p) {
			return nil, fmt.Errorf("%q: use letters, digits, dots, hyphens, * and $hostname, $upn or $user", p)
		}
		rest := p
		for _, v := range []string{"$hostname", "$upn", "$user"} {
			rest = strings.ReplaceAll(rest, v, "")
		}
		if strings.Contains(rest, "$") {
			return nil, fmt.Errorf("%q: the placeholders are $hostname, $upn and $user", p)
		}
		if strings.Trim(p, "*.") == "" {
			return nil, fmt.Errorf("%q matches everything; leave the list empty instead", p)
		}
		if !contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) > 20 {
		return nil, fmt.Errorf("use at most 20 patterns")
	}
	return out, nil
}

// NameVars are the values the placeholders stand for.
type NameVars struct {
	Hostname string
	UPN      string
}

// patternMatches reports whether name fits pattern after filling placeholders.
func patternMatches(pattern, name string, v NameVars) bool {
	host := strings.ToLower(strings.TrimSpace(v.Hostname))
	upn := strings.ToLower(strings.TrimSpace(v.UPN))
	user := upn
	if i := strings.IndexByte(user, '@'); i >= 0 {
		user = user[:i]
	}
	vars := []struct{ tok, val string }{{"$hostname", host}, {"$upn", upn}, {"$user", user}}
	var b strings.Builder
	b.WriteString("^")
next:
	for i := 0; i < len(pattern); {
		if pattern[i] == '*' {
			b.WriteString(".*")
			i++
			continue
		}
		for _, v := range vars {
			if strings.HasPrefix(pattern[i:], v.tok) {
				if v.val == "" {
					return false // unknown here: can't match
				}
				b.WriteString(regexp.QuoteMeta(v.val))
				i += len(v.tok)
				continue next
			}
		}
		b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		i++
	}
	b.WriteString("$")
	ok, err := regexp.MatchString(b.String(), strings.ToLower(name))
	return err == nil && ok
}

// CertNames lists the names a certificate is matched on.
func CertNames(c *x509.Certificate, user bool) []string {
	var out []string
	if user {
		out = append(out, c.EmailAddresses...)
		out = append(out, SANUPNs(c)...)
	} else {
		out = append(out, c.DNSNames...)
	}
	if c.Subject.CommonName != "" {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

// CertNameAllowed reports whether any of the certificate's names matches any
// pattern (true when there are no patterns).
func CertNameAllowed(c *x509.Certificate, user bool, patterns []string, v NameVars) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, n := range CertNames(c, user) {
		for _, p := range patterns {
			if patternMatches(p, n, v) {
				return true
			}
		}
	}
	return false
}

var (
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3} // Microsoft UPN otherName
)

// SANUPNs returns the UPN otherName values from the subject alternative names.
func SANUPNs(c *x509.Certificate) []string {
	var out []string
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			return out
		}
		rest := seq.Bytes
		for len(rest) > 0 {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				break
			}
			if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 { // otherName
				continue
			}
			var oid asn1.ObjectIdentifier
			r2, err := asn1.Unmarshal(gn.Bytes, &oid)
			if err != nil || !oid.Equal(oidUPN) {
				continue
			}
			var explicit asn1.RawValue
			if _, err := asn1.Unmarshal(r2, &explicit); err != nil {
				continue
			}
			var s string
			if _, err := asn1.Unmarshal(explicit.Bytes, &s); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}
