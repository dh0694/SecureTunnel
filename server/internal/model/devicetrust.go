package model

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Device trust: checked on every connect, on top of Conditional Access.
//
//   - Entra device identity: the agent signs a server challenge with the PC's
//     Entra device certificate (issued by MS-Organization-Access when the PC
//     is Entra joined or hybrid joined; CN = Entra device ID). The server
//     checks that key against the device's registered key in Microsoft Graph,
//     then reads join type and Intune compliance from Graph.
//   - Certificates: optionally require a device certificate (machine store)
//     and/or a user certificate (user store) issued by your own CAs.

// Certificate requirement modes.
const (
	CertOff    = "off"
	CertDevice = "device"
	CertUser   = "user"
	CertEither = "either" // device or user
	CertBoth   = "both"
)

// DeviceTrustPolicy is saved on the admin site (Policies → Device trust).
type DeviceTrustPolicy struct {
	CertMode         string `json:"cert_mode"`         // off | device | user | either | both
	TrustedCAs       string `json:"trusted_cas"`       // PEM: the CAs that issue device/user certificates
	MatchDeviceName  bool   `json:"match_device_name"` // device certificate CN or DNS name must be the computer name
	MatchUser        bool   `json:"match_user"`        // user certificate UPN or email must be the signed-in user
	// Name rules: the certificate's name must match one of these patterns
	// (see certname.go), e.g. "$hostname.cb-sisco.com" or "*.cb-sisco.com".
	DeviceNamePatterns []string `json:"device_name_patterns"`
	UserNamePatterns   []string `json:"user_name_patterns"`
}

// Normalize validates the policy and returns the parsed CA certificates.
func (p *DeviceTrustPolicy) Normalize() ([]*x509.Certificate, error) {
	switch p.CertMode {
	case "":
		p.CertMode = CertOff
	case CertOff, CertDevice, CertUser, CertEither, CertBoth:
	default:
		return nil, errors.New("unknown certificate mode")
	}
	cas, err := ParseCAs(p.TrustedCAs)
	if err != nil {
		return nil, err
	}
	if p.CertMode != CertOff && len(cas) == 0 {
		return nil, errors.New("add the CA certificate(s) that issue your device or user certificates")
	}
	p.TrustedCAs = strings.TrimSpace(p.TrustedCAs)
	if p.DeviceNamePatterns, err = NormalizeNamePatterns(p.DeviceNamePatterns); err != nil {
		return nil, fmt.Errorf("device certificate names: %w", err)
	}
	if p.UserNamePatterns, err = NormalizeNamePatterns(p.UserNamePatterns); err != nil {
		return nil, fmt.Errorf("user certificate names: %w", err)
	}
	return cas, nil
}

// WantsDeviceCert / WantsUserCert say which certificates the agent should send.
func (p DeviceTrustPolicy) WantsDeviceCert() bool {
	return p.CertMode == CertDevice || p.CertMode == CertEither || p.CertMode == CertBoth
}
func (p DeviceTrustPolicy) WantsUserCert() bool {
	return p.CertMode == CertUser || p.CertMode == CertEither || p.CertMode == CertBoth
}

// ParseCAs reads PEM certificates.
func ParseCAs(pemText string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemText)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("a CA certificate couldn't be read: " + err.Error())
		}
		if !c.IsCA {
			return nil, errors.New(c.Subject.CommonName + " isn't a CA certificate")
		}
		out = append(out, c)
	}
	if len(out) == 0 && strings.TrimSpace(pemText) != "" {
		return nil, errors.New("paste CA certificates in PEM format (-----BEGIN CERTIFICATE-----)")
	}
	return out, nil
}

// CertInfo describes a certificate an agent presented.
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Thumbprint string    `json:"thumbprint"` // SHA-1, hex, as Windows shows it
	NotAfter   time.Time `json:"not_after"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
}

// DeviceTrust is the result of the latest connect-time check of a device.
type DeviceTrust struct {
	CheckedAt time.Time `json:"checked_at"`
	User      string    `json:"user"`
	Group     string    `json:"group,omitempty"` // policy group applied

	// Entra device identity.
	EntraDeviceID string `json:"entra_device_id,omitempty"`
	EntraProven   bool   `json:"entra_proven"`         // signed with the registered Entra device key
	JoinType      string `json:"join_type,omitempty"`  // "Hybrid joined", "Entra joined", "Registered", "Not joined"
	JoinSource    string `json:"join_source,omitempty"` // "graph" or "agent"
	Compliant     *bool  `json:"compliant,omitempty"`  // Intune; nil = unknown
	Managed       *bool  `json:"managed,omitempty"`
	EntraEnabled  *bool  `json:"entra_enabled,omitempty"`
	OS            string `json:"os,omitempty"`
	GraphError    string `json:"graph_error,omitempty"`

	// Active Directory domain.
	ADDomain     string `json:"ad_domain,omitempty"`
	DomainProven bool   `json:"domain_proven"` // shown by a trusted device certificate

	DeviceCert *CertInfo `json:"device_cert,omitempty"`
	UserCert   *CertInfo `json:"user_cert,omitempty"`

	Passed   bool     `json:"passed"`
	Problems []string `json:"problems,omitempty"` // why the policy blocked it
}

// DeviceProof is a challenge signature from the agent.
type DeviceProof struct {
	Kind  string   `json:"kind"`  // "entra_device", "device_cert" or "user_cert"
	Chain []string `json:"chain"` // base64 DER certificates, leaf first
	Alg   string   `json:"alg"`   // RS256, ES256 or ES384 (ECDSA as raw r||s)
	Sig   string   `json:"sig"`   // base64
}

// JoinInfo is what the agent reports about the PC's Entra/AD join (dsregcmd).
type JoinInfo struct {
	EntraJoined     bool   `json:"entra_joined"`
	DomainJoined    bool   `json:"domain_joined"`
	WorkplaceJoined bool   `json:"workplace_joined"`
	DeviceID        string `json:"device_id,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	ADDomain        string `json:"ad_domain,omitempty"`  // Active Directory DNS domain (primary DNS suffix)
	ADNetBIOS       string `json:"ad_netbios,omitempty"` // Active Directory NetBIOS domain
}

// ProofMessage is the exact byte string an agent signs.
func ProofMessage(nonce, kind string) []byte {
	return []byte("SecureTunnel device proof v1\n" + nonce + "\n" + kind)
}

// LogUpload is a bundle of agent logs and diagnostics sent for troubleshooting.
type LogUpload struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Ref        string    `json:"ref"` // short code shown to the user, e.g. K7Q-4P2
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	UPN        string    `json:"upn"`       // "" when sent while not connected
	Verified   bool      `json:"verified"`  // sent with a live session's credentials
	Reason     string    `json:"reason"`    // "user" or "admin"
	Size       int       `json:"size"`
	Data       []byte    `json:"-"` // zip
}
