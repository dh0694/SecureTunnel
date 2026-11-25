// Package clienttls decides whether the agent trusts the control server's
// certificate, without asking users to install certificate files.
//
//  1. If the certificate chains to a CA Windows trusts (a real certificate,
//     or a Cloudflare hostname), it is accepted as normal.
//  2. Otherwise, if a pin is configured (installer /PIN= or a previous
//     connection), the server's public key must match it.
//  3. Otherwise this is the first connection to a server with a private or
//     self-signed certificate: its public key is pinned and accepted (trust on
//     first use, like SSH host keys). Later connections must present the same key.
package clienttls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// PinStore persists the pinned public-key hash for the configured server.
type PinStore interface {
	GetPin() string
	SetPin(pin string) error
}

// MemoryPins is an in-memory PinStore (tests, and tools that don't persist).
type MemoryPins struct {
	mu  sync.Mutex
	Pin string
}

func (m *MemoryPins) GetPin() string { m.mu.Lock(); defer m.mu.Unlock(); return m.Pin }
func (m *MemoryPins) SetPin(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Pin = p
	return nil
}

// ErrPinMismatch means the server presented a different key than the pinned one.
var ErrPinMismatch = errors.New("the server's certificate changed since this PC first connected; ask IT to check the server, or reinstall with the new /PIN")

// SPKIHash returns the hex SHA-256 of a certificate's public key.
func SPKIHash(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

// NormalizePin accepts hex with or without colons/spaces, any case.
func NormalizePin(p string) string {
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(p)))
}

// Mode reports how the last successful handshake was trusted.
type Mode string

const (
	ModeSystem Mode = "system"      // chains to a trusted CA
	ModePinned Mode = "pinned"      // matched the stored pin
	ModeFirst  Mode = "first-use"   // pinned on this connection
)

// Trust builds TLS configs for one server host.
type Trust struct {
	Host  string   // host name or IP of the control server
	Pins  PinStore // nil: only system-trusted certificates are accepted
	Roots *x509.CertPool

	mu       sync.Mutex
	lastMode Mode
}

// LastMode returns how the most recent handshake was trusted.
func (t *Trust) LastMode() Mode {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastMode
}

func (t *Trust) setMode(m Mode) {
	t.mu.Lock()
	t.lastMode = m
	t.mu.Unlock()
}

// Config returns a tls.Config implementing the rules above.
func (t *Trust) Config() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         sniName(t.Host),
		InsecureSkipVerify: true, //nolint:gosec // verification is done in VerifyConnection below
		VerifyConnection:   t.verify,
	}
}

func sniName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func (t *Trust) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: t.Host, Intermediates: inter, Roots: t.Roots}); err == nil {
		t.setMode(ModeSystem)
		return nil
	} else if t.Pins == nil {
		return err
	}
	got := SPKIHash(leaf)
	if want := NormalizePin(t.Pins.GetPin()); want != "" {
		if got != want {
			return fmt.Errorf("%w (expected %s…, got %s…)", ErrPinMismatch, want[:12], got[:12])
		}
		t.setMode(ModePinned)
		return nil
	}
	if err := t.Pins.SetPin(got); err != nil {
		return fmt.Errorf("could not save the server's certificate pin: %w", err)
	}
	t.setMode(ModeFirst)
	return nil
}
