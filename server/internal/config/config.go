// Package config loads control server settings from environment variables.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full control server configuration.
type Config struct {
	Listen      string // ST_LISTEN, default ":8443"
	TLSCert     string // ST_TLS_CERT
	TLSKey      string // ST_TLS_KEY
	DatabaseURL string // ST_DATABASE_URL; empty = in-memory store (dev only)
	Dev         bool   // ST_DEV=true allows plain HTTP and the in-memory store

	GatewaysFile string // ST_GATEWAYS_FILE: JSON list of gateways, upserted at startup

	PublicURL    string // ST_PUBLIC_URL: the address clients use, e.g. https://vpn.example.com
	DownloadsDir string // ST_DOWNLOADS_DIR: client binaries for /downloads/, default /opt/securetunnel/clients

	// SecretKey is the master secret (hex, 32+ bytes) that signs local connect
	// tokens and admin cookies. All control servers must share it. ST_SECRET_KEY.
	SecretKey []byte

	LocalAuth          bool   // ST_LOCAL_AUTH, default true: local accounts for VPN + admin site
	LocalRequireTOTP   bool   // ST_LOCAL_REQUIRE_TOTP, default false
	BootstrapAdminUser string // ST_BOOTSTRAP_ADMIN_USER, default "admin"
	BootstrapAdminPass string // ST_BOOTSTRAP_ADMIN_PASSWORD: creates that admin if no users exist

	// Entra is enabled when both ST_TENANT_ID and ST_API_AUDIENCE are set.
	TenantID        string        // ST_TENANT_ID
	Audiences       []string      // ST_API_AUDIENCE (comma-separated)
	RequiredScope   string        // ST_REQUIRED_SCOPE, default "access_as_user"
	RequireMFAClaim bool          // ST_REQUIRE_MFA_CLAIM, default false (v2 access tokens may omit amr; Conditional Access enforces MFA)
	MaxAuthAge      time.Duration // ST_MAX_AUTH_AGE, default 10m
	RequireAuthTime bool          // ST_REQUIRE_AUTH_TIME, default false (v2 access tokens omit auth_time)
	EntraSecret     string        // ST_ENTRA_CLIENT_SECRET: admin site sign-in (also settable on the admin site)

	Grace            time.Duration // ST_GRACE, default 15m
	SuspendAfter     time.Duration // ST_SUSPEND_AFTER, default 90s
	Heartbeat        time.Duration // ST_HEARTBEAT, default 30s
	MaxLifetime      time.Duration // ST_MAX_SESSION, default 12h
	GatewayHealthTTL time.Duration // ST_GATEWAY_HEALTH_TTL, default 45s

	// Default gateway placement limits, until an admin saves others on the
	// Gateways page: ST_PLACE_MAX_CPU (70), ST_PLACE_MAX_MEM (70), ST_PLACE_MIN_DISK_GB (10).
	PlaceMaxCPU, PlaceMaxMem, PlaceMinDiskGB float64
	SweepInterval    time.Duration // ST_SWEEP_INTERVAL, default 15s

	DNS        []string // ST_DNS_SERVERS (comma-separated)
	AllowedIPs []string // ST_ALLOWED_IPS, default "0.0.0.0/0,::/0" (full tunnel)
	MTU        int      // ST_MTU, default 1380
	Keepalive  int      // ST_KEEPALIVE seconds, default 25
}

// Load reads and validates the configuration.
func Load() (Config, error) {
	var errs []error
	c := Config{
		Listen:       env("ST_LISTEN", ":8443"),
		TLSCert:      os.Getenv("ST_TLS_CERT"),
		TLSKey:       os.Getenv("ST_TLS_KEY"),
		DatabaseURL:  os.Getenv("ST_DATABASE_URL"),
		Dev:          boolEnv("ST_DEV", false, &errs),
		GatewaysFile: os.Getenv("ST_GATEWAYS_FILE"),
		PublicURL:    os.Getenv("ST_PUBLIC_URL"),
		DownloadsDir: env("ST_DOWNLOADS_DIR", "/opt/securetunnel/clients"),

		LocalAuth:          boolEnv("ST_LOCAL_AUTH", true, &errs),
		LocalRequireTOTP:   boolEnv("ST_LOCAL_REQUIRE_TOTP", false, &errs),
		BootstrapAdminUser: env("ST_BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapAdminPass: os.Getenv("ST_BOOTSTRAP_ADMIN_PASSWORD"),

		TenantID:       os.Getenv("ST_TENANT_ID"),
		Audiences:       list(os.Getenv("ST_API_AUDIENCE")),
		RequiredScope:   env("ST_REQUIRED_SCOPE", "access_as_user"),
		RequireMFAClaim: boolEnv("ST_REQUIRE_MFA_CLAIM", false, &errs),
		MaxAuthAge:      durEnv("ST_MAX_AUTH_AGE", 10*time.Minute, &errs),
		RequireAuthTime: boolEnv("ST_REQUIRE_AUTH_TIME", false, &errs),
		EntraSecret:     os.Getenv("ST_ENTRA_CLIENT_SECRET"),

		Grace:            durEnv("ST_GRACE", 15*time.Minute, &errs),
		SuspendAfter:     durEnv("ST_SUSPEND_AFTER", 90*time.Second, &errs),
		Heartbeat:        durEnv("ST_HEARTBEAT", 30*time.Second, &errs),
		MaxLifetime:      durEnv("ST_MAX_SESSION", 12*time.Hour, &errs),
		GatewayHealthTTL: durEnv("ST_GATEWAY_HEALTH_TTL", 45*time.Second, &errs),
		PlaceMaxCPU:      floatEnv("ST_PLACE_MAX_CPU", 70, &errs),
		PlaceMaxMem:      floatEnv("ST_PLACE_MAX_MEM", 70, &errs),
		PlaceMinDiskGB:   floatEnv("ST_PLACE_MIN_DISK_GB", 10, &errs),
		SweepInterval:    durEnv("ST_SWEEP_INTERVAL", 15*time.Second, &errs),

		DNS:        list(os.Getenv("ST_DNS_SERVERS")),
		AllowedIPs: list(env("ST_ALLOWED_IPS", "0.0.0.0/0,::/0")),
		MTU:        intEnv("ST_MTU", 1380, &errs),
		Keepalive:  intEnv("ST_KEEPALIVE", 25, &errs),
	}

	if (c.TenantID == "") != (len(c.Audiences) == 0) {
		errs = append(errs, errors.New("set both ST_TENANT_ID and ST_API_AUDIENCE to enable Entra, or neither"))
	}
	if !c.LocalAuth && !c.EntraEnabled() {
		errs = append(errs, errors.New("no sign-in method: enable ST_LOCAL_AUTH or configure Entra"))
	}
	if v := os.Getenv("ST_SECRET_KEY"); v != "" {
		k, err := hex.DecodeString(strings.TrimSpace(v))
		if err != nil || len(k) < 32 {
			errs = append(errs, errors.New("ST_SECRET_KEY must be at least 32 bytes of hex (openssl rand -hex 32)"))
		}
		c.SecretKey = k
	} else if !c.Dev {
		errs = append(errs, errors.New("ST_SECRET_KEY is required (openssl rand -hex 32)"))
	}
	if !c.Dev {
		if c.TLSCert == "" || c.TLSKey == "" {
			errs = append(errs, errors.New("ST_TLS_CERT and ST_TLS_KEY are required (or set ST_DEV=true)"))
		}
		if c.DatabaseURL == "" {
			errs = append(errs, errors.New("ST_DATABASE_URL is required (or set ST_DEV=true for the in-memory store)"))
		}
	}
	if c.SuspendAfter <= c.Heartbeat {
		errs = append(errs, errors.New("ST_SUSPEND_AFTER must be longer than ST_HEARTBEAT"))
	}
	if c.Grace <= c.SuspendAfter {
		errs = append(errs, errors.New("ST_GRACE must be longer than ST_SUSPEND_AFTER"))
	}
	return c, errors.Join(errs...)
}

// EntraEnabled reports whether Entra token validation is configured.
func (c Config) EntraEnabled() bool { return c.TenantID != "" && len(c.Audiences) > 0 }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolEnv(k string, def bool, errs *[]error) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return b
}

func durEnv(k string, def time.Duration, errs *[]error) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return d
}

func floatEnv(k string, def float64, errs *[]error) float64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return f
}

func intEnv(k string, def int, errs *[]error) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return i
}
