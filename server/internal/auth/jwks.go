package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// KeySource returns the RSA public key Entra used to sign a token.
type KeySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// ErrUnknownKey means the token's key ID is not in Entra's published key set.
var ErrUnknownKey = errors.New("unknown signing key")

// JWKSSource fetches and caches Entra's signing keys for one tenant.
// Keys are refreshed daily, or early when a token names a key we have not seen
// (Entra rotates keys), at most once a minute.
type JWKSSource struct {
	url    string
	client *http.Client

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetched     time.Time
	lastAttempt time.Time
}

// NewJWKSSource returns a key source for the given Entra tenant ID.
func NewJWKSSource(tenantID string) *JWKSSource {
	return &JWKSSource{
		url:    "https://login.microsoftonline.com/" + tenantID + "/discovery/v2.0/keys",
		client: &http.Client{Timeout: 10 * time.Second},
		keys:   map[string]*rsa.PublicKey{},
	}
}

// Key implements KeySource.
func (j *JWKSSource) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	k, ok := j.keys[kid]
	if ok && time.Since(j.fetched) < 24*time.Hour {
		return k, nil
	}
	if time.Since(j.lastAttempt) < time.Minute {
		if ok {
			return k, nil
		}
		return nil, ErrUnknownKey
	}
	j.lastAttempt = time.Now()
	if err := j.refresh(ctx); err != nil {
		if ok {
			return k, nil // keep using the cached key if Entra is briefly unreachable
		}
		return nil, err
	}
	if k, ok = j.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

func (j *JWKSSource) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	j.keys = keys
	j.fetched = time.Now()
	return nil
}
