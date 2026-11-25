// Package ipam hands out client tunnel addresses from a gateway's pool.
package ipam

import (
	"errors"
	"net/netip"
)

// ErrPoolExhausted means every client address in the pool is in use.
var ErrPoolExhausted = errors.New("ip pool exhausted")

// GatewayAddr is the gateway's own tunnel address: the first host in its pool.
func GatewayAddr(pool netip.Prefix) netip.Addr {
	return pool.Masked().Addr().Next()
}

// Allocate returns the lowest free client address in pool. It skips the network
// address, the gateway's own address and (for IPv4) the broadcast address.
func Allocate(pool netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	pool = pool.Masked()
	if !pool.IsValid() {
		return netip.Addr{}, errors.New("invalid pool")
	}
	first := GatewayAddr(pool).Next()
	for a := first; a.IsValid() && pool.Contains(a); a = a.Next() {
		if a.Is4() && !pool.Contains(a.Next()) {
			break // broadcast address
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}
