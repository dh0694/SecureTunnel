package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateSkipsReservedAddresses(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.0/30") // .0 network, .1 gateway, .2 client, .3 broadcast
	if got := GatewayAddr(pool).String(); got != "10.200.0.1" {
		t.Errorf("gateway addr = %s", got)
	}
	a, err := Allocate(pool, nil)
	if err != nil || a.String() != "10.200.0.2" {
		t.Fatalf("first = %v, %v; want 10.200.0.2", a, err)
	}
	if _, err := Allocate(pool, map[netip.Addr]bool{a: true}); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("err = %v, want ErrPoolExhausted", err)
	}
}

func TestAllocateReusesFreedAddress(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.0/21")
	used := map[netip.Addr]bool{
		netip.MustParseAddr("10.200.0.2"): true,
		netip.MustParseAddr("10.200.0.4"): true,
	}
	a, _ := Allocate(pool, used)
	if a.String() != "10.200.0.3" {
		t.Errorf("got %s, want the gap at 10.200.0.3", a)
	}
}

func TestPoolSizeFor1500Users(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.0/21")
	used := map[netip.Addr]bool{}
	for i := 0; i < 2045; i++ { // 2048 - network - gateway - broadcast
		a, err := Allocate(pool, used)
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		used[a] = true
	}
	if _, err := Allocate(pool, used); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("err = %v, want exhausted after 2045", err)
	}
}
