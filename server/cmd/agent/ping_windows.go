//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi       = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate    = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose     = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho  = modiphlpapi.NewProc("IcmpSendEcho")
	errPingNoReply    = errors.New("no reply")
)

// icmpEchoReply is ICMP_ECHO_REPLY (64-bit layout); only the first fields are read.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [16]byte
}

// icmpPing sends one ICMP echo with the Windows ICMP helper (no raw sockets
// or admin rights needed) and times the round trip.
func icmpPing(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, error) {
	if !ip.Is4() {
		return 0, fmt.Errorf("ping: %s isn't IPv4", ip)
	}
	h, _, err := procIcmpCreate.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, fmt.Errorf("IcmpCreateFile: %w", err)
	}
	defer procIcmpClose.Call(h)

	a := ip.As4()
	dest := *(*uint32)(unsafe.Pointer(&a)) // IPAddr is in network byte order
	payload := []byte("SecureTunnel ping")
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+64)
	ms := uint32(timeout / time.Millisecond)

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// Blocks for at most the timeout.
	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(h, uintptr(dest),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(ms))
	elapsed := time.Since(start)
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if n == 0 || r.Status != 0 {
		return 0, errPingNoReply
	}
	// Windows reports whole milliseconds; the measured time is finer.
	if reported := time.Duration(r.RoundTripTime) * time.Millisecond; reported > elapsed {
		return reported, nil
	}
	return elapsed, nil
}
