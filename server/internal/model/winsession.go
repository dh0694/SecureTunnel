package model

import (
	"fmt"
	"strings"
)

// WindowsSessionPolicy says what the app does when Windows users sign out,
// switch, or lock the screen while the VPN is connected. Set per policy group.
type WindowsSessionPolicy struct {
	// OnSignOut: the user who connected signs out of Windows.
	OnSignOut string `json:"on_sign_out"` // disconnect | stay | device_tunnel
	// OnSwitch: a different Windows user signs in or switches in (console or RDP).
	OnSwitch string `json:"on_switch"` // disconnect | share | block
	// SameUserSession: the same Windows user in a second session (e.g. RDP to their own PC).
	SameUserSession string `json:"same_user_session"` // same | different
	// LockMinutes disconnects after the screen has been locked this long (0 = never).
	LockMinutes int `json:"lock_minutes"`
	// UserMatch: the Windows user isn't the user who signed in to the VPN.
	UserMatch string `json:"user_match"` // allow | warn | block
	// DisconnectBy: who can press Disconnect on the PC.
	DisconnectBy string `json:"disconnect_by"` // anyone | owner
}

// Windows session options.
const (
	WinDisconnect   = "disconnect"
	WinStay         = "stay"
	WinDeviceTunnel = "device_tunnel"
	WinShare        = "share"
	WinBlock        = "block"
	WinSame         = "same"
	WinDifferent    = "different"
	WinAllow        = "allow"
	WinWarn         = "warn"
	WinAnyone       = "anyone"
	WinOwner        = "owner"
)

// DefaultWindowsSessions is the recommended behavior.
func DefaultWindowsSessions() WindowsSessionPolicy {
	return WindowsSessionPolicy{OnSignOut: WinDisconnect, OnSwitch: WinDisconnect, SameUserSession: WinSame,
		LockMinutes: 0, UserMatch: WinAllow, DisconnectBy: WinAnyone}
}

// Normalize fills defaults and checks the options.
func (p *WindowsSessionPolicy) Normalize() error {
	d := DefaultWindowsSessions()
	pick := func(field *string, def, name string, ok ...string) error {
		*field = strings.ToLower(strings.TrimSpace(*field))
		if *field == "" {
			*field = def
			return nil
		}
		for _, o := range ok {
			if *field == o {
				return nil
			}
		}
		return fmt.Errorf("unknown %s option %q", name, *field)
	}
	if err := pick(&p.OnSignOut, d.OnSignOut, "sign-out", WinDisconnect, WinStay, WinDeviceTunnel); err != nil {
		return err
	}
	if err := pick(&p.OnSwitch, d.OnSwitch, "user switch", WinDisconnect, WinShare, WinBlock); err != nil {
		return err
	}
	if err := pick(&p.SameUserSession, d.SameUserSession, "same user", WinSame, WinDifferent); err != nil {
		return err
	}
	if err := pick(&p.UserMatch, d.UserMatch, "user match", WinAllow, WinWarn, WinBlock); err != nil {
		return err
	}
	if err := pick(&p.DisconnectBy, d.DisconnectBy, "disconnect", WinAnyone, WinOwner); err != nil {
		return err
	}
	if p.LockMinutes < 0 || p.LockMinutes > 1440 {
		return fmt.Errorf("screen lock: minutes must be 0 (never) to 1440")
	}
	return nil
}

// WindowsUserMatches compares the Windows user with the VPN user. Windows
// users come as a UPN (jsmith@contoso.com, from Entra/AD) or DOMAIN\user
// (local or unknown); VPN users are a UPN (Entra) or a local name.
func WindowsUserMatches(windowsUser, vpnUser string) bool {
	w, v := strings.ToLower(strings.TrimSpace(windowsUser)), strings.ToLower(strings.TrimSpace(vpnUser))
	if w == "" || v == "" {
		return true // nothing to compare
	}
	if w == v {
		return true
	}
	// DOMAIN\jsmith vs jsmith@contoso.com or jsmith: compare the user part.
	if i := strings.LastIndexByte(w, '\\'); i >= 0 {
		w = w[i+1:]
		if j := strings.IndexByte(v, '@'); j >= 0 {
			v = v[:j]
		}
		return w == v
	}
	return false
}
