//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
)

// Windows users and the tunnel: the tunnel belongs to the whole PC, so the
// service remembers which Windows user connected it (the "owner") and, per
// the policy group's settings, disconnects when that user signs out, when
// someone else starts using the PC, or after the screen has been locked a
// while. It also refuses connect/disconnect from other users when told to.

const (
	wtsConsoleConnect = 0x1
	wtsRemoteConnect  = 0x3
	wtsSessionLogon   = 0x5
	wtsSessionLogoff  = 0x6
	wtsSessionLock    = 0x7
	wtsSessionUnlock  = 0x8

	wtsUserName       = 5
	wtsDomainName     = 7
	nameUserPrincipal = 8
	noSession         = ^uint32(0)
)

var (
	modwtsapi32                  = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInfo      = modwtsapi32.NewProc("WTSQuerySessionInformationW")
	procGetPipeClientSessionID   = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientSessionId")
	procImpersonateLoggedOnUser  = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	procGetUserNameExW           = windows.NewLazySystemDLL("secur32.dll").NewProc("GetUserNameExW")
)

// winUser identifies a Windows user in a session.
type winUser struct {
	Session uint32 `json:"session"`
	SID     string `json:"sid"`
	Name    string `json:"name"` // UPN when there is one, else DOMAIN\user
}

func (u winUser) known() bool { return u.SID != "" }

// sameUser reports whether two sessions belong to the same Windows account.
func (u winUser) sameUser(o winUser) bool { return u.SID != "" && strings.EqualFold(u.SID, o.SID) }

// sessionUser looks up who is signed in to a Windows session ("" if nobody).
func sessionUser(session uint32) winUser {
	u := winUser{Session: session}
	if session == noSession {
		return u
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return u
	}
	defer tok.Close()
	if tu, err := tok.GetTokenUser(); err == nil {
		u.SID = tu.User.Sid.String()
	}
	u.Name = upnFor(tok)
	if u.Name == "" {
		dom, name := wtsString(session, wtsDomainName), wtsString(session, wtsUserName)
		u.Name = name
		if dom != "" {
			u.Name = dom + `\` + name
		}
	}
	return u
}

// upnFor returns the user's UPN (jsmith@contoso.com) for domain and Entra
// accounts by briefly impersonating them; local accounts have none.
func upnFor(tok windows.Token) string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, _ := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
		return ""
	}
	defer windows.RevertToSelf()
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	if r, _, _ := procGetUserNameExW.Call(nameUserPrincipal, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func wtsString(session uint32, class int) string {
	var p *uint16
	var n uint32
	if r, _, _ := procWTSQuerySessionInfo.Call(0, uintptr(session), uintptr(class), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n))); r == 0 || p == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(p)))
	return windows.UTF16PtrToString(p)
}

// pipeCallerSession returns the Windows session of the process on the other
// end of the pipe, or noSession if it can't be told.
func pipeCallerSession(c any) uint32 {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return windows.WTSGetActiveConsoleSessionId()
	}
	var id uint32
	if r, _, _ := procGetPipeClientSessionID.Call(f.Fd(), uintptr(unsafe.Pointer(&id))); r == 0 {
		return windows.WTSGetActiveConsoleSessionId()
	}
	return id
}

// ---- the owner ----

type winOwner struct {
	mu        sync.Mutex
	u         winUser
	lockTimer *time.Timer
}

func ownerPath() string { return filepath.Join(dataDir(), "owner.json") }

func (o *winOwner) load() {
	b, err := os.ReadFile(ownerPath())
	if err != nil {
		return
	}
	o.mu.Lock()
	_ = json.Unmarshal(b, &o.u)
	o.mu.Unlock()
}

func (o *winOwner) get() winUser {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.u
}

func (o *winOwner) set(u winUser) {
	o.mu.Lock()
	o.u = u
	if o.lockTimer != nil {
		o.lockTimer.Stop()
		o.lockTimer = nil
	}
	o.mu.Unlock()
	if b, err := json.Marshal(u); err == nil {
		_ = os.WriteFile(ownerPath(), b, 0o600)
	}
}

// ownerView is what the app window is told about who owns the tunnel.
type ownerView struct {
	Name          string `json:"name,omitempty"`
	You           bool   `json:"you"`            // the caller is the owner (or the same user, when that counts)
	CanConnect    bool   `json:"can_connect"`    // false when another user's tunnel blocks this one
	CanDisconnect bool   `json:"can_disconnect"` // false when only the owner may disconnect
}

// isOwner reports whether caller counts as the owner under the policy.
func isOwner(owner, caller winUser, pol clientapi.WindowsSessions) bool {
	if !owner.known() || !caller.known() {
		return true // can't tell: don't lock anyone out
	}
	if caller.Session == owner.Session {
		return true
	}
	return owner.sameUser(caller) && pol.SameUserSession != "different"
}

// view says, for the caller, whether they own the tunnel and what they may do.
func (a *agentService) ownerViewFor(caller winUser) *ownerView {
	pol, connected := a.engine.WindowsSessions()
	owner := a.owner.get()
	if !connected || !owner.known() {
		return &ownerView{You: true, CanConnect: true, CanDisconnect: true}
	}
	v := &ownerView{Name: owner.Name, CanConnect: true, CanDisconnect: true}
	v.You = isOwner(owner, caller, pol)
	if !v.You {
		v.CanConnect = pol.OnSwitch != "block"
		v.CanDisconnect = pol.DisconnectBy != "owner" && pol.OnSwitch != "block"
	}
	return v
}

// checkCaller refuses commands another Windows user isn't allowed to run
// while this tunnel is connected. It returns "" when the command may go ahead.
func (a *agentService) checkCaller(cmd string, caller winUser) string {
	if cmd != "connect" && cmd != "connect_token" && cmd != "disconnect" {
		return ""
	}
	v := a.ownerViewFor(caller)
	switch {
	case v.You:
		return ""
	case cmd == "disconnect" && !v.CanDisconnect:
		return "The VPN was connected by " + v.Name + ". Only they can disconnect it on this PC."
	case cmd != "disconnect" && !v.CanConnect:
		return "SecureTunnel is in use by " + v.Name + " on this PC. Ask them to disconnect, or sign out of their Windows session."
	}
	return ""
}

// claim makes caller the owner after they connect.
func (a *agentService) claim(caller winUser) {
	if caller.known() {
		a.owner.set(caller)
		a.log.Info("tunnel owner", "windows_user", caller.Name, "session", caller.Session)
	}
}

// ---- Windows session events ----

// onSessionChange runs for each Windows session event (sign-in, sign-out,
// switch, lock) while the service runs.
func (a *agentService) onSessionChange(event uint32, session uint32) {
	pol, connected := a.engine.WindowsSessions()
	owner := a.owner.get()
	if !connected || !owner.known() {
		return
	}
	switch event {
	case wtsSessionLogoff:
		if session != owner.Session || pol.OnSignOut == "stay" {
			return
		}
		a.disconnectFor("You signed out of Windows, so the VPN disconnected.")
		if pol.OnSignOut == "device_tunnel" {
			a.onUserSignedOut()
		}
	case wtsSessionLogon, wtsConsoleConnect, wtsRemoteConnect:
		if session == owner.Session || pol.OnSwitch != "disconnect" {
			return
		}
		u := sessionUser(session)
		if !u.known() || isOwner(owner, u, pol) {
			return
		}
		if owner.sameUser(u) {
			a.disconnectFor("You opened another Windows session on this PC, so the VPN disconnected. Connect again from the session you're using.")
		} else {
			a.disconnectFor(fmt.Sprintf("Another Windows user (%s) started using this PC, so the VPN disconnected.", u.Name))
		}
	case wtsSessionLock:
		if session != owner.Session || pol.LockMinutes <= 0 {
			return
		}
		mins := pol.LockMinutes
		a.owner.mu.Lock()
		if a.owner.lockTimer != nil {
			a.owner.lockTimer.Stop()
		}
		a.owner.lockTimer = time.AfterFunc(time.Duration(mins)*time.Minute, func() {
			a.disconnectFor(fmt.Sprintf("Your screen was locked for %d minutes, so the VPN disconnected.", mins))
		})
		a.owner.mu.Unlock()
	case wtsSessionUnlock:
		if session != owner.Session {
			return
		}
		a.owner.mu.Lock()
		if a.owner.lockTimer != nil {
			a.owner.lockTimer.Stop()
			a.owner.lockTimer = nil
		}
		a.owner.mu.Unlock()
	}
}

func (a *agentService) disconnectFor(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ { // a connect or disconnect may be in progress
		err := a.engine.DisconnectBecause(ctx, reason)
		if err != agentcore.ErrBusy {
			if err != nil {
				a.log.Warn("disconnect", "reason", reason, "err", err)
			}
			break
		}
		time.Sleep(time.Second)
	}
}

// checkOwnerAfterRestore runs at service start: if the tunnel resumed but its
// owner's Windows session is gone (signed out while the service was down),
// apply the sign-out rule.
func (a *agentService) checkOwnerAfterRestore() {
	pol, connected := a.engine.WindowsSessions()
	owner := a.owner.get()
	if !connected || !owner.known() || pol.OnSignOut == "stay" {
		return
	}
	if now := sessionUser(owner.Session); now.SID != owner.SID {
		a.disconnectFor("You signed out of Windows, so the VPN disconnected.")
		if pol.OnSignOut == "device_tunnel" {
			a.onUserSignedOut()
		}
	}
}

// onUserSignedOut runs after the user tunnel ends because its owner signed
// out and the policy says "switch to the device tunnel". The device tunnel
// (pre-logon) work hooks in here.
func (a *agentService) onUserSignedOut() { a.engine.WakeDeviceTunnel() }


// wtsSessionNotification is WTSSESSION_NOTIFICATION, the event data of a
// service session-change notification.
type wtsSessionNotification struct {
	Size      uint32
	SessionID uint32
}
