//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runEntraConnect does the whole Microsoft sign-in and connect for the GUI and
// returns a response shaped like the pipe's (ok / error / status).
func runEntraConnect() map[string]any {
	fail := func(err error) map[string]any { return map[string]any{"ok": false, "error": err.Error()} }
	resp, err := pipeCall(ipcRequest{Cmd: "auth_config"}, 15*time.Second)
	if err != nil {
		return map[string]any{"ok": false, "service_down": true,
			"error": "The SecureTunnel service isn't running. Restart the PC or reinstall SecureTunnel."}
	}
	if !resp.OK || resp.Auth == nil {
		if resp.Error == "" {
			resp.Error = "couldn't get the sign-in settings from the server"
		}
		return fail(errors.New(resp.Error))
	}
	r, err := entraSignIn(context.Background(), *resp.Auth)
	if err != nil {
		return fail(err)
	}
	creq := ipcRequest{Cmd: "connect_token", Token: r.Token, Username: r.User}
	addUserProof(&creq)
	cresp, err := pipeCall(creq, 200*time.Second)
	if err != nil {
		return fail(errors.New("the SecureTunnel service isn't running"))
	}
	b, _ := json.Marshal(cresp)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// addUserProof fetches a challenge through the service and, when the server
// wants a user certificate, signs it with one from the user's store.
func addUserProof(req *ipcRequest) {
	resp, err := pipeCall(ipcRequest{Cmd: "challenge"}, 15*time.Second)
	if err != nil || !resp.OK || resp.Challenge == nil {
		return // older server or no device trust: the service manages without
	}
	req.Challenge = resp.Challenge
	req.Proofs = userProof(*resp.Challenge)
}

// openBrowser opens the sign-in page in a small Microsoft Edge app window
// (no tabs or address bar) near the tray. Edge signs in with the Windows
// account's Primary Refresh Token, so Conditional Access sees the device
// (compliant / hybrid joined) without any extension. Falls back to the
// default browser.
func openBrowser(u string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	if edge := edgePath(); edge != "" {
		args := `--app="` + u + `" --window-size=480,680`
		var work windows.Rect
		const spiGetWorkArea, margin = 0x0030, 12
		if r, _, _ := procSysParamsInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0); r != 0 {
			x, y := work.Right-480-margin, work.Bottom-680-margin
			if y < work.Top {
				y = work.Top
			}
			args += fmt.Sprintf(" --window-position=%d,%d", x, y)
		}
		file, _ := windows.UTF16PtrFromString(edge)
		params, _ := windows.UTF16PtrFromString(args)
		if err := windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL); err == nil {
			return nil
		}
	}
	target, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

var (
	procEnumWindows    = user32.NewProc("EnumWindows")
	procGetWindowTextW = user32.NewProc("GetWindowTextW")
	procPostMessageW   = user32.NewProc("PostMessageW")
)

// signedInNote is shown on the success page.
const signedInNote = "SecureTunnel is connecting. This window closes by itself."

// closeSignInWindow closes the browser window showing our "signed in" page.
func closeSignInWindow() { procEnumWindows.Call(closeSignInCB, 0) }

var closeSignInCB = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
	buf := make([]uint16, 256)
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n > 0 && strings.HasPrefix(windows.UTF16ToString(buf[:n]), signedInTitle) {
		const wmClose = 0x0010
		procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
	return 1 // keep enumerating
})

func edgePath() string {
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		p := filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
