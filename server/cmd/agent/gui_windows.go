package main

import (
	"embed"
	"encoding/json"
	"errors"
	"image/color"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/agenticon"
)

//go:embed web/index.html web/app.css web/app.js
var webFS embed.FS

const (
	guiMutexName = `Local\SecureTunnelGUI`
	guiShowEvent = `Local\SecureTunnelShow`
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procSetForeground = user32.NewProc("SetForegroundWindow")
	procShowWindow    = user32.NewProc("ShowWindow")
	procSysParamsInfo = user32.NewProc("SystemParametersInfoW")
	procGetWindowRect = user32.NewProc("GetWindowRect")
	procSetWindowPos  = user32.NewProc("SetWindowPos")
	procGetClientRect = user32.NewProc("GetClientRect")
	procGetDpiForWin  = user32.NewProc("GetDpiForWindow")
	procSetHook       = user32.NewProc("SetWindowsHookExW")
	procUnhook        = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHook  = user32.NewProc("CallNextHookEx")

	icons = map[string][]byte{}

	winMu sync.Mutex
	win   webview2.WebView

	trayStatus, trayAction *systray.MenuItem
	lastIcon               string
	lastNotice             string
	lastUpdateNotice       string // the update notice the window was last opened for
)

func runGUI() {
	// One tray icon per user session: a second launch just opens the window.
	name, _ := windows.UTF16PtrFromString(guiMutexName)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		ev, _ := windows.UTF16PtrFromString(guiShowEvent)
		if h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, ev); err == nil {
			_ = windows.SetEvent(h)
			_ = windows.CloseHandle(h)
		}
		return
	}
	for k, c := range map[string]color.RGBA{
		"connected":    agenticon.Connected,
		"reconnecting": agenticon.Reconnecting,
		"disconnected": agenticon.Disconnected,
		"office":       agenticon.Office,
	} {
		icons[k] = agenticon.ICO(c)
	}
	go listenForShow()
	systray.Run(onTrayReady, func() { os.Exit(0) })
}

// listenForShow opens the window when another launch signals the show event.
func listenForShow() {
	name, _ := windows.UTF16PtrFromString(guiShowEvent)
	h, err := windows.CreateEvent(nil, 0, 0, name)
	if err != nil {
		return
	}
	for {
		if ev, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil || ev != windows.WAIT_OBJECT_0 {
			return
		}
		openWindow()
	}
}

func onTrayReady() {
	systray.SetIcon(icons["disconnected"])
	systray.SetTitle("SecureTunnel")
	systray.SetTooltip("SecureTunnel")
	trayStatus = systray.AddMenuItem("Checking…", "")
	trayStatus.Disable()
	systray.AddSeparator()
	open := systray.AddMenuItem("Open SecureTunnel", "Show the SecureTunnel window")
	trayAction = systray.AddMenuItem("Connect…", "")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Exit", "Close the tray icon (the VPN service keeps running)")

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				openWindow()
			case <-trayAction.ClickedCh:
				st, err := pipeCall(ipcRequest{Cmd: "status"}, 5*time.Second)
				if err == nil && st.Status != nil && st.Status.State != agentcore.StateDisconnected {
					_, _ = pipeCall(ipcRequest{Cmd: "disconnect"}, 30*time.Second)
				} else {
					openWindow()
				}
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()

	go func() {
		first := true
		for {
			st := refreshTray()
			if first {
				first = false
				// At sign-in to Windows, show the window so the user can connect.
				if st == nil || st.State == agentcore.StateDisconnected {
					openWindow()
				}
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

func refreshTray() *agentcore.Status {
	resp, err := pipeCall(ipcRequest{Cmd: "status"}, 5*time.Second)
	if err != nil || resp.Status == nil {
		setIcon("disconnected")
		systray.SetTooltip("SecureTunnel: service not running")
		trayStatus.SetTitle("Service not running")
		trayAction.SetTitle("Connect…")
		return nil
	}
	// A new message from IT: open the window so the user sees it.
	if resp.Notice != nil && resp.Notice.ID != lastNotice {
		lastNotice = resp.Notice.ID
		openWindow()
	}
	// An update is about to interrupt the connection, or was just scheduled:
	// open the window once so the user can update now or postpone.
	if u := resp.Update; u != nil && u.State == "ready" && (!u.Countdown.IsZero() || !u.InstallAt.IsZero()) {
		key := u.Latest + "|" + u.Countdown.String() + "|" + u.InstallAt.String()
		if key != lastUpdateNotice {
			lastUpdateNotice = key
			openWindow()
		}
	}
	st := resp.Status
	label, icon := "Not connected", "disconnected"
	switch st.State {
	case agentcore.StateConnected:
		label, icon = "Connected", "connected"
		if st.OfficeMode {
			label, icon = "Office mode: traffic goes direct", "office"
		} else if st.Gateway != "" {
			label += " (" + st.Gateway + ")"
		}
	case agentcore.StateReconnecting:
		label, icon = "Reconnecting…", "reconnecting"
		if st.Message == "Connecting…" { // just after a network change
			label = "Connecting…"
		}
	case agentcore.StateSigningIn, agentcore.StateConnecting:
		label, icon = "Connecting…", "reconnecting"
	case agentcore.StateDisconnecting:
		label, icon = "Disconnecting…", "disconnected"
	default:
		if st.OnTrustedNetwork {
			label, icon = "On the corporate network", "office"
		}
	}
	setIcon(icon)
	systray.SetTooltip("SecureTunnel: " + label)
	trayStatus.SetTitle(label)
	if st.State == agentcore.StateDisconnected {
		trayAction.SetTitle("Connect…")
	} else {
		trayAction.SetTitle("Disconnect")
	}
	return st
}

func setIcon(name string) {
	if name != lastIcon {
		systray.SetIcon(icons[name])
		lastIcon = name
	}
}

// openWindow shows the app window, creating it if needed. The window runs on
// its own locked OS thread with its own message loop.
func openWindow() {
	winMu.Lock()
	if win != nil {
		hwnd := uintptr(win.Window())
		winMu.Unlock()
		procShowWindow.Call(hwnd, 9) // SW_RESTORE
		procSetForeground.Call(hwnd)
		return
	}
	winMu.Unlock()

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		dataPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "SecureTunnel", "WebView2")
		// Put the window in the bottom-right corner as Windows creates it,
		// so it never shows up centered first.
		unhook := hookPlacement()
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     false,
			AutoFocus: true,
			DataPath:  dataPath,
			WindowOptions: webview2.WindowOptions{
				Title:  "SecureTunnel",
				Width:  420,
				Height: 820,
				Center: false,
			},
		})
		unhook()
		if w == nil {
			msg, _ := windows.UTF16PtrFromString("SecureTunnel needs the Microsoft Edge WebView2 Runtime, which isn't installed on this PC.\n\nInstall it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and open SecureTunnel again.")
			title, _ := windows.UTF16PtrFromString("SecureTunnel")
			windows.MessageBox(0, msg, title, windows.MB_ICONWARNING)
			return
		}
		winMu.Lock()
		win = w
		winMu.Unlock()
		w.SetSize(420, 820, webview2.HintFixed)
		placeNearTray(uintptr(w.Window()))
		_ = w.Bind("stCall", func(reqJSON string) (string, error) {
			var req ipcRequest
			if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
				return "", err
			}
			if req.Cmd == "connect" {
				addUserProof(&req)
			}
			timeout := 10 * time.Second
			if req.Cmd == "auth_config" {
				timeout = authConfigPipeTimeout
			}
			if req.Cmd == "connect" || req.Cmd == "disconnect" || req.Cmd == "diagnose" || req.Cmd == "send_logs" {
				timeout = 200 * time.Second
			}
			resp, err := pipeCall(req, timeout)
			if err != nil {
				b, _ := json.Marshal(map[string]any{"ok": false, "service_down": true,
					"error": "The SecureTunnel service isn't running. Restart the PC or reinstall SecureTunnel."})
				return string(b), nil
			}
			go refreshTray()
			b, _ := json.Marshal(resp)
			return string(b), nil
		})
		// Sign in with Microsoft runs in the background; the page gets the
		// result through window.stEntraDone(json).
		_ = w.Bind("stEntra", func(seq int) (bool, error) {
			go func() {
				resp := runEntraConnect()
				b, _ := json.Marshal(resp)
				w.Dispatch(func() {
					w.Eval("window.stEntraDone && window.stEntraDone(" + string(b) + "," + strconv.Itoa(seq) + ")")
					hwnd := uintptr(w.Window())
					procShowWindow.Call(hwnd, 9) // SW_RESTORE
					procSetForeground.Call(hwnd)
				})
				go refreshTray()
			}()
			return true, nil
		})
		// Settings → Certificates: device certificates come through the
		// service (machine store); user certificates are read here, as the user.
		_ = w.Bind("stCerts", func() (string, error) {
			return certsForGUI(), nil
		})
		_ = w.Bind("stSetCert", func(kind, thumb string) (string, error) {
			var err error
			switch {
			case !validThumb(thumb):
				err = errors.New("that isn't a certificate thumbprint")
			case kind == "user":
				err = setUserCertPin(thumb)
			case kind == "device":
				var resp ipcResponse
				if resp, err = pipeCall(ipcRequest{Cmd: "set_device_cert", ID: thumb}, 10*time.Second); err == nil && !resp.OK {
					err = errors.New(resp.Error)
				}
			default:
				err = errors.New("unknown certificate kind")
			}
			if err != nil {
				b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
				return string(b), nil
			}
			return certsForGUI(), nil
		})
		_ = w.Bind("stEntraCancel", func() (bool, error) {
			cancelEntra()
			return true, nil
		})
		// The page asks for the height its content needs; the window follows,
		// staying anchored above the tray.
		_ = w.Bind("stResize", func(cssHeight int) (bool, error) {
			fitWindow(uintptr(w.Window()), cssHeight)
			return true, nil
		})
		w.SetHtml(pageHTML())
		w.Run()
		winMu.Lock()
		win = nil
		winMu.Unlock()
		w.Destroy()
	}()
}

// pageHTML inlines the CSS and JS into the HTML.
func pageHTML() string {
	html, _ := webFS.ReadFile("web/index.html")
	css, _ := webFS.ReadFile("web/app.css")
	js, _ := webFS.ReadFile("web/app.js")
	page := strings.Replace(string(html), "<!--CSS-->", "<style>"+string(css)+"</style>", 1)
	page = strings.Replace(page, "<!--JS-->", "<script>"+string(js)+"</script>", 1)
	return strings.Replace(page, "{{VERSION}}", version, 1)
}

// placeNearTray moves the window to the bottom-right of the work area (just
// above the taskbar, next to the tray icon), like the Wi-Fi and volume
// flyouts, and shortens it on small screens. If the taskbar is on another
// edge, the work area already excludes it.
func placeNearTray(hwnd uintptr) {
	var work, rc windows.Rect
	const spiGetWorkArea = 0x0030
	if r, _, _ := procSysParamsInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0); r == 0 {
		return
	}
	if r, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc))); r == 0 {
		return
	}
	const margin = 12
	w := rc.Right - rc.Left
	h := rc.Bottom - rc.Top
	if maxH := work.Bottom - work.Top - 2*margin; h > maxH {
		h = maxH
	}
	x := work.Right - w - margin
	y := work.Bottom - h - margin
	const swpNoZOrder, swpNoActivate = 0x0004, 0x0010
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpNoZOrder|swpNoActivate)
}

// fitWindow sets the window's height so the page (cssHeight CSS pixels)
// fits without scrolling, keeping the bottom edge above the tray and the
// window within the screen.
func fitWindow(hwnd uintptr, cssHeight int) {
	if cssHeight < 300 || cssHeight > 4000 {
		return
	}
	var work, rc, client windows.Rect
	const spiGetWorkArea = 0x0030
	if r, _, _ := procSysParamsInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0); r == 0 {
		return
	}
	if r, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc))); r == 0 {
		return
	}
	if r, _, _ := procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client))); r == 0 {
		return
	}
	dpi := uint32(96)
	if procGetDpiForWin.Find() == nil {
		if d, _, _ := procGetDpiForWin.Call(hwnd); d != 0 {
			dpi = uint32(d)
		}
	}
	frame := (rc.Bottom - rc.Top) - (client.Bottom - client.Top) // title bar + borders
	h := int32(cssHeight)*int32(dpi)/96 + frame
	const margin = 12
	if maxH := work.Bottom - work.Top - 2*margin; h > maxH {
		h = maxH
	}
	w := rc.Right - rc.Left
	if h == rc.Bottom-rc.Top {
		return
	}
	// Keep the window's bottom edge where it was (above the tray) when it
	// was docked there; otherwise grow downward but stay on screen.
	y := rc.Bottom - h
	if rc.Bottom > work.Bottom-margin-2 || y < work.Top {
		y = work.Bottom - h - margin
	}
	const swpNoZOrder, swpNoActivate = 0x0004, 0x0010
	procSetWindowPos.Call(hwnd, 0, uintptr(rc.Left), uintptr(y), uintptr(w), uintptr(h), swpNoZOrder|swpNoActivate)
}

// CREATESTRUCTW and CBT_CREATEWNDW (winuser.h).
type createStruct struct {
	createParams uintptr
	instance     uintptr
	menu         uintptr
	parent       uintptr
	cy, cx, y, x int32
	style        int32
	name         *uint16
	class        *uint16
	exStyle      uint32
}

type cbtCreateWnd struct {
	cs          *createStruct
	insertAfter uintptr
}

var (
	placeHook     uintptr
	placeHookProc = syscall.NewCallback(func(code int, wparam, lparam uintptr) uintptr {
		const hcbtCreateWnd = 3
		if code == hcbtCreateWnd && lparam != 0 {
			cbt := *(**cbtCreateWnd)(unsafe.Pointer(&lparam)) // lparam points to a CBT_CREATEWND
			if cs := cbt.cs; cs != nil && cs.parent == 0 && cs.cx > 0 && cs.cy > 0 {
				var work windows.Rect
				const spiGetWorkArea, margin = 0x0030, 12
				if r, _, _ := procSysParamsInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0); r != 0 {
					if maxH := work.Bottom - work.Top - 2*margin; cs.cy > maxH {
						cs.cy = maxH
					}
					cs.x = work.Right - cs.cx - margin
					cs.y = work.Bottom - cs.cy - margin
				}
			}
		}
		r, _, _ := procCallNextHook.Call(placeHook, uintptr(code), wparam, lparam)
		return r
	})
)

// hookPlacement watches window creation on this thread (WH_CBT) and places
// the first top-level window in the bottom-right corner. Call the returned
// func once the window exists.
func hookPlacement() func() {
	const whCBT = 5
	h, _, _ := procSetHook.Call(whCBT, placeHookProc, 0, uintptr(windows.GetCurrentThreadId()))
	placeHook = h
	return func() {
		if placeHook != 0 {
			procUnhook.Call(placeHook)
			placeHook = 0
		}
	}
}
