package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
)

// updater keeps the agent current. It checks the server shortly after start
// and every 6 hours (or when asked, or when IT pushes an update), downloads a
// newer installer in the background and verifies its SHA-256.
//
// When it installs follows the policy from the admin site's App updates page:
//   - while the VPN is disconnected: as soon as the update is due;
//   - while connected: only when it's due: pushed "now", scheduled, inside
//     the maintenance window, "anytime", past the deadline, or the user's
//     own "Update now". Then the user gets a 2-minute countdown (they can
//     update right away or postpone, within limits) before it installs.
//
// Installing while connected doesn't end the session: the installer replaces
// the app, the service restarts and resumes the saved session on its own
// (no sign-in), so users see a short drop.
type updater struct {
	a *agentService

	checkMu   sync.Mutex
	mu        sync.Mutex
	state     string // "", "checking", "up_to_date", "held", "downloading", "ready", "installing", "error"
	latest    string
	message   string
	file      string
	checkedAt time.Time
	policy    clientapi.UpdatePolicy
	held      string // why a newer version isn't offered yet: "paused" or "rollout"
	plan      updatePlan
}

// updatePlan is what's decided about the waiting update; it's saved so a
// restart doesn't reset the deadline, the schedule or the postpones.
type updatePlan struct {
	Version      string    `json:"version"`
	ReadySince   time.Time `json:"ready_since"`
	InstallAt    time.Time `json:"install_at,omitempty"`    // scheduled by IT, or after a postpone
	Pushed       bool      `json:"pushed,omitempty"`        // IT asked for it now
	AdminPush    bool      `json:"admin_push,omitempty"`    // keep honoring the push across update checks
	OnDisconnect bool      `json:"on_disconnect,omitempty"` // IT asked to wait for a disconnect
	UserNow      bool      `json:"user_now,omitempty"`      // the user clicked Update now
	Immediate    bool      `json:"immediate,omitempty"`     // IT pushed it with no warning: install at once
	Countdown    time.Time `json:"countdown,omitempty"`     // installs at this time (2-minute warning)
	Postponed    int       `json:"postponed,omitempty"`
	Why          string    `json:"why,omitempty"` // shown with the countdown
}

const updateWarning = 2 * time.Minute

// UpdateInfo is shown in the app.
type UpdateInfo struct {
	Current     string    `json:"current"`
	Latest      string    `json:"latest,omitempty"`
	State       string    `json:"state"`
	Message     string    `json:"message,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
	Held        string    `json:"held,omitempty"`
	InstallWhen string    `json:"install_when,omitempty"` // the policy: disconnected | window | anytime
	Window      string    `json:"window,omitempty"`       // e.g. "Mon, Tue 01:00–05:00"
	InstallAt   time.Time `json:"install_at,omitempty"`
	Countdown   time.Time `json:"countdown,omitempty"`
	Why         string    `json:"why,omitempty"`
	CanPostpone bool      `json:"can_postpone"`
	Postponed   int       `json:"postponed,omitempty"`
	Deadline    time.Time `json:"deadline,omitempty"`
	Notify      bool      `json:"notify"`
}

func (u *updater) info() UpdateInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	i := UpdateInfo{Current: version, Latest: u.latest, State: u.state, Message: u.message, CheckedAt: u.checkedAt,
		Held: u.held, InstallWhen: u.policy.InstallWhen, Window: windowText(u.policy),
		InstallAt: u.plan.InstallAt, Countdown: u.plan.Countdown, Why: u.plan.Why, Postponed: u.plan.Postponed,
		Notify: u.policy.NotifyUsers || u.plan.Pushed || !u.plan.InstallAt.IsZero() || !u.plan.Countdown.IsZero()}
	if u.plan.OnDisconnect {
		i.InstallWhen, i.Window = "disconnected", ""
	}
	if u.state == "ready" {
		i.Deadline = u.deadlineLocked()
		i.CanPostpone = u.canPostponeLocked(time.Now())
	}
	return i
}

func (u *updater) set(state, msg string) {
	u.mu.Lock()
	u.state, u.message = state, msg
	u.mu.Unlock()
}

func updateDir() string { return filepath.Join(dataDir(), "update") }
func planPath() string  { return filepath.Join(updateDir(), "plan.json") }

func (u *updater) savePlanLocked() {
	if u.plan.Version == "" {
		_ = os.Remove(planPath())
		return
	}
	_ = os.MkdirAll(updateDir(), 0o700)
	if b, err := json.Marshal(u.plan); err == nil {
		_ = os.WriteFile(planPath(), b, 0o600)
	}
}

func (u *updater) loadPlan() {
	b, err := os.ReadFile(planPath())
	if err != nil {
		return
	}
	u.mu.Lock()
	_ = json.Unmarshal(b, &u.plan)
	u.plan.Countdown, u.plan.UserNow = time.Time{}, false // these don't survive a restart
	u.mu.Unlock()
}

// deadlineLocked is when a waiting update installs even while connected.
func (u *updater) deadlineLocked() time.Time {
	if u.policy.DeadlineDays <= 0 || u.plan.ReadySince.IsZero() {
		return time.Time{}
	}
	return u.plan.ReadySince.Add(time.Duration(u.policy.DeadlineDays) * 24 * time.Hour)
}

func (u *updater) canPostponeLocked(now time.Time) bool {
	if u.plan.UserNow || u.plan.Immediate || u.plan.Postponed >= u.policy.MaxPostpones {
		return false
	}
	d := u.deadlineLocked()
	return d.IsZero() || now.Add(time.Hour).Before(d)
}

func windowText(p clientapi.UpdatePolicy) string {
	if p.InstallWhen != "window" || len(p.WindowDays) == 0 {
		return ""
	}
	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	var days []string
	for _, d := range p.WindowDays {
		if d >= 0 && d < 7 {
			days = append(days, names[d])
		}
	}
	return strings.Join(days, ", ") + " " + p.WindowStart + "–" + p.WindowEnd
}

// run checks periodically and installs a downloaded update when it's due.
func (u *updater) run(ctx context.Context) {
	u.loadPlan()
	sleepUntil := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	if !sleepUntil(90 * time.Second) {
		return
	}
	for {
		u.mu.Lock()
		due := time.Since(u.checkedAt) >= 6*time.Hour
		u.mu.Unlock()
		if due {
			u.check(ctx, false)
		}
		u.maybeInstall()
		if !sleepUntil(5 * time.Second) {
			return
		}
	}
}

// check asks the server which version this PC should run and downloads it if
// newer. force (an IT push) skips pause and staged rollout.
func (u *updater) check(ctx context.Context, force bool) UpdateInfo {
	return u.checkWithPush(ctx, force, nil)
}

func (u *updater) checkWithPush(ctx context.Context, force bool, push *updatePlan) UpdateInfo {
	u.checkMu.Lock()
	defer u.checkMu.Unlock()
	if ctx.Err() != nil {
		return u.info()
	}

	server, _ := configuredServer()
	if server == "" {
		u.set("error", "No server is set up yet.")
		return u.info()
	}
	u.mu.Lock()
	if u.state == "downloading" || u.state == "installing" {
		u.mu.Unlock()
		return u.info()
	}
	force = force || u.plan.AdminPush
	u.state, u.message, u.checkedAt = "checking", "", time.Now()
	u.mu.Unlock()

	c := u.a.client(server)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	v, err := c.CheckUpdate(cctx, "windows", deviceID(), force)
	cancel()
	if err != nil {
		u.set("error", "Couldn't check for updates: "+agentcore.Friendly(err))
		return u.info()
	}
	u.mu.Lock()
	if v.Policy != nil {
		u.policy = *v.Policy
	}
	u.latest, u.held = v.Version, v.Held
	if v.Version == "" {
		u.latest = v.Latest
	}
	u.mu.Unlock()
	if v.Version == "" && v.Held != "" && clientapi.NewerVersion(v.Latest, version) {
		u.set("held", "")
		return u.info()
	}
	if !clientapi.NewerVersion(v.Version, version) {
		u.mu.Lock()
		u.state, u.message, u.plan = "up_to_date", "", updatePlan{}
		u.savePlanLocked()
		u.mu.Unlock()
		return u.info()
	}

	file := filepath.Join(updateDir(), "SecureTunnel-Setup-"+v.Version+".exe")
	if fileSHA256(file) != strings.ToLower(v.SHA256) {
		u.set("downloading", "")
		if err := u.download(ctx, c, v, file); err != nil {
			u.set("error", err.Error())
			return u.info()
		}
		u.a.log.Info("update downloaded", "version", v.Version)
	}
	u.mu.Lock()
	u.state, u.file, u.message = "ready", file, ""
	if u.plan.Version != v.Version { // a new release: start its plan afresh
		u.plan = updatePlan{Version: v.Version, ReadySince: time.Now()}
	}
	if push != nil {
		u.plan.AdminPush = true
		u.plan.Immediate, u.plan.Pushed, u.plan.OnDisconnect = push.Immediate, push.Pushed, push.OnDisconnect
		u.plan.InstallAt = push.InstallAt
		u.plan.UserNow, u.plan.Countdown, u.plan.Why = false, time.Time{}, ""
	}
	u.savePlanLocked()
	u.mu.Unlock()
	return u.info()
}

func (u *updater) download(ctx context.Context, c *clientapi.Client, v clientapi.ClientVersion, file string) error {
	if err := os.MkdirAll(updateDir(), 0o700); err != nil {
		return err
	}
	tmp := file + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	err = c.Download(dctx, v.URL, f, 200<<20)
	cancel()
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return errors.New("Download failed: " + agentcore.Friendly(err))
	}
	if got := fileSHA256(tmp); got != strings.ToLower(v.SHA256) {
		os.Remove(tmp)
		u.a.log.Error("update checksum mismatch", "want", v.SHA256, "got", got)
		return errors.New("The downloaded update didn't match its checksum, so it wasn't installed.")
	}
	return os.Rename(tmp, file)
}

// pushed handles an "update" command from the admin site: "disconnect"
// (install the next time they disconnect), "now" (disconnect, update and
// reconnect, after the warning), "immediate" (the same with no warning and
// no postponing) or an RFC 3339 time to do it at (with the warning).
func (u *updater) pushed(text string) {
	var push updatePlan
	switch text {
	case "immediate":
		push.Immediate = true
	case "now":
		push.Pushed = true
	case "disconnect":
		push.OnDisconnect = true
	default:
		at, err := time.Parse(time.RFC3339, text)
		if err != nil {
			u.a.log.Warn("invalid update push schedule", "when", text, "err", err)
			return
		}
		push.InstallAt = at
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		info := u.checkWithPush(ctx, true, &push)
		if info.State != "ready" {
			u.a.log.Info("update push: nothing to install", "state", info.State, "message", info.Message)
			return
		}
		u.a.log.Info("update pushed by IT", "when", text, "version", info.Latest)
		u.maybeInstall()
	}()
}

// maybeInstall installs a downloaded update if it's due (see updater).
func (u *updater) maybeInstall() {
	now := time.Now()
	u.mu.Lock()
	if u.state != "ready" {
		u.mu.Unlock()
		return
	}
	pl := u.plan
	if !pl.UserNow && !pl.Immediate && !pl.InstallAt.IsZero() && now.Before(pl.InstallAt) {
		u.mu.Unlock()
		return
	}
	disconnected := u.a.engine.Status().State == agentcore.StateDisconnected
	why := ""
	p, deadline := u.policy, u.deadlineLocked()
	switch {
	case pl.UserNow:
		why = "you asked to update now"
	case pl.Immediate:
		why = "IT pushed an urgent update"
	case disconnected:
		why = "the VPN is disconnected"
	case pl.OnDisconnect:
		u.mu.Unlock()
		return
	case pl.Pushed:
		why = "IT pushed this update"
	case !pl.InstallAt.IsZero():
		why = "it was scheduled for now"
	case p.InstallWhen == "anytime":
		why = "updates install as soon as they're ready"
	case p.InstallWhen == "window" && p.InWindow(now):
		why = "it's the maintenance window"
	case !deadline.IsZero() && !now.Before(deadline):
		why = "the deadline to update has passed"
	}
	if why == "" {
		u.mu.Unlock()
		return
	}
	if !disconnected && !pl.UserNow && !pl.Immediate {
		if pl.Countdown.IsZero() {
			u.plan.Countdown, u.plan.Why = now.Add(updateWarning), why
			u.mu.Unlock()
			u.a.log.Info("update starts in 2 minutes", "why", why)
			return
		}
		if now.Before(pl.Countdown) {
			u.mu.Unlock()
			return
		}
	}
	file := u.file
	u.state, u.message = "installing", ""
	u.plan = updatePlan{}
	u.savePlanLocked()
	u.mu.Unlock()
	u.install(file, why)
}

// install runs the installer. The session stays saved, so after the service
// restarts it reconnects without signing in.
func (u *updater) install(file, why string) {
	u.a.log.Info("installing update", "file", file, "why", why)
	// Tell the next service start to reopen the tray app for the signed-in user.
	_ = os.WriteFile(filepath.Join(dataDir(), "relaunch-gui"), []byte(time.Now().Format(time.RFC3339)), 0o600)
	cmd := exec.Command(file, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		u.set("error", "Couldn't start the installer: "+err.Error())
		return
	}
	_ = cmd.Process.Release()
	// The installer now stops this service, replaces the files and starts the new version.
}

// requestInstall is the app's "Update now" button: install right away (a
// short drop if connected; the session resumes on its own).
func (u *updater) requestInstall() error {
	u.mu.Lock()
	if u.state != "ready" {
		u.mu.Unlock()
		return errors.New("no update is ready to install")
	}
	u.plan.UserNow = true
	u.mu.Unlock()
	go u.maybeInstall()
	return nil
}

// postpone is the app's "Postpone" button: an hour later, within the limits.
func (u *updater) postpone() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state != "ready" || !u.canPostponeLocked(time.Now()) {
		return errors.New("this update can't be postponed any more")
	}
	u.plan.Postponed++
	u.plan.Pushed, u.plan.Countdown, u.plan.Why = false, time.Time{}, ""
	u.plan.InstallAt = time.Now().Add(time.Hour)
	u.savePlanLocked()
	u.a.log.Info("update postponed by the user", "until", u.plan.InstallAt, "times", u.plan.Postponed)
	return nil
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cleanupUpdates removes old installers after a successful update.
func cleanupUpdates() {
	entries, _ := os.ReadDir(updateDir())
	for _, e := range entries {
		_ = os.Remove(filepath.Join(updateDir(), e.Name()))
	}
}

// relaunchGUIIfUpdated reopens the tray app in the signed-in user's session
// after an update (the installer closed it to replace the files).
func relaunchGUIIfUpdated(log func(string, ...any)) {
	marker := filepath.Join(dataDir(), "relaunch-gui")
	st, err := os.Stat(marker)
	if err != nil {
		return
	}
	_ = os.Remove(marker)
	cleanupUpdates()
	if time.Since(st.ModTime()) > 30*time.Minute {
		return
	}
	exe, _ := os.Executable()
	if err := startInUserSession(exe); err != nil {
		log("couldn't reopen the tray app after update", "err", err)
	}
}

// startInUserSession starts exe as the user signed in at the console.
func startInUserSession(exe string) error {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return errors.New("no one is signed in")
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sid, &tok); err != nil {
		return fmt.Errorf("get user token: %w", err)
	}
	defer tok.Close()
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, tok, false); err != nil {
		return fmt.Errorf("user environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(block)
	cmdline, _ := windows.UTF16PtrFromString(`"` + exe + `"`)
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, nil, cmdline, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT, block, dir, &si, &pi); err != nil {
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	return nil
}
