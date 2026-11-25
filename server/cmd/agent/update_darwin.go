//go:build darwin

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
)

// macUpdater checks the server for a newer Mac package every 6 hours,
// downloads it, and installs it when the user isn't connected (or when they
// click Install now). Installing restarts the daemon; a live session is
// restored right after, without signing in again.
type macUpdater struct {
	a *agentDaemon

	mu        sync.Mutex
	state     string // up_to_date | checking | downloading | ready | installing | error
	message   string
	latest    string
	checkedAt time.Time
	pkgPath   string
	install   chan struct{}
}

func (u *macUpdater) info() UpdateInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.state
	if st == "" {
		st = "up_to_date"
	}
	return UpdateInfo{Current: version, Latest: u.latest, State: st, Message: u.message, CheckedAt: u.checkedAt}
}

func (u *macUpdater) set(state, msg string) {
	u.mu.Lock()
	u.state, u.message = state, msg
	u.mu.Unlock()
}

func (u *macUpdater) run(ctx context.Context) {
	u.install = make(chan struct{}, 1)
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		u.check(ctx)
		// Install a ready update when disconnected, checking each minute.
		deadline := time.After(6 * time.Hour)
	wait:
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.install:
				u.doInstall()
			case <-deadline:
				break wait
			case <-time.After(time.Minute):
				if u.info().State == "ready" && u.a.engine.Status().State == agentcore.StateDisconnected {
					u.doInstall()
				}
			}
		}
	}
}

func (u *macUpdater) check(ctx context.Context) UpdateInfo {
	server, _ := configuredServer()
	if server == "" {
		u.set("error", "No server is set up yet.")
		return u.info()
	}
	u.mu.Lock()
	u.state, u.message, u.checkedAt = "checking", "", time.Now()
	u.mu.Unlock()
	c := u.a.client(server)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	v, err := c.LatestVersionFor(cctx, "macos")
	cancel()
	if err != nil {
		u.set("error", "Couldn't check for updates: "+agentcore.Friendly(err))
		return u.info()
	}
	u.mu.Lock()
	u.latest = v.Version
	u.mu.Unlock()
	if !clientapi.NewerVersion(v.Version, version) {
		u.set("up_to_date", "")
		return u.info()
	}
	u.set("downloading", "")
	path := filepath.Join(appSupport, "update.pkg")
	if err := download(ctx, c, v, path); err != nil {
		u.set("error", "Couldn't download the update: "+err.Error())
		return u.info()
	}
	u.mu.Lock()
	u.pkgPath, u.state, u.message = path, "ready", ""
	u.mu.Unlock()
	return u.info()
}

func download(ctx context.Context, c *clientapi.Client, v clientapi.ClientVersion, path string) error {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	err = c.Download(dctx, v.URL, io.MultiWriter(f, h), 200<<20)
	f.Close()
	if err != nil {
		return err
	}
	if v.SHA256 != "" && hex.EncodeToString(h.Sum(nil)) != v.SHA256 {
		_ = os.Remove(tmp)
		return errors.New("checksum mismatch")
	}
	return os.Rename(tmp, path)
}

func (u *macUpdater) requestInstall() error {
	if u.info().State != "ready" {
		return errors.New("no update is ready to install")
	}
	select {
	case u.install <- struct{}{}:
	default:
	}
	return nil
}

// doInstall runs Apple's installer in its own process group so it survives
// the daemon being restarted by the package's postinstall script.
func (u *macUpdater) doInstall() {
	u.mu.Lock()
	path := u.pkgPath
	u.state = "installing"
	u.mu.Unlock()
	u.a.log.Info("installing update", "pkg", path)
	cmd := exec.Command("/usr/sbin/installer", "-pkg", path, "-target", "/")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		u.set("error", "Couldn't start the installer: "+err.Error())
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			u.set("error", "The update didn't install: "+err.Error())
		}
	}()
}
