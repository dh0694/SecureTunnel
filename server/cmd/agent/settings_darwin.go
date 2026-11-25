//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
)

// Mac settings:
//   - /Library/Application Support/SecureTunnel/config.json (root only):
//     server, certificate pins.
//   - A server pushed by MDM (configuration profile, domain
//     com.securetunnel.agent, key Server) wins and locks the setting.
//   - session.json holds the live session (root only, 0600).

const (
	appSupport   = "/Library/Application Support/SecureTunnel"
	managedPlist = "/Library/Managed Preferences/com.securetunnel.agent.plist"
	socketPath   = "/var/run/securetunnel.sock"
	appBundle    = "/Applications/SecureTunnel.app"
)

func dataDir() string { return appSupport }

func ensureDataDir() error { return os.MkdirAll(appSupport, 0o755) }

type macConfig struct {
	Server string            `json:"server,omitempty"`
	Pins   map[string]string `json:"pins,omitempty"`
}

var cfgMu sync.Mutex

func loadConfig() macConfig {
	var c macConfig
	b, err := os.ReadFile(filepath.Join(appSupport, "config.json"))
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Pins == nil {
		c.Pins = map[string]string{}
	}
	return c
}

func saveConfig(c macConfig) error {
	if err := ensureDataDir(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := filepath.Join(appSupport, "config.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(appSupport, "config.json"))
}

// managedServer reads the Server key MDM pushed, if any.
func managedServer() string {
	if _, err := os.Stat(managedPlist); err != nil {
		return ""
	}
	out, err := exec.Command("/usr/bin/plutil", "-extract", "Server", "raw", "-o", "-", managedPlist).Output()
	if err != nil {
		return ""
	}
	s, err := agentcfg.NormalizeServer(strings.TrimSpace(string(out)))
	if err != nil {
		return ""
	}
	return s
}

// configuredServer returns the server and whether IT locked it.
func configuredServer() (string, bool) {
	if s := managedServer(); s != "" {
		return s, true
	}
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return loadConfig().Server, false
}

func saveServer(server string) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	c := loadConfig()
	c.Server = server
	return saveConfig(c)
}

// filePins stores the trusted-on-first-use certificate pin per server.
type filePins struct{ server string }

func (p filePins) GetPin() string {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return loadConfig().Pins[p.server]
}

func (p filePins) SetPin(pin string) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	c := loadConfig()
	c.Pins[p.server] = pin
	return saveConfig(c)
}

var bootRE = regexp.MustCompile(`sec = (\d+)`)

// bootID changes on every reboot (kern.boottime).
func bootID() string {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return "unknown"
	}
	if m := bootRE.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return strings.TrimSpace(string(out))
}

var uuidRE = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`)

// deviceID is the Mac's hardware UUID.
func deviceID() string {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		if m := uuidRE.FindSubmatch(out); m != nil {
			return strings.ToLower(string(m[1]))
		}
	}
	h, _ := os.Hostname()
	return h
}

func deviceName() string {
	out, err := exec.Command("/usr/sbin/scutil", "--get", "ComputerName").Output()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return strings.TrimSpace(string(out))
	}
	h, _ := os.Hostname()
	return strings.TrimSuffix(h, ".local")
}

// fileStore keeps the session in a root-only file. (The Windows agent uses
// DPAPI; on the Mac the file's permissions protect it.)
type fileStore struct{ path string }

func newStore() *fileStore { return &fileStore{path: filepath.Join(appSupport, "session.json")} }

func (f *fileStore) Load() (*agentcore.Session, error) {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s agentcore.Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (f *fileStore) Save(s *agentcore.Session) error {
	if err := ensureDataDir(); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *fileStore) Clear() error {
	err := os.Remove(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
