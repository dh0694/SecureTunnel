package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clienttls"
)

const (
	settingsKey = `SOFTWARE\SecureTunnel`          // written by the installer and the app
	policyKey   = `SOFTWARE\Policies\SecureTunnel` // written by GPO/Intune; overrides and locks
	runKey      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	serviceName = "SecureTunnel"
	tunnelName  = "SecureTunnel"
	pipeName    = `\\.\pipe\SecureTunnel`
)

// dataDir is where the service keeps its state, logs and tunnel config.
// Only SYSTEM and Administrators can read it.
func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "SecureTunnel")
}

// ensureDataDir creates dataDir with an ACL for SYSTEM and Administrators only.
func ensureDataDir() error {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func readString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func writeString(path, name, value string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func deleteValue(path, name string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(name)
}

// configuredServer returns the control server URL and whether policy locks it.
func configuredServer() (string, bool) {
	if v := readString(policyKey, "ControlUrl"); v != "" {
		if s, err := agentcfg.NormalizeServer(v); err == nil {
			return s, true
		}
	}
	if v := readString(settingsKey, "Server"); v != "" {
		if s, err := agentcfg.NormalizeServer(v); err == nil {
			return s, false
		}
	}
	return "", false
}

// backupServers lists the backup addresses: from Group Policy/Intune
// (BackupServers, comma separated), the installer (/BACKUP), and the list the
// server sends with each heartbeat (cached so it works when the main
// address is down). The main server is left out.
func backupServers() []string {
	primary, _ := configuredServer()
	var raw []string
	for _, v := range []string{readString(policyKey, "BackupServers"), readString(settingsKey, "BackupServers")} {
		raw = append(raw, strings.Split(v, ",")...)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir(), "backup-servers.json")); err == nil {
		var pushed []string
		if json.Unmarshal(b, &pushed) == nil {
			raw = append(raw, pushed...)
		}
	}
	var out []string
	seen := map[string]bool{primary: true}
	for _, r := range raw {
		s, err := agentcfg.NormalizeServer(strings.TrimSpace(r))
		if err != nil || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// saveServer stores a new server and forgets the old server's certificate pin.
func saveServer(server string) error {
	if err := writeString(settingsKey, "Server", server); err != nil {
		return err
	}
	if readString(settingsKey, "CertPinServer") != server {
		deleteValue(settingsKey, "CertPin")
	}
	return nil
}

// regPins stores the server certificate pin in the registry.
type regPins struct{ server string }

func (p regPins) GetPin() string {
	if v := readString(policyKey, "CertPin"); v != "" {
		return v
	}
	if readString(settingsKey, "CertPinServer") != p.server {
		return "" // pin belongs to a different server
	}
	return readString(settingsKey, "CertPin")
}

func (p regPins) SetPin(pin string) error {
	if err := writeString(settingsKey, "CertPin", pin); err != nil {
		return err
	}
	return writeString(settingsKey, "CertPinServer", p.server)
}

var _ clienttls.PinStore = regPins{}

// bootID changes on every boot. Windows keeps a boot counter in the registry;
// if it's missing, fall back to the boot time rounded to 10 minutes.
func bootID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("BootId"); err == nil {
			return "bootid-" + strconv.FormatUint(v, 10)
		}
	}
	up := time.Duration(windows.DurationSinceBoot())
	return "boot-" + time.Now().Add(-up).Truncate(10*time.Minute).UTC().Format("20060102T1504")
}

// deviceID identifies this PC to the server for device approval: the Windows
// MachineGuid (stable across renames), falling back to the computer name.
func deviceID() string {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		defer k.Close()
		if g, _, err := k.GetStringValue("MachineGuid"); err == nil && g != "" {
			return strings.ToLower(g)
		}
	}
	return deviceName()
}

// deviceName is the computer name shown to admins.
func deviceName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "windows-pc"
	}
	return h
}

// dpapiStore keeps the session in dataDir, encrypted with the machine's DPAPI key.
type dpapiStore struct{ path string }

func newStore() *dpapiStore { return &dpapiStore{path: filepath.Join(dataDir(), "session.dat")} }

func (d *dpapiStore) Load() (*agentcore.Session, error) {
	enc, err := os.ReadFile(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := dpapi(enc, false)
	if err != nil {
		return nil, err
	}
	var s agentcore.Session
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (d *dpapiStore) Save(s *agentcore.Session) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	enc, err := dpapi(b, true)
	if err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}

func (d *dpapiStore) Clear() error {
	err := os.Remove(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func dpapi(in []byte, protect bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("empty input")
	}
	inBlob := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_LOCAL_MACHINE | windows.CRYPTPROTECT_UI_FORBIDDEN)
	var err error
	if protect {
		err = windows.CryptProtectData(&inBlob, nil, nil, 0, nil, flags, &out)
	} else {
		err = windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, flags, &out)
	}
	if err != nil {
		return nil, fmt.Errorf("dpapi: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// logToFile appends a line to a log file in dataDir (best effort).
func logToFile(name, line string) {
	f, err := os.OpenFile(filepath.Join(dataDir(), name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), line)
}
