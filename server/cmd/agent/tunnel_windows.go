package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"securetunnel/server/internal/agentcore"
)

// The WireGuard-for-Windows tunnel library runs each tunnel as its own
// Windows service named WireGuardTunnel$<name>, which creates the network
// adapter, sets routes and DNS, and (for a full tunnel) blocks all traffic
// outside the tunnel. We run it from our own exe ("securetunnel.exe tunnel").
const tunnelService = "WireGuardTunnel$" + tunnelName

type serviceTunnel struct {
	exe string
	log *slog.Logger
}

func (t *serviceTunnel) confPath() string {
	return filepath.Join(dataDir(), tunnelName+".conf")
}

func (t *serviceTunnel) Running() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(tunnelService)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State == svc.Running
}

func (t *serviceTunnel) Up(c agentcore.TunnelConfig) error {
	if err := t.Down(); err != nil {
		t.log.Warn("removing old tunnel", "err", err)
	}
	if err := ensureDataDir(); err != nil {
		return fmt.Errorf("prepare data folder: %w", err)
	}
	if err := os.WriteFile(t.confPath(), []byte(c.WGQuick()), 0o600); err != nil {
		return fmt.Errorf("write tunnel config: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	waitGone(m)
	s, err := m.CreateService(tunnelService, t.exe, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		DisplayName:  "SecureTunnel tunnel",
		Description:  "WireGuard tunnel for SecureTunnel. Started and stopped by the SecureTunnel service.",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "tunnel", t.confPath())
	if err != nil {
		return fmt.Errorf("create tunnel service: %w", err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start tunnel service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			t.log.Info("tunnel up", "endpoint", c.Endpoint, "address", c.Address)
			return nil
		case svc.Stopped:
			msg := fmt.Sprintf("tunnel service stopped (exit code %d)", st.Win32ExitCode)
			if st.ServiceSpecificExitCode != 0 {
				msg += fmt.Sprintf(", service code %d", st.ServiceSpecificExitCode)
			}
			_ = s.Delete()
			return errors.New(msg + "; see " + filepath.Join(dataDir(), "log.bin") + " or the Windows event log")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("the tunnel took too long to start")
}

func (t *serviceTunnel) Down() error {
	defer os.Remove(t.confPath())
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(tunnelService)
	if err != nil {
		return nil // not installed: nothing to do
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("remove tunnel service: %w", err)
	}
	// Windows finishes deleting the service in the background; Up waits for
	// that if needed, so disconnecting doesn't have to.
	t.log.Info("tunnel down")
	return nil
}

// waitGone waits (briefly) for a deleted tunnel service to disappear so it can be recreated.
func waitGone(m *mgr.Mgr) {
	for i := 0; i < 40; i++ {
		s, err := m.OpenService(tunnelService)
		if err != nil {
			return
		}
		s.Close()
		time.Sleep(250 * time.Millisecond)
	}
}
