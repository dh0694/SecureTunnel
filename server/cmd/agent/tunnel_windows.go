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
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if err := stopTunnelService(m); err != nil {
		return fmt.Errorf("remove old tunnel: %w", err)
	}
	if err := waitGone(m); err != nil {
		return err
	}
	if err := ensureDataDir(); err != nil {
		return fmt.Errorf("prepare data folder: %w", err)
	}
	configPath := t.confPath()
	tempPath := configPath + ".tmp"
	defer os.Remove(tempPath)
	if err := os.WriteFile(tempPath, []byte(c.WGQuick()), 0o600); err != nil {
		return fmt.Errorf("write tunnel config: %w", err)
	}
	if err := os.Rename(tempPath, configPath); err != nil {
		return fmt.Errorf("replace tunnel config: %w", err)
	}
	s, err := m.CreateService(tunnelService, t.exe, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		DisplayName:  "SecureTunnel tunnel",
		Description:  "WireGuard tunnel for SecureTunnel. Started and stopped by the SecureTunnel service.",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "tunnel", configPath)
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
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if err := stopTunnelService(m); err != nil {
		return err
	}
	if err := os.Remove(t.confPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tunnel config: %w", err)
	}
	t.log.Info("tunnel down")
	return nil
}

func stopTunnelService(m *mgr.Mgr) error {
	s, err := m.OpenService(tunnelService)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return nil
	case errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
		return waitGone(m)
	case err != nil:
		return fmt.Errorf("open tunnel service: %w", err)
	}
	defer s.Close()
	stopRequested := false
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query tunnel service: %w", err)
		}
		if st.State == svc.Stopped {
			break
		}
		if !time.Now().Before(deadline) {
			return errors.New("the tunnel service took too long to stop")
		}
		if !stopRequested && st.State != svc.StartPending && st.State != svc.StopPending {
			_, err = s.Control(svc.Stop)
			switch {
			case err == nil:
				stopRequested = true
			case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE),
				errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
				// The service transitioned while the stop request was sent.
			default:
				return fmt.Errorf("stop tunnel service: %w", err)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("remove tunnel service: %w", err)
	}
	return nil
}

// waitGone waits (briefly) for a deleted tunnel service to disappear so it can be recreated.
func waitGone(m *mgr.Mgr) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, err := m.OpenService(tunnelService)
		switch {
		case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
			return nil
		case err == nil:
			s.Close()
		case !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
			return fmt.Errorf("check tunnel service deletion: %w", err)
		}
		if !time.Now().Before(deadline) {
			return errors.New("the tunnel service took too long to be deleted")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
