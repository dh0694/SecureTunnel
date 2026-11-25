package api

import (
	"context"
	"net/http/httptest"
	"testing"

	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/session"
)

func TestHeartbeatCommandAcknowledgments(t *testing.T) {
	r := newRig(t)
	server := httptest.NewServer(r.mux)
	defer server.Close()
	client := &clientapi.Client{Base: server.URL}
	ctx := context.Background()
	connect := func(device, key string) session.Placement {
		t.Helper()
		p, err := r.srv.Sessions.Connect(ctx, model.Identity{UPN: "user@example.com"},
			session.ConnectRequest{DeviceID: device, BootID: "boot", WGPublicKey: key})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	queue := func(p session.Placement, message string) model.Command {
		t.Helper()
		cmd, err := r.srv.Sessions.SendCommand(ctx, p.Session.ID, "admin", "message", message)
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	heartbeat := func(p session.Placement, wantID string, acks ...string) {
		t.Helper()
		got, _, err := client.HeartbeatWithCommandAcks(ctx, p.Session.ID, p.ResumeToken, "boot", nil, acks)
		if err != nil {
			t.Fatal(err)
		}
		if wantID == "" && len(got.Commands) == 0 {
			return
		}
		if wantID == "" || len(got.Commands) != 1 || got.Commands[0].ID != wantID {
			t.Fatalf("commands = %#v, want %q", got.Commands, wantID)
		}
	}

	p := connect("user-device", wgKey)
	other := connect("other-device", wgKey2)
	cmd := queue(p, "first")
	otherCmd := queue(other, "other session")
	heartbeat(p, cmd.ID)
	heartbeat(p, cmd.ID)
	heartbeat(p, "", cmd.ID, otherCmd.ID)
	heartbeat(p, "", cmd.ID)
	heartbeat(other, otherCmd.ID)

	cmd = queue(p, "legacy")
	legacy, _, err := client.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot", nil)
	if err != nil || len(legacy.Commands) != 1 || legacy.Commands[0].ID != cmd.ID {
		t.Fatalf("legacy heartbeat = %#v, %v, want %q", legacy.Commands, err, cmd.ID)
	}
	heartbeat(p, "")
}
