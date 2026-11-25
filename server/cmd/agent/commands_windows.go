package main

import (
	"context"
	"sync"
	"time"

	"securetunnel/server/internal/clientapi"
)

// Notice is a message from IT shown in the app until the user dismisses it.
type Notice struct {
	ID   string    `json:"id"`
	Text string    `json:"text"`
	From string    `json:"from"`
	At   time.Time `json:"at"`
}

type noticeBox struct {
	mu sync.Mutex
	n  *Notice
}

func (b *noticeBox) get() *Notice {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n == nil {
		return nil
	}
	c := *b.n
	return &c
}

func (b *noticeBox) set(n Notice) {
	b.mu.Lock()
	b.n = &n
	b.mu.Unlock()
}

func (b *noticeBox) dismiss(id string) {
	b.mu.Lock()
	if b.n != nil && (id == "" || b.n.ID == id) {
		b.n = nil
	}
	b.mu.Unlock()
}

// handleCommands runs admin commands delivered with a heartbeat.
func (a *agentService) handleCommands(cmds []clientapi.Command) {
	for _, c := range cmds {
		a.log.Info("admin command", "type", c.Type, "from", c.From)
		switch c.Type {
		case "speedtest":
			a.speed.start(false)
		case "diagnostics":
			// Refresh public IPs in the background and send a diagnostics heartbeat.
			if a.ips != nil {
				a.ips.requestRefresh()
			}
			a.engine.Kick()
		case "move":
			a.engine.RequestMove(c.Text)
		case "update": // pushed from the admin site's App updates page
			a.upd.pushed(c.Text)
		case "logs":
			go func() {
				ref, err := sendLogs(context.Background(), a.engine, a.client, deviceID(), "admin", a.gatherLogs)
				a.log.Info("logs collected by IT", "ref", ref, "err", err)
			}()
		case "message":
			if c.Text != "" {
				a.notice.set(Notice{ID: c.ID, Text: c.Text, From: c.From, At: c.At})
			}
		}
	}
}
