package model

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"regexp"
	"sort"
)

// UpdatePolicy controls how the apps update themselves (admin site → App
// updates). Apps get it with every version check, so it reaches PCs that
// aren't connected too.
type UpdatePolicy struct {
	// Paused stops offering new versions (pushes from the admin site still work).
	Paused bool `json:"paused"`
	// RolloutPercent offers a new version to this share of PCs first (1–100).
	// Which PCs are in the first group changes with every release.
	RolloutPercent int `json:"rollout_percent"`
	// InstallWhen: "disconnected" (whenever the VPN is off: no interruption),
	// "window" (also while connected, inside the maintenance window), or
	// "anytime" (as soon as it's downloaded: disconnect, update, reconnect).
	InstallWhen string `json:"install_when"`
	// The maintenance window, in each PC's local time. Days: 0 = Sunday.
	WindowDays  []int  `json:"window_days"`
	WindowStart string `json:"window_start"` // "HH:MM"
	WindowEnd   string `json:"window_end"`   // "HH:MM"; earlier than start = past midnight
	// DeadlineDays installs a waiting update even while connected after this
	// many days (0 = no deadline).
	DeadlineDays int `json:"deadline_days"`
	// NotifyUsers shows a notice in the app when an update is waiting.
	NotifyUsers bool `json:"notify_users"`
	// MaxPostpones is how many times a user may put off an install that would
	// interrupt their connection, by an hour each (0 = they can't).
	MaxPostpones int `json:"max_postpones"`
}

// Install timing options.
const (
	InstallDisconnected = "disconnected"
	InstallWindow       = "window"
	InstallAnytime      = "anytime"
)

// DefaultUpdatePolicy installs only while disconnected, to everyone, with a
// notice in the app.
func DefaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{RolloutPercent: 100, InstallWhen: InstallDisconnected,
		WindowDays: []int{1, 2, 3, 4, 5}, WindowStart: "01:00", WindowEnd: "05:00", NotifyUsers: true, MaxPostpones: 3}
}

var hhmmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// Normalize fills defaults and checks the values.
func (p *UpdatePolicy) Normalize() error {
	d := DefaultUpdatePolicy()
	if p.RolloutPercent == 0 {
		p.RolloutPercent = 100
	}
	if p.RolloutPercent < 1 || p.RolloutPercent > 100 {
		return errors.New("rollout must be 1–100%")
	}
	switch p.InstallWhen {
	case "":
		p.InstallWhen = d.InstallWhen
	case InstallDisconnected, InstallWindow, InstallAnytime:
	default:
		return errors.New("unknown install option")
	}
	if p.WindowStart == "" {
		p.WindowStart = d.WindowStart
	}
	if p.WindowEnd == "" {
		p.WindowEnd = d.WindowEnd
	}
	if !hhmmRE.MatchString(p.WindowStart) || !hhmmRE.MatchString(p.WindowEnd) {
		return errors.New("window times look like 01:00")
	}
	if p.WindowStart == p.WindowEnd {
		return errors.New("the maintenance window can't start and end at the same time")
	}
	seen := map[int]bool{}
	days := []int{}
	for _, x := range p.WindowDays {
		if x < 0 || x > 6 {
			return errors.New("window days are 0 (Sunday) to 6 (Saturday)")
		}
		if !seen[x] {
			seen[x] = true
			days = append(days, x)
		}
	}
	sort.Ints(days)
	if p.InstallWhen == InstallWindow && len(days) == 0 {
		return errors.New("pick at least one day for the maintenance window")
	}
	p.WindowDays = days
	if p.DeadlineDays < 0 || p.DeadlineDays > 90 {
		return errors.New("deadline must be 0 (none) to 90 days")
	}
	if p.MaxPostpones < 0 || p.MaxPostpones > 10 {
		return errors.New("postpones must be 0 to 10")
	}
	return nil
}

// InRollout reports whether a PC gets version now under a staged rollout.
// The split is by device and version, so each release starts with a
// different group of PCs, and a PC stays in or out for that release.
func InRollout(deviceID, version string, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 || deviceID == "" {
		return false
	}
	h := sha256.Sum256([]byte(deviceID + "\x00" + version))
	return int(binary.BigEndian.Uint32(h[:4])%100) < percent
}
