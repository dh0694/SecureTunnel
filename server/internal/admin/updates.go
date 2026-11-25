package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/model"
)

// App updates (admin site → App updates): the update policy every app gets
// with its version check, and pushing an update to connected PCs.

// deviceInfo finds a device's name and platform (cached a minute: version
// checks come from every PC every few hours).
func (s *Server) deviceInfo(ctx context.Context, id string) (name, platform string) {
	devCache.Lock()
	defer devCache.Unlock()
	if time.Since(devCache.at) > time.Minute {
		if devs, err := s.Store.ListDevices(ctx, ""); err == nil {
			devCache.byID = map[string]model.Device{}
			for _, d := range devs {
				devCache.byID[d.ID] = d
			}
			devCache.at = time.Now()
		}
	}
	d := devCache.byID[id]
	return d.Name, d.Platform
}

var devCache struct {
	sync.Mutex
	byID map[string]model.Device
	at   time.Time
}

// updatePolicyFor is the app updates policy for a device.
func (s *Server) updatePolicyFor(ctx context.Context, platform, name string) model.Policy {
	if s.Groups == nil {
		return model.DefaultPolicies()[2]
	}
	p, _ := s.Groups.ForDevice(ctx, model.PolicyUpdates, platform, name)
	return p
}

// UpdateOffer is the downloads handler's per-PC decision: is the latest
// version offered to this PC now, and with which install policy (from the
// app updates policy that applies to the PC).
func (s *Server) UpdateOffer(r *http.Request, deviceID, latest string, force bool) (bool, string, any) {
	name, platform := s.deviceInfo(r.Context(), deviceID)
	if platform == "" {
		platform = "windows"
	}
	p := *s.updatePolicyFor(r.Context(), platform, name).Updates
	switch {
	case force:
		return true, "", p
	case p.Paused:
		return false, "paused", p
	case !model.InRollout(deviceID, latest, p.RolloutPercent):
		return false, "rollout", p
	}
	return true, "", p
}

// updatePC is one connected PC on the App updates page.
type updatePC struct {
	SessionID string    `json:"session_id"`
	User      string    `json:"user"`
	PC        string    `json:"pc"`
	Platform  string    `json:"platform"`
	Version   string    `json:"version"`
	Outdated  bool      `json:"outdated"`
	Update    string    `json:"update,omitempty"`     // the app's update state: downloading, ready, scheduled…
	UpdateAt  time.Time `json:"update_at,omitempty"`   // when it will install, if scheduled
	Postponed int       `json:"postponed,omitempty"` // times the user put it off
	Policy    string    `json:"policy"`              // the app updates policy that applies
}

// updatePolicyView is one app updates policy on the App updates page.
type updatePolicyView struct {
	model.Policy
	GroupNames []string `json:"group_names"`
	PCs        int      `json:"pcs"` // Windows PCs it applies to now
}

// getUpdates is the App updates page: the current version, which versions
// the PCs run, and the connected PCs with their update state.
func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	latest := ""
	if s.LatestClient != nil {
		latest = s.LatestClient()
	}
	devs, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		s.internal(w, err)
		return
	}
	// The app updates policies, with how many PCs each applies to.
	var pols []updatePolicyView
	byID := map[string]int{}
	if s.Groups != nil {
		ps := s.Groups.Set(ctx)
		names := map[string]string{}
		for _, g := range ps.Groups {
			names[g.ID] = g.Name
		}
		for _, p := range ps.Policies {
			if p.Type != model.PolicyUpdates {
				continue
			}
			v := updatePolicyView{Policy: p}
			for _, gid := range p.Groups {
				v.GroupNames = append(v.GroupNames, names[gid])
			}
			byID[p.ID] = len(pols)
			pols = append(pols, v)
		}
	}
	versions := map[string]int{}
	for _, d := range devs {
		if d.Platform == "windows" && d.AgentVersion != "" {
			versions[d.AgentVersion]++
		}
		if d.Platform == "windows" {
			if i, ok := byID[s.updatePolicyFor(ctx, d.Platform, d.Name).ID]; ok {
				pols[i].PCs++
			}
		}
	}
	type vc struct {
		Version string `json:"version"`
		PCs     int    `json:"pcs"`
		Current bool   `json:"current"`
	}
	var vlist []vc
	outdatedPCs := 0
	for v, n := range versions {
		vlist = append(vlist, vc{Version: v, PCs: n, Current: v == latest})
		if latest != "" && clientapi.NewerVersion(latest, v) {
			outdatedPCs += n
		}
	}
	sort.Slice(vlist, func(i, j int) bool { return clientapi.NewerVersion(vlist[i].Version, vlist[j].Version) })

	live, err := s.Store.ListSessions(ctx, model.SessionFilter{State: "live", Limit: 100000})
	if err != nil {
		s.internal(w, err)
		return
	}
	pcs := []updatePC{}
	for _, se := range live {
		if se.IsDevice() || se.ClientVersion == "" || se.Platform != "windows" {
			continue
		}
		pc := updatePC{SessionID: se.ID, User: se.UPN, PC: se.DeviceName, Platform: se.Platform, Version: se.ClientVersion,
			Outdated: latest != "" && clientapi.NewerVersion(latest, se.ClientVersion),
			Policy:   s.updatePolicyFor(ctx, se.Platform, se.DeviceName).Name}
		if d := parseDiag(se.Diag); d != nil {
			pc.Update, pc.UpdateAt, pc.Postponed = d.UpdateState, d.UpdateAt, d.UpdatePostponed
		}
		pcs = append(pcs, pc)
	}
	sort.Slice(pcs, func(i, j int) bool {
		if pcs[i].Outdated != pcs[j].Outdated {
			return pcs[i].Outdated
		}
		return strings.ToLower(pcs[i].PC) < strings.ToLower(pcs[j].PC)
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"latest": latest, "policies": pols, "versions": vlist,
		"devices": len(devs), "outdated_devices": outdatedPCs, "connected": pcs,
	})
}

type pushBody struct {
	// Target: "outdated" (every connected PC on an older version) or "pcs".
	Target   string   `json:"target"`
	Sessions []string `json:"sessions"`
	// When: "disconnect" (install the next time they disconnect), "now"
	// (disconnect, update, reconnect, after a 2-minute warning), "immediate"
	// (the same with no warning and no postponing) or "at" (like now, at At).
	When string    `json:"when"`
	At   time.Time `json:"at"`
}

// pushUpdate sends an "update" command to connected PCs. The command's text
// is "disconnect", "now", "immediate" or the RFC 3339 time to install at.
func (s *Server) pushUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var b pushBody
	if !readJSON(w, r, &b) {
		return
	}
	text := b.When
	switch b.When {
	case "disconnect", "now", "immediate":
	case "at":
		if b.At.Before(s.now().Add(time.Minute)) {
			writeErr(w, http.StatusBadRequest, "bad_request", "pick a time in the future")
			return
		}
		if b.At.After(s.now().Add(30 * 24 * time.Hour)) {
			writeErr(w, http.StatusBadRequest, "bad_request", "schedule it within the next 30 days")
			return
		}
		text = b.At.UTC().Format(time.RFC3339)
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "when must be disconnect, now, immediate or at")
		return
	}
	latest := ""
	if s.LatestClient != nil {
		latest = s.LatestClient()
	}
	live, err := s.Store.ListSessions(ctx, model.SessionFilter{State: "live", Limit: 100000})
	if err != nil {
		s.internal(w, err)
		return
	}
	want := map[string]bool{}
	for _, id := range b.Sessions {
		want[id] = true
	}
	sent, skipped := 0, 0
	for _, se := range live {
		if se.IsDevice() || se.Platform != "windows" {
			continue
		}
		switch b.Target {
		case "outdated":
			if latest == "" || !clientapi.NewerVersion(latest, se.ClientVersion) {
				continue
			}
		case "pcs":
			if !want[se.ID] {
				continue
			}
		default:
			writeErr(w, http.StatusBadRequest, "bad_request", "target must be outdated or pcs")
			return
		}
		if se.ClientVersion == "" { // not the SecureTunnel app (test client): can't take commands
			skipped++
			continue
		}
		c := model.Command{ID: randID(), Type: "update", Text: text, From: current(r).Username, At: s.now()}
		if err := s.Store.AddCommand(ctx, se.ID, c); err != nil {
			skipped++
			continue
		}
		sent++
	}
	what := map[string]string{"disconnect": "install after they disconnect", "now": "disconnect, update and reconnect now",
		"immediate": "update immediately, with no warning and no postponing",
		"at": "disconnect, update and reconnect at " + text}[b.When]
	s.audit(ctx, current(r).Username, "updates.push", b.Target, fmt.Sprintf("%s to %d PCs (version %s)", what, sent, latest))
	writeJSON(w, http.StatusOK, map[string]int{"sent": sent, "skipped": skipped})
}

// parseDiag reads a session's stored diagnostics report (nil if none).
func parseDiag(raw string) *clientapi.Diagnostics {
	if raw == "" {
		return nil
	}
	var d clientapi.Diagnostics
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return nil
	}
	return &d
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
