package admin

import (
	"context"
	"net/http"
	"strings"
	"time"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/duo"
	"securetunnel/server/internal/model"
)

// ---- groups and policies ----

type policiesView struct {
	model.PolicySet
	Migrated bool `json:"migrated"` // still the automatic conversion from policy groups
	DuoReady bool `json:"duo_ready"`
	CAsReady bool `json:"cas_ready"`
	// Devices that each device group matches right now (by name and platform).
	DeviceCounts map[string]int `json:"device_counts"`
}

func (s *Server) policiesView(ctx context.Context, ps model.PolicySet) policiesView {
	v := policiesView{PolicySet: ps, Migrated: s.Groups.Migrated(ctx), DeviceCounts: map[string]int{}}
	if s.Duo != nil {
		v.DuoReady = s.Duo.Settings(ctx).Ready()
	}
	if s.Trust != nil {
		cas, _ := model.ParseCAs(s.Trust.Policy(ctx).TrustedCAs)
		v.CAsReady = len(cas) > 0
	}
	if devs, err := s.Store.ListDevices(ctx, ""); err == nil {
		for _, g := range ps.Groups {
			if len(g.Platforms) == 0 && len(g.NamePatterns) == 0 && g.ID != model.GroupAllDevices {
				continue
			}
			for _, d := range devs {
				if model.DeviceInGroup(g, d.Platform, d.Name) {
					v.DeviceCounts[g.ID]++
				}
			}
		}
	}
	return v
}

func (s *Server) getPolicies(w http.ResponseWriter, r *http.Request) {
	if s.Groups == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	writeJSON(w, http.StatusOK, s.policiesView(r.Context(), s.Groups.Set(r.Context())))
}

func (s *Server) setPolicies(w http.ResponseWriter, r *http.Request) {
	if s.Groups == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	var body model.PolicySet
	if !readJSON(w, r, &body) {
		return
	}
	ps, err := s.Groups.Save(r.Context(), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var gs, pols []string
	for _, g := range ps.Groups {
		if !g.BuiltIn {
			gs = append(gs, g.Name)
		}
	}
	for _, p := range ps.Policies {
		pols = append(pols, p.Type+":"+p.Name)
	}
	s.audit(r.Context(), current(r).Username, "settings.policies", "",
		"groups: "+strings.Join(gs, ", ")+" · policies: "+strings.Join(pols, " > "))
	writeJSON(w, http.StatusOK, s.policiesView(r.Context(), ps))
}

// explainPolicies is GET /admin/api/policies/explain?user=…&platform=…&device=…:
// which policy of each type applies, and through which group.
func (s *Server) explainPolicies(w http.ResponseWriter, r *http.Request) {
	if s.Groups == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, s.Groups.Explain(r.Context(), q.Get("user"), q.Get("platform"), q.Get("device")))
}

// searchEntraGroups finds Entra security groups for the group picker.
func (s *Server) searchEntraGroups(w http.ResponseWriter, r *http.Request) {
	if s.Trust == nil || s.Trust.Graph == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := s.Trust.Graph.SearchGroups(ctx, r.URL.Query().Get("q"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "graph", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// ---- Duo ----

type duoView struct {
	APIHost        string `json:"api_host"`
	IntegrationKey string `json:"integration_key"`
	HasSecret      bool   `json:"has_secret"`
	UsernameFormat string `json:"username_format"`
	Ready          bool   `json:"ready"`
}

func viewDuo(d duo.Settings) duoView {
	return duoView{APIHost: d.APIHost, IntegrationKey: d.IntegrationKey, HasSecret: d.SecretKey != "",
		UsernameFormat: d.UsernameFormat, Ready: d.Ready()}
}

func (s *Server) getDuo(w http.ResponseWriter, r *http.Request) {
	if s.Duo == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	writeJSON(w, http.StatusOK, viewDuo(s.Duo.Settings(r.Context())))
}

func (s *Server) setDuo(w http.ResponseWriter, r *http.Request) {
	if s.Duo == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	var body duo.Settings
	if !readJSON(w, r, &body) {
		return
	}
	secretChanged := body.SecretKey != ""
	saved, err := s.Duo.Save(r.Context(), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	detail := "host=" + saved.APIHost + " ikey=" + saved.IntegrationKey + " username=" + saved.UsernameFormat
	if secretChanged {
		detail += " secret=changed"
	}
	s.audit(r.Context(), current(r).Username, "settings.duo", "", detail)
	writeJSON(w, http.StatusOK, viewDuo(saved))
}

func (s *Server) testDuo(w http.ResponseWriter, r *http.Request) {
	if s.Duo == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.Duo.Check(ctx); err != nil {
		writeErr(w, http.StatusBadGateway, "duo", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- backup server addresses ----

type serversView struct {
	Primary string   `json:"primary"`
	Backups []string `json:"backups"`
}

func (s *Server) serversView(r *http.Request) serversView {
	v := serversView{Primary: strings.TrimRight(s.PublicURL, "/"), Backups: []string{}}
	if v.Primary == "" {
		v.Primary = "https://" + r.Host
	}
	_, _ = s.Store.GetSetting(r.Context(), "backup_servers", &v.Backups)
	if v.Backups == nil {
		v.Backups = []string{}
	}
	return v
}

func (s *Server) getServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.serversView(r))
}

func (s *Server) setServers(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Backups []string `json:"backups"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	primary := s.serversView(r).Primary
	out := []string{}
	for _, b := range body.Backups {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		n, err := agentcfg.NormalizeServer(b)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", b+": "+err.Error())
			return
		}
		if n == primary {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o == n
		}
		if !dup {
			out = append(out, n)
		}
	}
	if len(out) > 5 {
		writeErr(w, http.StatusBadRequest, "bad_request", "at most 5 backup addresses")
		return
	}
	if err := s.Store.SetSetting(r.Context(), "backup_servers", out); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.servers", "", "backups="+strings.Join(out, ","))
	writeJSON(w, http.StatusOK, s.serversView(r))
}
