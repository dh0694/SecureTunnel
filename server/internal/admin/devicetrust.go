package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/model"
)

type caView struct {
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
}

type deviceTrustView struct {
	model.DeviceTrustPolicy
	CAs         []caView `json:"cas"`
	GraphStatus string   `json:"graph_status"` // "ok", "not_set_up" or "error"
	GraphError  string   `json:"graph_error,omitempty"`
}

var (
	graphProbeMu  sync.Mutex
	graphProbeAt  time.Time
	graphProbeErr error
)

// probeGraph checks Graph access at most once a minute (force skips the cache).
func (s *Server) probeGraph(ctx context.Context, force bool) error {
	graphProbeMu.Lock()
	defer graphProbeMu.Unlock()
	if !force && !graphProbeAt.IsZero() && time.Since(graphProbeAt) < time.Minute {
		return graphProbeErr
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	graphProbeErr = s.Trust.Graph.Probe(pctx)
	graphProbeAt = time.Now()
	return graphProbeErr
}

func (s *Server) deviceTrustView(ctx context.Context, p model.DeviceTrustPolicy, force bool) deviceTrustView {
	v := deviceTrustView{DeviceTrustPolicy: p, CAs: []caView{}}
	if cas, err := model.ParseCAs(p.TrustedCAs); err == nil {
		for _, ca := range cas {
			v.CAs = append(v.CAs, caView{Subject: ca.Subject.String(), NotAfter: ca.NotAfter})
		}
	}
	switch err := s.probeGraph(ctx, force); {
	case err == nil:
		v.GraphStatus = "ok"
	case errors.Is(err, devicetrust.ErrGraphNotSetUp):
		v.GraphStatus = "not_set_up"
	default:
		v.GraphStatus, v.GraphError = "error", err.Error()
	}
	return v
}

func (s *Server) getDeviceTrust(w http.ResponseWriter, r *http.Request) {
	if s.Trust == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	writeJSON(w, http.StatusOK, s.deviceTrustView(r.Context(), s.Trust.Policy(r.Context()), r.URL.Query().Get("recheck") == "1"))
}

func (s *Server) setDeviceTrust(w http.ResponseWriter, r *http.Request) {
	if s.Trust == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	var body model.DeviceTrustPolicy
	if !readJSON(w, r, &body) {
		return
	}
	// The certificate requirement now lives on policy groups; keep the saved
	// legacy value, which seeds the Default group until groups are saved.
	old := s.Trust.Policy(r.Context())
	body.CertMode = old.CertMode
	if _, err := model.ParseCAs(body.TrustedCAs); err == nil && body.CertMode != model.CertOff && strings.TrimSpace(body.TrustedCAs) == "" {
		body.CertMode = model.CertOff
	}
	p, err := s.Trust.SavePolicy(r.Context(), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.device_trust", "",
		"certs="+p.CertMode+
			" match_name="+boolStr(p.MatchDeviceName)+" match_user="+boolStr(p.MatchUser)+
			" device_names="+strings.Join(p.DeviceNamePatterns, ",")+" user_names="+strings.Join(p.UserNamePatterns, ","))
	writeJSON(w, http.StatusOK, s.deviceTrustView(r.Context(), p, true))
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
