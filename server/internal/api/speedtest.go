package api

import (
	"crypto/rand"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"securetunnel/server/internal/model"
)

// Speed tests through the VPN: the agent downloads and uploads data to these
// endpoints over the tunnel, then reports both these results and its
// internet (outside-the-tunnel) results to /speedtest/result.

const maxSpeedTestBytes = 100 << 20

// speedBlock is random data served repeatedly (random so nothing on the path
// can compress it and inflate the result).
var speedBlock = func() []byte {
	b := make([]byte, 256<<10)
	_, _ = rand.Read(b)
	return b
}()

func (s *Server) speedDown(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return
	}
	if _, err := s.Sessions.CheckSession(r.Context(), r.PathValue("id"), token); err != nil {
		s.sessionErr(w, err)
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
	if n < 0 || n > maxSpeedTestBytes {
		writeErr(w, http.StatusBadRequest, "bad_request", "bytes must be between 0 and 100 MB")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	for n > 0 {
		chunk := speedBlock
		if n < len(chunk) {
			chunk = chunk[:n]
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
		n -= len(chunk)
	}
}

func (s *Server) speedUp(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return
	}
	if _, err := s.Sessions.CheckSession(r.Context(), r.PathValue("id"), token); err != nil {
		s.sessionErr(w, err)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Minute))
	n, err := io.Copy(io.Discard, io.LimitReader(r.Body, maxSpeedTestBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "upload interrupted")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"received": n})
}

type speedResult struct {
	Kind      string    `json:"kind"`
	DownBps   float64   `json:"down_bps"`
	UpBps     float64   `json:"up_bps"`
	LatencyMs int       `json:"latency_ms"`
	Network   string    `json:"network"`
	Auto      bool      `json:"auto"`
	At        time.Time `json:"at"`
}

func (s *Server) speedReport(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return
	}
	sess, err := s.Sessions.CheckSession(r.Context(), r.PathValue("id"), token)
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	var body struct {
		Results []speedResult `json:"results"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	now := s.now()
	for i, res := range body.Results {
		if i >= 10 {
			break
		}
		if res.Kind != "internet" && res.Kind != "vpn" {
			continue
		}
		at := res.At
		if at.IsZero() || at.After(now) || now.Sub(at) > 7*24*time.Hour {
			at = now
		}
		net := strings.TrimSpace(res.Network)
		if len(net) > 100 {
			net = net[:100]
		}
		_ = s.Store.AddSpeedTest(r.Context(), model.SpeedTest{
			At: at, SessionID: sess.ID, UPN: sess.UPN, DeviceID: sess.DeviceID, Kind: res.Kind,
			DownBps: clampRate(res.DownBps), UpBps: clampRate(res.UpBps), LatencyMs: res.LatencyMs,
			Network: net, Auto: res.Auto,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func clampRate(v float64) float64 {
	if v < 0 || v != v {
		return 0
	}
	if v > 100e9 {
		return 100e9
	}
	return v
}
