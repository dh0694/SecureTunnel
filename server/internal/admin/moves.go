package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"securetunnel/server/internal/session"
	"securetunnel/server/internal/store"
)

// moveSession asks one connected agent to switch gateways.
func (s *Server) moveSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"` // gateway ID, or "" for the best other gateway
	}
	if !readJSON(w, r, &body) {
		return
	}
	err := s.Sessions.RequestMove(r.Context(), r.PathValue("id"), current(r).Username, strings.TrimSpace(body.Target))
	switch {
	case errors.Is(err, session.ErrReauthRequired), errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "that session has ended")
	case errors.Is(err, session.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), session.ErrBadRequest.Error()+": "))
	case err != nil:
		s.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// drainGateway stops new sessions on a gateway and asks every connected agent
// on it to move to another gateway. Sessions from clients that can't move
// (the stclient test tool) stay until they reconnect.
func (s *Server) drainGateway(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	gws, err := s.Store.ListGateways(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	others := 0
	found := false
	for _, g := range gws {
		if g.ID == id {
			found = true
		} else if g.Enabled {
			others++
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "no such gateway")
		return
	}
	if others == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "there's no other enabled gateway to move people to")
		return
	}
	if err := s.Store.SetGatewayEnabled(ctx, id, false); err != nil {
		s.internal(w, err)
		return
	}
	live, err := s.Store.LivePeers(ctx, id)
	if err != nil {
		s.internal(w, err)
		return
	}
	moved, skipped, failed := 0, 0, 0
	for _, se := range live {
		if se.ClientVersion == "" { // not the SecureTunnel agent; can't take commands
			skipped++
			continue
		}
		if err := s.Sessions.RequestMove(ctx, se.ID, current(r).Username, ""); err != nil {
			s.Log.Warn("queue gateway drain move", "gateway", id, "session", se.ID, "err", err)
			failed++
			continue
		}
		moved++
	}
	s.audit(ctx, current(r).Username, "gateway.drain", id, fmt.Sprintf("queued %d moves, %d unsupported, %d queue failures", moved, skipped, failed))
	writeJSON(w, http.StatusOK, map[string]int{"moving": moved, "cannot_move": skipped, "failed": failed})
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListLogUploads(r.Context(), r.URL.Query().Get("device"), 100)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) downloadLogs(w http.ResponseWriter, r *http.Request) {
	l, err := s.Store.GetLogUpload(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such upload")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	name := strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			return c
		}
		return '-'
	}, l.DeviceName)
	s.audit(r.Context(), current(r).Username, "device.logs_download", l.DeviceID, "downloaded logs "+l.Ref)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="securetunnel-logs-%s-%s-%s.zip"`, name, l.At.UTC().Format("20060102-1504"), l.Ref))
	_, _ = w.Write(l.Data)
}
