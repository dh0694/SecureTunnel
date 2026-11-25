package api

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

// Log uploads: the agent zips its log, the connection checks and the
// network settings, and posts them here, connected or not. With a live
// session's credentials the upload is tied to the user; without, it's only
// accepted for a device the server already knows, at most once a minute.

const maxLogUpload = 3 << 20

var (
	logRateMu sync.Mutex
	logRate   = map[string]time.Time{}
)

func logRef() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:3]) + "-" + string(b[3:])
}

func (s *Server) uploadLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	deviceID := strings.TrimSpace(r.Header.Get("X-ST-Device"))
	if deviceID == "" || len(deviceID) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing device")
		return
	}
	reason := r.Header.Get("X-ST-Reason")
	if reason != "admin" {
		reason = "user"
	}

	// Who sent it: a live session (verified) or just a known device.
	up := model.LogUpload{DeviceID: deviceID, Reason: reason}
	if sid := r.Header.Get("X-ST-Session"); sid != "" {
		if tok, ok := bearer(r); ok {
			if se, err := s.Sessions.CheckSession(ctx, sid, tok); err == nil && se.DeviceID == deviceID {
				up.UPN, up.Verified, up.DeviceName = se.UPN, true, se.DeviceName
			}
		}
	}
	if !up.Verified {
		devs, err := s.Store.ListDevices(ctx, "")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		known := false
		for _, d := range devs {
			if d.ID == deviceID {
				known, up.DeviceName, up.UPN = true, d.Name, d.LastUser
				break
			}
		}
		if !known {
			writeErr(w, http.StatusForbidden, "unknown_device", "This device hasn't connected to the VPN before, so its logs can't be sent. Contact IT.")
			return
		}
	}
	logRateMu.Lock()
	if last, ok := logRate[deviceID]; ok && time.Since(last) < time.Minute {
		logRateMu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too_soon", "Logs were just sent. Try again in a minute.")
		return
	}
	logRate[deviceID] = time.Now()
	if len(logRate) > 10000 {
		logRate = map[string]time.Time{}
	}
	logRateMu.Unlock()

	data, err := io.ReadAll(io.LimitReader(r.Body, maxLogUpload+1))
	if err != nil || len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "empty upload")
		return
	}
	if len(data) > maxLogUpload {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "The logs are too large to send (3 MB limit).")
		return
	}
	if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "logs must be a zip file")
		return
	}
	up.ID = newLogID()
	up.At = s.now()
	up.Ref = logRef()
	up.Size = len(data)
	up.Data = data
	if err := s.Store.AddLogUpload(ctx, up); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "unknown device")
			return
		}
		s.Log.Error("store log upload", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	actor := up.UPN
	if actor == "" {
		actor = "device " + up.DeviceName
	}
	who := "sent by the user"
	if reason == "admin" {
		who = "collected by IT"
	}
	_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: strings.ToLower(actor), Action: "device.logs",
		Target: deviceID, Detail: "logs from " + up.DeviceName + " (" + who + "), reference " + up.Ref})
	writeJSON(w, http.StatusCreated, map[string]string{"ref": up.Ref, "id": up.ID})
}

func newLogID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 24)
	for i, v := range b {
		out[i*2], out[i*2+1] = hexd[v>>4], hexd[v&15]
	}
	return string(out)
}
