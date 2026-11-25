package agentcore

import (
	"errors"
	"time"

	"securetunnel/server/internal/clientapi"
)

// controlReachability describes recent control replies for the UI. It has no
// effect on tunnel state, retries or failover. The engine's mu protects it.
type controlReachability struct {
	checkedAt time.Time
	confirmed bool
	misses    int
}

const controlMissLimit = 2

func (e *Engine) staleControl(s *Session, now time.Time) bool {
	return e.control.checkedAt.IsZero() || now.Sub(e.control.checkedAt) > 2*e.heartbeatEvery(s)+10*time.Second
}

// observeControl records the outcome of a current session's control request.
// Caller holds mu.
func (e *Engine) observeControl(s *Session, generation uint64, now time.Time, err error) {
	if e.sess != s || s.Device || e.apiGeneration != generation {
		return
	}
	if e.staleControl(s, now) {
		e.control = controlReachability{}
	}
	e.control.checkedAt = now.Round(0) // include time spent asleep in freshness checks
	var reply *clientapi.APIError
	if err == nil || errors.As(err, &reply) && reply.Code != "" {
		e.control.confirmed = true
		e.control.misses = 0
	} else {
		e.control.misses = min(e.control.misses+1, controlMissLimit)
	}
}

// controlStatus reports the UI state. Caller holds mu.
func (e *Engine) controlStatus(now time.Time) string {
	s := e.sess
	switch {
	case s == nil || s.Device || (e.state != StateConnected && e.state != StateReconnecting):
		return "checking"
	case e.staleControl(s, now):
		return "checking"
	case e.control.misses >= controlMissLimit:
		return "offline"
	case e.control.confirmed:
		return "online"
	default:
		return "checking"
	}
}
