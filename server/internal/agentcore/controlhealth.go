package agentcore

import (
	"context"
	"time"
)

const (
	controlHealthEvery   = 30 * time.Second
	controlHealthTimeout = 4 * time.Second
)

// controlHealth holds UI-only measurements, separate from the heartbeats
// that keep the session alive. The engine's mu protects its fields.
type controlHealth struct {
	session       *Session
	apiGeneration uint64
	host          string
	history       []LatencySample
	wake          chan struct{}
}

func (h *controlHealth) poke() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// syncControlHealthSession runs with mu held when the connection state changes.
func (e *Engine) syncControlHealthSession() {
	var s *Session
	if e.sess != nil && !e.sess.Device && (e.state == StateConnected || e.state == StateReconnecting) {
		s = e.sess
	}
	h := &e.controlHealth
	if h.session == s {
		return
	}
	h.session, h.host, h.history = s, "", nil
	if s != nil {
		h.poke()
	}
}

// activeServer returns the current control address with mu held.
func (e *Engine) activeServer() string {
	if api, ok := e.api.(interface{ Active() string }); ok {
		if host := api.Active(); host != "" {
			return host
		}
	}
	return e.server
}

func (e *Engine) controlHealthLoop(ctx context.Context) {
	ticker := time.NewTicker(controlHealthEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.controlHealth.wake:
			ticker.Reset(controlHealthEvery)
		}
		e.sampleControlHealth(ctx)
	}
}

func (e *Engine) sampleControlHealth(ctx context.Context) {
	e.mu.Lock()
	h := &e.controlHealth
	probe, ok := e.api.(interface{ ProbeHealth(context.Context) error })
	s, generation, host := h.session, h.apiGeneration, e.activeServer()
	e.mu.Unlock()
	if !ok || s == nil || ctx.Err() != nil {
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, controlHealthTimeout)
	start := time.Now()
	err := probe.ProbeHealth(probeCtx)
	ms := -1
	if err == nil && probeCtx.Err() == nil {
		ms = max(1, int(time.Since(start)/time.Millisecond))
	}
	cancel()

	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.sess != s || h.session != s || h.apiGeneration != generation || e.activeServer() != host {
		return
	}
	h.host = host
	h.history = append(h.history, LatencySample{At: e.o.Now(), MS: ms})
	if len(h.history) > histLen {
		h.history = h.history[len(h.history)-histLen:]
	}
}

func (h *controlHealth) status(st *Status, now, cutoff time.Time) {
	first := len(h.history)
	for first > 0 && h.history[first-1].At.After(cutoff) {
		first--
	}
	st.ControlLatencyHistory = append([]LatencySample{}, h.history[first:]...)
	if len(st.ControlLatencyHistory) == 0 || h.host != st.ServerInUse {
		return
	}
	latest := h.history[len(h.history)-1]
	if now.Sub(latest.At) <= 2*controlHealthEvery && latest.MS > 0 {
		st.ControlHealthMs = latest.MS
	}
}
