package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/speedtest"
)

// SpeedSample is one result shown in the app.
type SpeedSample struct {
	DownBps   float64   `json:"down_bps"`
	UpBps     float64   `json:"up_bps"`
	LatencyMs int       `json:"latency_ms"`
	At        time.Time `json:"at"`
	Network   string    `json:"network"`
}

// SpeedInfo is the speed test state shown in the app.
type SpeedInfo struct {
	Running  bool         `json:"running"`
	Phase    string       `json:"phase,omitempty"`
	Internet *SpeedSample `json:"internet,omitempty"`
	VPN      *SpeedSample `json:"vpn,omitempty"`
	Error    string       `json:"error,omitempty"`
	Interval int          `json:"interval_hours"`
}

// speedTester runs speed tests on demand and on a schedule, and reports the
// results to the server.
//   - internet: to the speed-test host, outside the tunnel (via the tunnel
//     process when connected, directly when not)
//   - vpn: to the control server, through the tunnel (only when connected)
type speedTester struct {
	a *agentService

	mu       sync.Mutex
	running  bool
	phase    string
	internet *SpeedSample
	vpn      *SpeedSample
	errMsg   string
	lastAuto time.Time
	pending  []clientapi.SpeedReport
}

func (t *speedTester) info() SpeedInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return SpeedInfo{Running: t.running, Phase: t.phase, Internet: t.internet, VPN: t.vpn, Error: t.errMsg,
		Interval: t.policy().IntervalHours}
}

// policy comes from the server with each heartbeat; defaults until connected once.
func (t *speedTester) policy() (p struct {
	IntervalHours int
	SizeMB        int
	Host          string
}) {
	p.IntervalHours, p.SizeMB, p.Host = 24, 25, "speed.cloudflare.com"
	if s, ok := t.a.engine.CurrentSession(); ok && s.Placement.SpeedTest.Host != "" {
		p.IntervalHours, p.SizeMB, p.Host = s.Placement.SpeedTest.IntervalHours, s.Placement.SpeedTest.SizeMB, s.Placement.SpeedTest.Host
	}
	return p
}

func (t *speedTester) setPhase(p string) {
	t.mu.Lock()
	t.phase = p
	t.mu.Unlock()
}

// start begins a test in the background; false if one is already running.
func (t *speedTester) start(auto bool) bool {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return false
	}
	t.running, t.errMsg = true, ""
	t.mu.Unlock()
	go t.run(auto)
	return true
}

func (t *speedTester) run(auto bool) {
	defer func() {
		t.mu.Lock()
		t.running, t.phase = false, ""
		t.mu.Unlock()
	}()
	pol := t.policy()
	down := pol.SizeMB << 20
	up := down / 4
	if up < 1<<20 {
		up = 1 << 20
	}
	ni := cachedNetworkInfo()
	netLabel := strings.TrimSpace(ni.Kind + " " + ni.SSID)
	now := time.Now()
	var errs []string
	var reports []clientapi.SpeedReport

	// Internet speed, outside the tunnel.
	t.setPhase("internet")
	tun := &serviceTunnel{log: t.a.log}
	var res speedtest.Result
	var err error
	if tun.Running() {
		res, err = bypassCall(bypassRequest{Host: pol.Host, DownBytes: down, UpBytes: up})
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		res, err = speedtest.Run(ctx, &http.Client{Timeout: 3 * time.Minute}, speedtest.Cloudflare(pol.Host), down, up)
		cancel()
	}
	if err != nil {
		errs = append(errs, "Internet test: "+err.Error())
		t.a.log.Warn("internet speed test failed", "err", err)
	} else {
		s := &SpeedSample{DownBps: res.DownBps, UpBps: res.UpBps, LatencyMs: res.LatencyMs, At: now, Network: netLabel}
		t.mu.Lock()
		t.internet = s
		t.mu.Unlock()
		reports = append(reports, clientapi.SpeedReport{Kind: "internet", DownBps: res.DownBps, UpBps: res.UpBps, LatencyMs: res.LatencyMs, Network: netLabel, Auto: auto, At: now})
	}

	// VPN speed, through the tunnel to the control server.
	sess, connected := t.a.engine.CurrentSession()
	if connected && t.a.engine.Status().State == agentcore.StateConnected {
		t.setPhase("vpn")
		c := t.a.client(sess.Server)
		target := speedtest.Target{
			DownURL: func(n int) string { return fmt.Sprintf("%s/v1/sessions/%s/speedtest/down?bytes=%d", sess.Server, sess.ID, n) },
			UpURL:   sess.Server + "/v1/sessions/" + sess.ID + "/speedtest/up",
			Header:  http.Header{"Authorization": {"Bearer " + sess.ResumeToken}},
		}
		hc := *c.HTTP
		hc.Timeout = 3 * time.Minute
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		res, err := speedtest.Run(ctx, &hc, target, down, up)
		cancel()
		if err != nil {
			errs = append(errs, "VPN test: "+agentcore.Friendly(err))
			t.a.log.Warn("vpn speed test failed", "err", err)
		} else {
			s := &SpeedSample{DownBps: res.DownBps, UpBps: res.UpBps, LatencyMs: res.LatencyMs, At: now, Network: netLabel}
			t.mu.Lock()
			t.vpn = s
			t.mu.Unlock()
			reports = append(reports, clientapi.SpeedReport{Kind: "vpn", DownBps: res.DownBps, UpBps: res.UpBps, LatencyMs: res.LatencyMs, Network: netLabel, Auto: auto, At: now})
		}
	}

	t.mu.Lock()
	t.errMsg = strings.Join(errs, " ")
	t.pending = append(t.pending, reports...)
	if len(t.pending) > 10 {
		t.pending = t.pending[len(t.pending)-10:]
	}
	if auto {
		t.lastAuto = now
	}
	t.mu.Unlock()
	t.report()
	t.a.log.Info("speed test done", "auto", auto, "results", len(reports))
}

// report sends queued results when connected (results from while
// disconnected go up with the next session).
func (t *speedTester) report() {
	sess, ok := t.a.engine.CurrentSession()
	if !ok {
		return
	}
	t.mu.Lock()
	batch := append([]clientapi.SpeedReport(nil), t.pending...)
	t.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := t.a.client(sess.Server).ReportSpeed(ctx, sess.ID, sess.ResumeToken, batch); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.a.log.Warn("report speed results", "err", err)
		}
		return
	}
	t.mu.Lock()
	t.pending = t.pending[min(len(batch), len(t.pending)):]
	t.mu.Unlock()
}

// loop runs automatic tests (when idle) and sends queued results.
func (t *speedTester) loop(ctx context.Context) {
	t.mu.Lock()
	t.lastAuto = time.Now() // first automatic test one interval after start
	t.mu.Unlock()
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		t.report()
		pol := t.policy()
		if pol.IntervalHours <= 0 {
			continue
		}
		t.mu.Lock()
		due := time.Since(t.lastAuto) >= time.Duration(pol.IntervalHours)*time.Hour
		t.mu.Unlock()
		st := t.a.engine.Status()
		idle := st.RxBps+st.TxBps < 2e6 // don't compete with real work
		if due && idle {
			t.start(true)
		}
	}
}
