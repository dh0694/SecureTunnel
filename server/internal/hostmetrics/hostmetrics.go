// Package hostmetrics samples CPU, memory, disk, load and uptime from Linux
// /proc and statfs, and keeps a short in-memory history for the admin site.
//
// Inside a container /proc/stat, /proc/meminfo and /proc/loadavg describe the
// host, which is what we want to show. On non-Linux systems the values are zero.
package hostmetrics

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/model"
)

// Sampler takes samples. CPU percent is computed between consecutive calls, so
// the first sample reports 0.
type Sampler struct {
	DiskPath string // filesystem to report, default "/"
	Label    string // hostname override, default os.Hostname()

	mu        sync.Mutex
	prevIdle  uint64
	prevTotal uint64
	have      bool
}

// Sample returns the current metrics.
func (s *Sampler) Sample() model.HostMetrics {
	m := model.HostMetrics{At: time.Now().UTC(), CPUCores: runtime.NumCPU(), Hostname: s.Label}
	if m.Hostname == "" {
		m.Hostname, _ = os.Hostname()
	}
	m.CPUPercent = s.cpu()
	m.MemTotal, m.MemUsed = memory()
	m.Load1, m.Load5, m.Load15 = load()
	m.UptimeSec = uptime()
	path := s.DiskPath
	if path == "" {
		path = "/"
	}
	m.DiskTotal, m.DiskUsed = disk(path)
	return m
}

func (s *Sampler) cpu() float64 {
	idle, total, ok := readCPU()
	if !ok {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var pct float64
	if s.have && total > s.prevTotal {
		dTotal := float64(total - s.prevTotal)
		dIdle := float64(idle - s.prevIdle)
		pct = (1 - dIdle/dTotal) * 100
		if pct < 0 {
			pct = 0
		}
	}
	s.prevIdle, s.prevTotal, s.have = idle, total, true
	return round1(pct)
}

// readCPU returns idle (idle+iowait) and total jiffies from the first line of /proc/stat.
func readCPU() (idle, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, v := range fields[1:] {
		if i >= 8 { // user nice system idle iowait irq softirq steal; guest is already in user
			break
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return idle, total, true
}

func memory() (total, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var avail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = n * 1024
		case "MemAvailable:":
			avail = n * 1024
		}
	}
	if avail > total {
		avail = total
	}
	return total, total - avail
}

func load() (l1, l5, l15 float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

func uptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// History keeps the most recent samples per key (e.g. "control", "gw:dc-pair").
// It is per control-server process and not persisted.
type History struct {
	mu  sync.Mutex
	max int
	m   map[string][]model.HostMetrics
}

// NewHistory keeps up to max samples per key.
func NewHistory(max int) *History {
	return &History{max: max, m: map[string][]model.HostMetrics{}}
}

// Add appends a sample.
func (h *History) Add(key string, s model.HostMetrics) {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := append(h.m[key], s)
	if len(l) > h.max {
		l = l[len(l)-h.max:]
	}
	h.m[key] = l
}

// Get returns a copy of the samples for key, oldest first.
func (h *History) Get(key string) []model.HostMetrics {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]model.HostMetrics(nil), h.m[key]...)
}

// Latest returns the newest sample for key.
func (h *History) Latest(key string) (model.HostMetrics, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.m[key]
	if len(l) == 0 {
		return model.HostMetrics{}, false
	}
	return l[len(l)-1], true
}
