package hostmetrics

import (
	"runtime"
	"testing"
	"time"

	"securetunnel/server/internal/model"
)

func TestHistoryKeepsNewest(t *testing.T) {
	h := NewHistory(3)
	for i := 1; i <= 5; i++ {
		h.Add("k", model.HostMetrics{CPUPercent: float64(i)})
	}
	got := h.Get("k")
	if len(got) != 3 || got[0].CPUPercent != 3 || got[2].CPUPercent != 5 {
		t.Fatalf("history = %+v, want samples 3,4,5", got)
	}
	if m, ok := h.Latest("k"); !ok || m.CPUPercent != 5 {
		t.Errorf("latest = %+v, %v", m, ok)
	}
	if _, ok := h.Latest("missing"); ok {
		t.Error("latest of missing key reported ok")
	}
}

func TestSampleOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	s := &Sampler{}
	s.Sample()
	time.Sleep(50 * time.Millisecond)
	m := s.Sample()
	if m.MemTotal == 0 || m.MemUsed > m.MemTotal {
		t.Errorf("memory = %d used of %d", m.MemUsed, m.MemTotal)
	}
	if m.DiskTotal == 0 || m.DiskUsed > m.DiskTotal {
		t.Errorf("disk = %d used of %d", m.DiskUsed, m.DiskTotal)
	}
	if m.CPUPercent < 0 || m.CPUPercent > 100 {
		t.Errorf("cpu = %v", m.CPUPercent)
	}
}
