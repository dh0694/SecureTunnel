package agentcore

import "testing"

func TestPingGraph(t *testing.T) {
	short := []int{5, -1, 7}
	if g := pingGraph(short); len(g) != 3 || g[1] != -1 {
		t.Fatalf("short history should pass through: %v", g)
	}
	// 360 pings (30 min at 5 s) → 60 points of 6 pings each.
	h := make([]int, 360)
	for i := range h {
		h[i] = 10
	}
	for i := 0; i < 6; i++ {
		h[i] = -1 // first bucket: every ping lost
	}
	h[6] = 40 // second bucket averages (40 + 5×10) / 6 = 15
	g := pingGraph(h)
	if len(g) != histLen || g[0] != -1 || g[1] != 15 || g[59] != 10 {
		t.Fatalf("graph: len %d, %v", len(g), g[:3])
	}
	// An uneven count drops the oldest partial bucket.
	if g := pingGraph(h[:200]); len(g) != 50 {
		t.Fatalf("200 pings → %d points, want 50 of 4", len(g))
	}
}
