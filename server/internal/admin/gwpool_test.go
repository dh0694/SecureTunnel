package admin

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

func TestCheckPool(t *testing.T) {
	gws := []model.Gateway{
		{ID: "a", Pool: netip.MustParsePrefix("10.200.0.0/21")},
		{ID: "b", Pool: netip.MustParsePrefix("10.200.8.0/21")},
	}
	bad := map[string]string{
		"nonsense":      "isn't a range",
		"10.200.1.0/21": "did you mean 10.200.0.0/21",
		"10.200.8.0/22": "overlaps b",
		"8.8.0.0/21":    "private range",
		"10.0.0.0/8":    "between /16",
		"fd00::/64":     "IPv4",
	}
	for in, want := range bad {
		if _, _, err := checkPool("a", in, gws, 1500, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", in, err, want)
		}
	}
	// Its own current range doesn't count as an overlap.
	if _, _, err := checkPool("a", "10.200.0.0/21", gws, 1500, nil); err != nil {
		t.Errorf("same range: %v", err)
	}
	// Smaller than capacity, and overlapping an office subnet: allowed with warnings.
	p, warn, err := checkPool("a", "10.201.0.0/24", gws, 1500, []string{"10.201.0.0/16"})
	if err != nil || p.String() != "10.201.0.0/24" || len(warn) != 2 {
		t.Errorf("got %v %v %v, want two warnings", p, warn, err)
	}
	if _, warn, _ := checkPool("a", "192.168.1.0/24", gws, 100, nil); len(warn) != 1 || !strings.Contains(warn[0], "home routers") {
		t.Errorf("home router range should warn: %v", warn)
	}
}

func TestGatewayPoolChangeProtectsLiveSessions(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := store.NewMemory()
	original := netip.MustParsePrefix("10.200.0.0/24")
	replacement := netip.MustParsePrefix("10.201.0.0/24")
	if err := st.UpsertGateway(ctx, model.Gateway{ID: "gw", Enabled: true, Pool: original}); err != nil {
		t.Fatal(err)
	}
	active := model.Session{ID: "session", DeviceID: "device", GatewayID: "gw", State: model.StateActive}
	if err := st.CreateSession(ctx, &active, original); err != nil {
		t.Fatal(err)
	}
	if count, err := st.SetGatewayPool(ctx, "gw", replacement, false, now); count != 1 || !errors.Is(err, store.ErrGatewayInUse) {
		t.Fatalf("unconfirmed pool change: count %d, error %v", count, err)
	}
	if count, err := st.SetGatewayPool(ctx, "gw", replacement, true, now); count != 1 || err != nil {
		t.Fatalf("confirmed pool change: count %d, error %v", count, err)
	}
	if peers, err := st.LivePeers(ctx, "gw"); len(peers) != 0 || err != nil {
		t.Fatalf("old peers after pool change: %v, error %v", peers, err)
	}
	stale := model.Session{ID: "stale", DeviceID: "device", GatewayID: "gw", State: model.StateActive}
	if err := st.CreateSession(ctx, &stale, original); !errors.Is(err, store.ErrGatewayUnavailable) {
		t.Fatalf("placement in an old range: %v", err)
	}
}
