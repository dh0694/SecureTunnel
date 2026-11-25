package agentcore

import (
	"context"
	"testing"
	"time"
)

type fakeControlHealthAPI struct {
	*fakeAPI
	host  string
	probe func(context.Context) error
}

func (f *fakeControlHealthAPI) Active() string { return f.host }

func (f *fakeControlHealthAPI) ProbeHealth(ctx context.Context) error {
	if f.probe != nil {
		return f.probe(ctx)
	}
	return nil
}

func TestControlHealthDropsResultsAfterActiveHostChanges(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	health := &fakeControlHealthAPI{fakeAPI: r.api, host: r.e.server}
	r.e.api = health
	ctx := context.Background()
	r.e.sampleControlHealth(ctx)
	health.probe = func(context.Context) error {
		health.host = "https://backup.example.com"
		return nil
	}
	r.advance(controlHealthEvery)
	r.e.sampleControlHealth(ctx)
	if st := r.e.Status(); st.ControlHealthMs != 0 || len(st.ControlLatencyHistory) != 1 {
		t.Fatalf("old host populated the new host's status: %+v", st)
	}
	health.probe = nil
	r.e.sampleControlHealth(ctx)
	if st := r.e.Status(); st.ControlHealthMs <= 0 || len(st.ControlLatencyHistory) != 2 {
		t.Fatalf("expected the backup host's result: %+v", st)
	}
	r.advance(2*controlHealthEvery + time.Second)
	if st := r.e.Status(); st.ControlHealthMs != 0 || len(st.ControlLatencyHistory) != 2 {
		t.Fatalf("latest result should expire without clearing the chart: %+v", st)
	}
}

func TestControlHealthDropsResultsAfterSessionReplacement(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	health := &fakeControlHealthAPI{fakeAPI: r.api, host: r.e.server}
	r.e.api = health
	ctx := context.Background()
	r.e.sampleControlHealth(ctx)
	health.probe = func(context.Context) error {
		if err := r.e.Disconnect(ctx); err != nil {
			t.Fatal(err)
		}
		r.connect(t)
		return nil
	}
	r.e.sampleControlHealth(ctx)
	if st := r.e.Status(); st.State != StateConnected || st.ControlHealthMs != 0 || len(st.ControlLatencyHistory) != 0 {
		t.Fatalf("replacement session inherited old health measurements: %+v", st)
	}
}

func TestControlHealthProbeDoesNotBlockHeartbeat(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.advance(time.Minute)
	started, done := make(chan bool, 1), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	health := &fakeControlHealthAPI{fakeAPI: r.api, host: r.e.server}
	health.probe = func(probeCtx context.Context) error {
		deadline, bounded := probeCtx.Deadline()
		started <- bounded && time.Until(deadline) <= controlHealthTimeout
		<-probeCtx.Done()
		return probeCtx.Err()
	}
	r.e.api = health
	go func() {
		r.e.controlHealthLoop(ctx)
		close(done)
	}()
	select {
	case bounded := <-started:
		if !bounded {
			t.Fatal("health probe has no deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("health probe did not start")
	}
	heartbeat := make(chan struct{})
	go func() {
		r.e.Tick(ctx)
		close(heartbeat)
	}()
	select {
	case <-heartbeat:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was blocked by health probe")
	}
	cancel()
	<-done
	if st := r.e.Status(); st.ControlMs != 20 || len(st.ControlLatencyHistory) != 0 {
		t.Fatalf("expected a heartbeat reply and no sample for process cancellation: %+v", st)
	}
}
