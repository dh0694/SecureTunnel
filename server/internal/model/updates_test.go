package model

import "testing"

func TestUpdatePolicyNormalize(t *testing.T) {
	var p UpdatePolicy
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.RolloutPercent != 100 || p.InstallWhen != InstallDisconnected || p.WindowStart != "01:00" {
		t.Fatalf("defaults not filled: %+v", p)
	}
	for _, bad := range []UpdatePolicy{
		{InstallWhen: "sometimes"},
		{RolloutPercent: 150},
		{WindowStart: "25:00"},
		{WindowStart: "02:00", WindowEnd: "02:00"},
		{InstallWhen: InstallWindow, WindowDays: []int{}},
		{WindowDays: []int{7}},
		{DeadlineDays: -1},
	} {
		b := bad
		if err := b.Normalize(); err == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

func TestInRollout(t *testing.T) {
	in := 0
	for i := 0; i < 1000; i++ {
		if InRollout(string(rune('a'+i%26))+string(rune(i)), "1.2.3", 25) {
			in++
		}
	}
	if in < 180 || in > 320 {
		t.Fatalf("25%% rollout picked %d of 1000", in)
	}
	if !InRollout("pc", "1.2.3", 100) || InRollout("pc", "1.2.3", 0) {
		t.Fatal("100% includes everyone, 0% nobody")
	}
	if InRollout("pc", "1.2.3", 37) != InRollout("pc", "1.2.3", 37) {
		t.Fatal("a PC must stay in or out for a release")
	}
}
