package clientapi

import (
	"testing"
	"time"
)

func TestInWindow(t *testing.T) {
	at := func(day time.Weekday, hhmm string) time.Time {
		// 2026-11-22 is a Sunday.
		base := time.Date(2026, 11, 22, 0, 0, 0, 0, time.Local).AddDate(0, 0, int(day))
		h, _ := time.Parse("15:04", hhmm)
		return base.Add(time.Duration(h.Hour())*time.Hour + time.Duration(h.Minute())*time.Minute)
	}
	weeknights := UpdatePolicy{WindowDays: []int{1, 2, 3, 4, 5}, WindowStart: "01:00", WindowEnd: "05:00"}
	cases := []struct {
		p    UpdatePolicy
		t    time.Time
		want bool
	}{
		{weeknights, at(time.Monday, "01:00"), true},
		{weeknights, at(time.Monday, "04:59"), true},
		{weeknights, at(time.Monday, "05:00"), false},
		{weeknights, at(time.Monday, "00:59"), false},
		{weeknights, at(time.Saturday, "02:00"), false},
		// Past midnight: Friday 22:00 to Saturday 02:00 belongs to Friday.
		{UpdatePolicy{WindowDays: []int{5}, WindowStart: "22:00", WindowEnd: "02:00"}, at(time.Friday, "23:30"), true},
		{UpdatePolicy{WindowDays: []int{5}, WindowStart: "22:00", WindowEnd: "02:00"}, at(time.Saturday, "01:30"), true},
		{UpdatePolicy{WindowDays: []int{5}, WindowStart: "22:00", WindowEnd: "02:00"}, at(time.Friday, "01:30"), false},
		{UpdatePolicy{WindowDays: []int{1}, WindowStart: "bad", WindowEnd: "02:00"}, at(time.Monday, "01:00"), false},
	}
	for i, c := range cases {
		if got := c.p.InWindow(c.t); got != c.want {
			t.Errorf("case %d (%s): got %v, want %v", i, c.t.Format("Mon 15:04"), got, c.want)
		}
	}
}
