// Package lbstats reads HAProxy's CSV stats page so the admin site can show
// which control server the load balancer is sending traffic to.
package lbstats

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server is one backend server as HAProxy sees it.
type Server struct {
	Name        string `json:"name"`
	Backup      bool   `json:"backup"`       // standby: used only when no active server is up
	Status      string `json:"status"`       // UP, DOWN, MAINT, "UP 1/2" ...
	Check       string `json:"check"`        // last health check, e.g. L7OK / L4CON
	CheckMs     int    `json:"check_ms"`     // how long the last check took
	Current     int    `json:"current"`      // open connections now
	Total       int64  `json:"total"`        // connections since HAProxy started
	ChecksFail  int64  `json:"checks_failed"`
	DownSec     int64  `json:"down_sec"`     // total time spent down
	ChangedSec  int64  `json:"changed_sec"`  // seconds since the status last changed
	Serving     bool   `json:"serving"`      // receiving new connections right now
}

// Status is the load balancer as a whole.
type Status struct {
	Frontend string   `json:"frontend"`
	Current  int      `json:"current"` // open connections on the frontend
	Total    int64    `json:"total"`
	Rate     int      `json:"rate"`     // new connections in the last second
	Servers  []Server `json:"servers"`
	UptimeSec int64   `json:"uptime_sec,omitempty"`
}

// Fetch reads url (HAProxy's "stats uri" with ";csv") and summarises the
// first backend and frontend.
func Fetch(ctx context.Context, url string) (*Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("haproxy stats: %s", resp.Status)
	}
	return Parse(resp.Body)
}

// Parse reads HAProxy's stats CSV.
func Parse(r io.Reader) (*Status, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("haproxy stats: empty")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimPrefix(strings.TrimSpace(h), "# ")] = i
	}
	get := func(r []string, k string) string {
		if i, ok := col[k]; ok && i < len(r) {
			return r[i]
		}
		return ""
	}
	num := func(r []string, k string) int64 { n, _ := strconv.ParseInt(get(r, k), 10, 64); return n }

	st := &Status{}
	var backend string
	for _, r := range rows[1:] {
		px, sv := get(r, "pxname"), get(r, "svname")
		switch {
		case sv == "FRONTEND" && px != "stats" && st.Frontend == "":
			st.Frontend = px
			st.Current, st.Total, st.Rate = int(num(r, "scur")), num(r, "stot"), int(num(r, "rate"))
		case sv == "BACKEND" || sv == "FRONTEND" || px == "stats":
		default:
			if backend == "" {
				backend = px
			}
			if px != backend {
				continue
			}
			st.Servers = append(st.Servers, Server{
				Name: sv, Backup: get(r, "bck") == "1", Status: get(r, "status"),
				Check: get(r, "check_status"), CheckMs: int(num(r, "check_duration")),
				Current: int(num(r, "scur")), Total: num(r, "stot"),
				ChecksFail: num(r, "chkfail"), DownSec: num(r, "downtime"), ChangedSec: num(r, "lastchg"),
			})
		}
	}
	// HAProxy sends new connections to active servers that are up, and to a
	// backup only when no active server is up.
	activeUp := false
	for _, s := range st.Servers {
		if !s.Backup && isUp(s.Status) {
			activeUp = true
		}
	}
	for i := range st.Servers {
		s := &st.Servers[i]
		s.Serving = isUp(s.Status) && (!s.Backup || !activeUp)
	}
	return st, nil
}

// isUp covers "UP" and the transitional "UP 1/2" (one check failed so far).
func isUp(status string) bool { return strings.HasPrefix(status, "UP") }
