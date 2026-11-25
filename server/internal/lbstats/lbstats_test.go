package lbstats

import (
	"strings"
	"testing"
)

const sample = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,
control,FRONTEND,,,3,9,,120,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,2,0,,,,0,2,0,5,,,,
controls,control-a,0,0,3,8,,100,0,0,,0,,0,0,0,0,DOWN,1,1,0,4,1,12,12,,1,3,1,,100,,2,0,,4,L4CON,,1,
controls,control-b,0,0,0,2,,20,0,0,,0,,0,0,0,0,UP,1,0,1,0,0,500,0,,1,3,2,,20,,2,0,,2,L7OK,200,3,
controls,BACKEND,0,0,3,9,,120,0,0,0,0,,0,0,0,0,UP,1,1,1,,0,500,0,,1,3,0,,120,,1,0,,5,,,,
stats,FRONTEND,,,1,1,,5,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,4,0,,,,0,1,0,1,,,,
`

func TestParseFailover(t *testing.T) {
	st, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if st.Frontend != "control" || st.Current != 3 || st.Total != 120 {
		t.Fatalf("frontend: %+v", st)
	}
	if len(st.Servers) != 2 {
		t.Fatalf("servers: %+v", st.Servers)
	}
	a, b := st.Servers[0], st.Servers[1]
	if a.Serving || a.Backup || a.Check != "L4CON" || a.ChecksFail != 4 {
		t.Fatalf("control-a: %+v", a)
	}
	if !b.Serving || !b.Backup || b.CheckMs != 3 {
		t.Fatalf("control-b should be serving as the backup: %+v", b)
	}
}

func TestParseNormal(t *testing.T) {
	st, err := Parse(strings.NewReader(strings.Replace(sample, "DOWN,1,1,0,4", "UP,1,1,0,4", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Servers[0].Serving || st.Servers[1].Serving {
		t.Fatalf("control-a should serve, backup stand by: %+v", st.Servers)
	}
}
