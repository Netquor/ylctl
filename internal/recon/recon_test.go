package recon

import (
	"net/netip"
	"strings"
	"testing"
)

func pf(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestParseSubnets(t *testing.T) {
	guess := []netip.Prefix{pf("192.168.0.77/24")}
	cases := []struct {
		in   string
		want string
	}{
		{"", "192.168.0.0/24"},
		{"  ", "192.168.0.0/24"},
		{"/23", "192.168.0.0/23"},
		{"10.1.2.0/24", "10.1.2.0/24"},
		{"10.1.2.9", "10.1.2.0/24"},
		{"10.1.2.0/24, 10.1.3.0/24 192.168.9.0/24", "10.1.2.0/24, 10.1.3.0/24, 192.168.9.0/24"},
		{"10.1.2.0/24 10.1.2.77", "10.1.2.0/24"},
		{"/22 172.16.0.0/16", "192.168.0.0/22, 172.16.0.0/16"},
	}
	for _, c := range cases {
		got, err := ParseSubnets(guess, c.in)
		if err != nil || Describe(got) != c.want {
			t.Errorf("%q -> %q %v, want %q", c.in, Describe(got), err, c.want)
		}
	}
	for _, bad := range []string{"/7", "/31", "/x", "nope", "10.0.0.0/33", "::1", "1.2.3"} {
		if _, err := ParseSubnets(guess, bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, err := ParseSubnets(nil, "/24"); err == nil {
		t.Error("a bare mask needs a guess")
	}
}

func TestParseARP(t *testing.T) {
	mac := `? (10.20.30.204) at 80:5e:c0:00:00:0a on en0 ifscope [ethernet]
? (192.168.0.5) at 0:1c:42:2:3:4 on en0 ifscope [ethernet]
? (192.168.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.0.9) at (incomplete) on en0 ifscope [ethernet]`
	m := ParseARP(mac)
	if m["10.20.30.204"] != "805ec000000a" || m["192.168.0.5"] != "001c42020304" || len(m) != 2 {
		t.Fatalf("%v", m)
	}
	lin := "10.20.30.211 dev eth0 lladdr 80:5e:c0:00:00:0b REACHABLE\n10.20.30.3 dev eth0  FAILED\n"
	if m := ParseARP(lin); m["10.20.30.211"] != "805ec000000b" || len(m) != 1 {
		t.Fatalf("%v", m)
	}
}

func TestNormMACAndColon(t *testing.T) {
	for in, want := range map[string]string{"80:5E:C0:00:00:0A": "805ec000000a", "80-5e-c0-00-00-0a": "805ec000000a", "805ec000000a": "805ec000000a", "xyz": "", "1:2:3": ""} {
		if got := NormMAC(in); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if Colon("805ec000000a") != "80:5e:c0:00:00:0a" {
		t.Error("colon")
	}
}

func TestPicker(t *testing.T) {
	p := NewPicker([]string{"a", "b", "c"}, 1)
	for _, k := range [][]byte{{27, '[', 'B'}, {' '}, {'j'}, {' '}, {27, '[', 'A'}, {'k'}} {
		p.Key(k)
	}
	// start cursor 0; down->1 toggle (was selected) off; j->2 toggle on; up->1; k->0
	if got := p.Chosen(); len(got) != 1 || got[0] != 2 || p.Cursor != 0 {
		t.Fatalf("%v cursor %d", got, p.Cursor)
	}
	p.Key([]byte{'a'})
	if len(p.Chosen()) != 3 {
		t.Error("a selects all")
	}
	p.Key([]byte{'n'})
	if len(p.Chosen()) != 0 {
		t.Error("n selects none")
	}
	p.Key([]byte{'\r'})
	if !p.Done || p.Canceled {
		t.Error("enter confirms")
	}
	q := NewPicker([]string{"a"})
	q.Key([]byte{'q'})
	if !q.Canceled || !q.Done {
		t.Error("q cancels")
	}
	empty := NewPicker(nil)
	empty.Key([]byte{'j'}) // must not panic or divide by zero
	if !strings.Contains(NewPicker([]string{"x"}, 0).Render("T", func(_, s string) string { return s }), "[x]") {
		t.Error("render shows the selection")
	}
}

func TestGuidesAndSettings(t *testing.T) {
	if g := GuideFor("YEALINK"); g.Vendor != "Yealink" || len(g.Steps) < 3 {
		t.Errorf("%+v", g)
	}
	if g := GuideFor("Acme"); len(g.Steps) != 1 {
		t.Errorf("%+v", g)
	}
	dir := t.TempDir()
	if s := Load(dir); s.TFTPOnNetwork != nil {
		t.Error("empty")
	}
	yes := true
	if err := Save(dir, Settings{TFTPOnNetwork: &yes, Subnets: []string{"10.0.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if s := Load(dir); s.TFTPOnNetwork == nil || !*s.TFTPOnNetwork || s.Subnets[0] != "10.0.0.0/24" {
		t.Errorf("%+v", s)
	}
}

func TestZeroTouchStates(t *testing.T) {
	var s Settings
	if s.ZeroTouch() != ZTUnknown {
		t.Error("unknown by default")
	}
	for _, z := range []ZeroTouch{ZTDHCPURL, ZTTFTP, ZTNone} {
		s.SetZeroTouch(z)
		if s.ZeroTouch() != z {
			t.Errorf("round trip %v", z)
		}
	}
	yes := true
	old := Settings{TFTPOnNetwork: &yes} // saved by an earlier version
	if old.ZeroTouch() != ZTTFTP {
		t.Error("an older tftp-only setting still means TFTP")
	}
	dir := t.TempDir()
	s.SetZeroTouch(ZTDHCPURL)
	if err := Save(dir, s); err != nil || Load(dir).ZeroTouch() != ZTDHCPURL {
		t.Error("saved mode survives a reload")
	}
}
