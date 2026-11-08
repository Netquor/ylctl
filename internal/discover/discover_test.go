package discover

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netquor/ylctl/internal/yealink"
)

func TestParseRange(t *testing.T) {
	for _, tc := range []struct {
		in            string
		public, force bool
		ok            bool
	}{
		{"192.168.0.0/24", false, false, true},
		{"10.20.30.0/24", false, false, true},
		{"10.0.0.0/22", false, false, true},
		{"10.0.0.0/21", false, false, false},
		{"10.0.0.0/21", false, true, true},
		{"172.16.0.5", false, false, true},
		{"8.8.8.0/24", false, false, false},
		{"8.8.8.0/24", true, false, true},
		{"172.15.255.0/24", false, false, false},
		{"100.64.0.0/24", false, false, false}, // CGNAT is not private
		{"127.0.0.0/30", false, false, true},
		{"10.0.0.0/7", false, true, false}, // spans public space
		{"::1/128", false, false, false},
		{"garbage", false, false, false},
	} {
		_, err := ParseRange(tc.in, tc.public, tc.force)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: err=%v", tc, err)
		}
	}
}

func TestAddresses(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	a := Addresses(p)
	if len(a) != 254 || a[0].String() != "192.168.1.1" || a[253].String() != "192.168.1.254" || Size(p) != 254 {
		t.Fatalf("%d %v %v", len(a), a[0], a[len(a)-1])
	}
	if got := Addresses(netip.MustParsePrefix("10.0.0.7/32")); len(got) != 1 || got[0].String() != "10.0.0.7" {
		t.Fatalf("%v", got)
	}
	if got := Addresses(netip.MustParsePrefix("10.0.0.6/31")); len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if got := Addresses(netip.MustParsePrefix("255.255.255.255/32")); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

func TestScanFindsAndLimits(t *testing.T) {
	addrs := Addresses(netip.MustParsePrefix("10.1.0.0/26")) // 62 addresses
	var inflight, maxInflight int32
	var mu sync.Mutex
	probed := map[string]int{}
	probe := func(_ context.Context, ip string, _ []int, _ time.Duration) (*yealink.ProbeResult, error) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			m := atomic.LoadInt32(&maxInflight)
			if n <= m || atomic.CompareAndSwapInt32(&maxInflight, m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		mu.Lock()
		probed[ip]++
		mu.Unlock()
		if ip == "10.1.0.40" || ip == "10.1.0.5" {
			return &yealink.ProbeResult{IP: ip, Port: 443, Model: "T41S"}, nil
		}
		return nil, nil
	}
	start := time.Now()
	res, err := Scan(context.Background(), addrs, Config{Workers: 4, Rate: 500, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].IP != "10.1.0.5" || res[1].IP != "10.1.0.40" {
		t.Fatalf("%+v", res)
	}
	if len(probed) != 62 {
		t.Fatalf("probed %d addresses", len(probed))
	}
	if maxInflight > 4 {
		t.Fatalf("concurrency %d exceeds workers", maxInflight)
	}
	// 62 probes at 500/s cannot finish faster than ~120ms
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Fatalf("rate limit not applied: %v", d)
	}
}

func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	addrs := Addresses(netip.MustParsePrefix("10.2.0.0/24"))
	var n int32
	probe := func(context.Context, string, []int, time.Duration) (*yealink.ProbeResult, error) {
		if atomic.AddInt32(&n, 1) == 3 {
			cancel()
		}
		return nil, nil
	}
	_, err := Scan(ctx, addrs, Config{Workers: 2, Rate: 200, Probe: probe})
	if err == nil {
		t.Fatal("expected context error")
	}
	if atomic.LoadInt32(&n) > 20 {
		t.Fatalf("scan did not stop: %d probes", n)
	}
}
