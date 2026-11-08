// Package discover finds Yealink phones by probing a range of addresses
// without ever logging in.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/Netquor/ylctl/internal/yealink"
)

// MaxPrefixBits is the smallest prefix length allowed without force (/22 = 1024 addresses).
const MaxPrefixBits = 22

// ParseRange parses a CIDR (or a single address) and applies the safety rules.
func ParseRange(s string, allowPublic, force bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("invalid range %q (use CIDR such as 192.168.1.0/24)", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("only IPv4 ranges are supported")
	}
	if !allowPublic && (!local(p.Addr()) || !local(last(p))) {
		return netip.Prefix{}, fmt.Errorf("%s is not a private range; scanning public addresses needs --allow-public", p)
	}
	if p.Bits() < MaxPrefixBits && !force {
		return netip.Prefix{}, fmt.Errorf("%s is larger than /%d (%d addresses); pass --force if you really mean it", p, MaxPrefixBits, Size(p))
	}
	return p, nil
}

func local(a netip.Addr) bool { return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() }

func last(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := 32 - p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if host > 0 {
		v |= uint32(1)<<uint(host) - 1
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Size is the number of host addresses that Addresses returns.
func Size(p netip.Prefix) int {
	host := 32 - p.Bits()
	n := 1 << uint(host)
	if host >= 2 {
		n -= 2 // network and broadcast
	}
	return n
}

// Addresses lists the probe targets of a prefix (network and broadcast excluded for /30 and larger).
func Addresses(p netip.Prefix) []netip.Addr {
	var out []netip.Addr
	host := 32 - p.Bits()
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		if host >= 2 && (a == p.Addr() || a == last(p)) {
			continue
		}
		out = append(out, a)
		if !a.Next().IsValid() {
			break
		}
	}
	return out
}

// LocalSubnets returns the private IPv4 subnets of the up, non-loopback interfaces.
func LocalSubnets() ([]netip.Prefix, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP.To4())
			if !ok || !ip.IsPrivate() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			p := netip.PrefixFrom(ip, ones).Masked()
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// Config for Scan.
type Config struct {
	Ports   []int
	Workers int           // default 32
	Rate    int           // probes per second, default 100
	Timeout time.Duration // per TCP/HTTP step, default 2s
	Probe   func(ctx context.Context, ip string, ports []int, timeout time.Duration) (*yealink.ProbeResult, error)
}

// Scan probes all addresses and returns the phones found, sorted by address.
func Scan(ctx context.Context, addrs []netip.Addr, c Config) ([]yealink.ProbeResult, error) {
	if c.Workers <= 0 {
		c.Workers = 32
	}
	if c.Rate <= 0 {
		c.Rate = 100
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if len(c.Ports) == 0 {
		c.Ports = []int{443, 80}
	}
	if c.Probe == nil {
		c.Probe = yealink.Probe
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tick := time.NewTicker(time.Second / time.Duration(c.Rate))
	defer tick.Stop()
	jobs := make(chan netip.Addr)
	var mu sync.Mutex
	var found []yealink.ProbeResult
	var wg sync.WaitGroup
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				r, err := c.Probe(ctx, a.String(), c.Ports, c.Timeout)
				if err == nil && r != nil {
					mu.Lock()
					found = append(found, *r)
					mu.Unlock()
				}
			}
		}()
	}
loop:
	for _, a := range addrs {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
		}
		select {
		case <-ctx.Done():
			break loop
		case jobs <- a:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(found, func(i, j int) bool {
		ai, _ := netip.ParseAddr(found[i].IP)
		aj, _ := netip.ParseAddr(found[j].IP)
		if ai != aj {
			return ai.Less(aj)
		}
		return found[i].Port < found[j].Port
	})
	return found, ctx.Err()
}
