// Package recon holds the pure parts of 'ylctl recon': reading the subnets a
// person types, the ARP table, the multi-select list, vendor reset guides and
// the few settings it remembers. Nothing here touches the network.
package recon

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseSubnets reads what a person typed at the "scan these subnets?" prompt.
//
//	(empty)          the guesses, as they are
//	/23              the same networks with a different mask (applied to each guess)
//	192.168.5.0/24   a full range
//	10.1.2.3         one address (a /24 around it)
//	any mix, separated by commas or spaces
//
// A bare "/N" with several guesses re-masks every guess.
func ParseSubnets(guesses []netip.Prefix, input string) ([]netip.Prefix, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return dedupe(guesses), nil
	}
	var out []netip.Prefix
	for _, tok := range strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		switch {
		case strings.HasPrefix(tok, "/"):
			n, err := strconv.Atoi(tok[1:])
			if err != nil || n < 8 || n > 30 {
				return nil, fmt.Errorf("%q is not a mask length between /8 and /30", tok)
			}
			if len(guesses) == 0 {
				return nil, fmt.Errorf("%q needs a guess to apply to; type a full range such as 192.168.1.0/24", tok)
			}
			for _, g := range guesses {
				out = append(out, netip.PrefixFrom(g.Addr(), n).Masked())
			}
		case strings.Contains(tok, "/"):
			p, err := netip.ParsePrefix(tok)
			if err != nil || !p.Addr().Is4() {
				return nil, fmt.Errorf("%q is not an IPv4 range like 192.168.1.0/24", tok)
			}
			out = append(out, p.Masked())
		default:
			a, err := netip.ParseAddr(tok)
			if err != nil || !a.Is4() {
				return nil, fmt.Errorf("%q is not an IPv4 address or range", tok)
			}
			out = append(out, netip.PrefixFrom(a, 24).Masked())
		}
	}
	return dedupe(out), nil
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range in {
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Describe lists prefixes for a prompt.
func Describe(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
