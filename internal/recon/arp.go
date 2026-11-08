package recon

import (
	"regexp"
	"strings"
)

var (
	reARPmac   = regexp.MustCompile(`\(([0-9.]+)\) at ([0-9a-fA-F:]{11,17}) `)      // macOS and BSD: ? (192.168.0.5) at 80:5e:c0:00:00:0a on en0
	reNeighMac = regexp.MustCompile(`^([0-9.]+) dev \S+ lladdr ([0-9a-fA-F:]{17})`) // Linux: ip neigh
)

// ParseARP reads `arp -an` (macOS, BSD, Linux net-tools) or `ip neigh` output
// into an IP -> MAC map with every MAC written as 12 lower-case hex digits.
func ParseARP(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		var ip, mac string
		if r := reARPmac.FindStringSubmatch(line + " "); r != nil {
			ip, mac = r[1], r[2]
		} else if r := reNeighMac.FindStringSubmatch(strings.TrimSpace(line)); r != nil {
			ip, mac = r[1], r[2]
		} else {
			continue
		}
		if n := NormMAC(mac); n != "" && n != "ffffffffffff" {
			m[ip] = n
		}
	}
	return m
}

// NormMAC turns any common spelling into 12 lower-case hex digits ("" if it is not a MAC).
// macOS drops leading zeros in each octet ("0:5e:c0"), which this repairs.
func NormMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) != 6 {
			return ""
		}
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, "")
	}
	s = strings.NewReplacer("-", "", ".", "", ":", "").Replace(s)
	if len(s) != 12 || strings.Trim(s, "0123456789abcdef") != "" {
		return ""
	}
	return s
}

// Colon writes a normalised MAC as aa:bb:cc:dd:ee:ff.
func Colon(mac string) string {
	if len(mac) != 12 {
		return mac
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(mac[i : i+2])
	}
	return b.String()
}
