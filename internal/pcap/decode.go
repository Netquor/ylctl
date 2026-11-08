package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Frame is a decoded packet: addresses, ports, protocol and, when it is SIP,
// the parsed message. Decode never fails; fields it could not read are empty.
type Frame struct {
	Time    time.Time
	Src     string // IP address
	Dst     string
	SrcPort int
	DstPort int
	Proto   string // ARP, ICMP, UDP, TCP, IPv6-ICMP, ETH or the number
	Len     int    // captured length
	Info    string // short human description
	Payload []byte // transport payload (not copied)
	SIP     *SIPMessage
	TLS     bool // payload looks like a TLS record (so SIP inside it is not readable)
}

// SIPMessage is one SIP request or response.
type SIPMessage struct {
	First  string // request line or status line
	CallID string
	CSeq   string
	From   string
	To     string
	Raw    []byte // the full message, headers and body
}

// Decode reads one captured frame of the given link type.
func Decode(link uint32, p Packet) Frame {
	f := Frame{Time: p.Time, Len: len(p.Data)}
	d := p.Data
	switch link {
	case LinkEthernet:
		if len(d) < 14 {
			f.Proto, f.Info = "ETH", "short frame"
			return f
		}
		et := binary.BigEndian.Uint16(d[12:])
		d = d[14:]
		for et == 0x8100 || et == 0x88a8 { // VLAN tags
			if len(d) < 4 {
				return f
			}
			et = binary.BigEndian.Uint16(d[2:])
			d = d[4:]
		}
		switch et {
		case 0x0800:
			decodeIPv4(&f, d)
		case 0x86dd:
			decodeIPv6(&f, d)
		case 0x0806:
			f.Proto = "ARP"
			if len(d) >= 28 {
				op := binary.BigEndian.Uint16(d[6:])
				sp, tp := net.IP(d[14:18]).String(), net.IP(d[24:28]).String()
				f.Src, f.Dst = sp, tp
				if op == 1 {
					f.Info = "who has " + tp + "? tell " + sp
				} else {
					f.Info = sp + " is at " + net.HardwareAddr(d[8:14]).String()
				}
			}
		default:
			f.Proto = fmt.Sprintf("ETH-0x%04x", et)
		}
	case LinkRaw:
		if len(d) > 0 && d[0]>>4 == 6 {
			decodeIPv6(&f, d)
		} else {
			decodeIPv4(&f, d)
		}
	case LinkLinuxSLL:
		if len(d) < 16 {
			return f
		}
		et := binary.BigEndian.Uint16(d[14:])
		d = d[16:]
		if et == 0x0800 {
			decodeIPv4(&f, d)
		} else if et == 0x86dd {
			decodeIPv6(&f, d)
		}
	default:
		f.Proto = "link-" + strconv.Itoa(int(link))
	}
	return f
}

func decodeIPv4(f *Frame, d []byte) {
	if len(d) < 20 || d[0]>>4 != 4 {
		f.Proto = "IPv4?"
		return
	}
	ihl := int(d[0]&0x0f) * 4
	if ihl < 20 || len(d) < ihl {
		f.Proto = "IPv4?"
		return
	}
	total := int(binary.BigEndian.Uint16(d[2:]))
	if total >= ihl && total <= len(d) {
		d = d[:total]
	}
	f.Src, f.Dst = net.IP(d[12:16]).String(), net.IP(d[16:20]).String()
	frag := binary.BigEndian.Uint16(d[6:])
	if frag&0x1fff != 0 {
		f.Proto, f.Info = "IPv4", "fragment (not first)"
		return
	}
	transport(f, d[9], d[ihl:])
}

func decodeIPv6(f *Frame, d []byte) {
	if len(d) < 40 || d[0]>>4 != 6 {
		f.Proto = "IPv6?"
		return
	}
	f.Src, f.Dst = net.IP(d[8:24]).String(), net.IP(d[24:40]).String()
	next, rest := d[6], d[40:]
	for i := 0; i < 4 && (next == 0 || next == 43 || next == 60) && len(rest) >= 8; i++ { // skip simple extension headers
		n := int(rest[1])*8 + 8
		if len(rest) < n {
			return
		}
		next, rest = rest[0], rest[n:]
	}
	transport(f, next, rest)
}

func transport(f *Frame, proto byte, d []byte) {
	switch proto {
	case 1, 58:
		f.Proto = "ICMP"
		if proto == 58 {
			f.Proto = "ICMPv6"
		}
		if len(d) >= 2 {
			f.Info = fmt.Sprintf("type %d code %d", d[0], d[1])
		}
	case 17:
		f.Proto = "UDP"
		if len(d) < 8 {
			return
		}
		f.SrcPort, f.DstPort = int(binary.BigEndian.Uint16(d)), int(binary.BigEndian.Uint16(d[2:]))
		f.Payload = d[8:]
		classify(f)
	case 6:
		f.Proto = "TCP"
		if len(d) < 20 {
			return
		}
		f.SrcPort, f.DstPort = int(binary.BigEndian.Uint16(d)), int(binary.BigEndian.Uint16(d[2:]))
		off := int(d[12]>>4) * 4
		flags := d[13]
		if off < 20 || off > len(d) {
			return
		}
		f.Payload = d[off:]
		f.Info = tcpFlags(flags)
		classify(f)
	default:
		f.Proto = "IP-" + strconv.Itoa(int(proto))
	}
}

func tcpFlags(b byte) string {
	var s []string
	for _, x := range []struct {
		bit  byte
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x01, "FIN"}, {0x04, "RST"}} {
		if b&x.bit != 0 {
			s = append(s, x.name)
		}
	}
	return strings.Join(s, ",")
}

var sipStart = [][]byte{
	[]byte("SIP/2.0 "), []byte("REGISTER "), []byte("INVITE "), []byte("ACK "), []byte("BYE "), []byte("CANCEL "),
	[]byte("OPTIONS "), []byte("NOTIFY "), []byte("SUBSCRIBE "), []byte("REFER "), []byte("INFO "),
	[]byte("MESSAGE "), []byte("PRACK "), []byte("UPDATE "), []byte("PUBLISH "),
}

// LooksLikeSIP reports whether b starts like a SIP message.
func LooksLikeSIP(b []byte) bool {
	for _, s := range sipStart {
		if bytes.HasPrefix(b, s) {
			return true
		}
	}
	return false
}

// classify fills Info, SIP and TLS for a UDP or TCP payload.
func classify(f *Frame) {
	pl := f.Payload
	if len(pl) == 0 {
		return
	}
	if len(pl) >= 5 && pl[0] >= 0x14 && pl[0] <= 0x17 && pl[1] == 3 && pl[2] <= 4 {
		f.TLS = true
		kind := map[byte]string{0x14: "change-cipher-spec", 0x15: "alert", 0x16: "handshake", 0x17: "application data"}[pl[0]]
		f.Info = joinInfo(f.Info, "TLS "+kind)
		return
	}
	if f.Proto == "UDP" && (f.SrcPort == 53 || f.DstPort == 53) && len(pl) >= 12 {
		f.Info = joinInfo(f.Info, "DNS "+dnsName(pl))
		return
	}
	if f.Proto == "UDP" && (f.SrcPort == 123 || f.DstPort == 123) {
		f.Info = joinInfo(f.Info, "NTP")
		return
	}
	if f.Proto == "UDP" && (f.SrcPort == 67 || f.DstPort == 67 || f.SrcPort == 68) {
		f.Info = joinInfo(f.Info, "DHCP")
		return
	}
	if LooksLikeSIP(pl) {
		if m, ok := ParseSIP(pl); ok {
			f.SIP = m
			f.Info = joinInfo(f.Info, m.Summary())
		}
	}
}

func joinInfo(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

func dnsName(p []byte) string {
	var parts []string
	i := 12
	for i < len(p) && len(parts) < 10 {
		n := int(p[i])
		if n == 0 || n > 63 || i+1+n > len(p) {
			break
		}
		parts = append(parts, string(p[i+1:i+1+n]))
		i += 1 + n
	}
	return strings.Join(parts, ".")
}

// ParseSIP reads the headers of one complete SIP message.
func ParseSIP(b []byte) (*SIPMessage, bool) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	hdr := b
	if end >= 0 {
		hdr = b[:end]
	}
	lines := strings.Split(string(hdr), "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, false
	}
	m := &SIPMessage{First: lines[0], Raw: b}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "call-id", "i":
			m.CallID = v
		case "cseq":
			m.CSeq = v
		case "from", "f":
			m.From = v
		case "to", "t":
			m.To = v
		}
	}
	return m, true
}

// Summary is a one-line description of the message.
func (m *SIPMessage) Summary() string {
	s := m.First
	if m.CSeq != "" {
		s += " [" + m.CSeq + "]"
	}
	return s
}

// SIPStream rebuilds SIP messages from TCP payloads (plain text only; TLS is
// not decrypted). One instance handles many flows.
type SIPStream struct {
	flows map[string][]byte
}

const maxFlowBuf = 64 << 10

// Feed adds a TCP payload for the flow and returns the complete messages.
func (s *SIPStream) Feed(flow string, payload []byte) []*SIPMessage {
	if s.flows == nil {
		s.flows = map[string][]byte{}
	}
	buf := append(s.flows[flow], payload...)
	var out []*SIPMessage
	for {
		if !LooksLikeSIP(buf) {
			if partialSIPStart(buf) {
				break // the first line has not fully arrived
			}
			// not at a message start: drop bytes until one is found, or keep nothing
			i := nextSIPStart(buf)
			if i < 0 {
				delete(s.flows, flow)
				return out
			}
			buf = buf[i:]
		}
		end := bytes.Index(buf, []byte("\r\n\r\n"))
		if end < 0 {
			break
		}
		bodyLen := contentLength(buf[:end])
		total := end + 4 + bodyLen
		if bodyLen < 0 || total > maxFlowBuf {
			buf = buf[end+4:] // unusable length: skip the headers
			continue
		}
		if len(buf) < total {
			break
		}
		if m, ok := ParseSIP(buf[:total]); ok {
			out = append(out, m)
		}
		buf = buf[total:]
	}
	if len(buf) > maxFlowBuf {
		buf = nil
	}
	if len(buf) == 0 {
		delete(s.flows, flow)
	} else {
		s.flows[flow] = append([]byte(nil), buf...)
		if len(s.flows) > 256 { // bound memory
			s.flows = map[string][]byte{}
		}
	}
	return out
}

func partialSIPStart(b []byte) bool {
	for _, s := range sipStart {
		if len(b) < len(s) && bytes.HasPrefix(s, b) {
			return true
		}
	}
	return false
}

func nextSIPStart(b []byte) int {
	best := -1
	for _, s := range sipStart {
		if i := bytes.Index(b, append([]byte("\n"), s...)); i >= 0 && (best < 0 || i+1 < best) {
			best = i + 1
		}
	}
	return best
}

func contentLength(h []byte) int {
	for _, l := range strings.Split(string(h), "\r\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		if k = strings.ToLower(strings.TrimSpace(k)); k == "content-length" || k == "l" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 || n > maxFlowBuf {
				return -1
			}
			return n
		}
	}
	return 0
}
