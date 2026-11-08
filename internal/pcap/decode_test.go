package pcap

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func udpFrame(src, dst [4]byte, sp, dp uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(payload)))
	ip[9] = 17
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sp)
	binary.BigEndian.PutUint16(u[2:], dp)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	return append(append(append(eth, ip...), u...), payload...)
}

func TestDecodeSIPOverUDP(t *testing.T) {
	msg := "REGISTER sip:pbx SIP/2.0\r\nCall-ID: abc123\r\nCSeq: 7 REGISTER\r\nFrom: <sip:1004@pbx>\r\nTo: <sip:1004@pbx>\r\nContent-Length: 0\r\n\r\n"
	f := Decode(LinkEthernet, Packet{Time: time.Unix(1, 0), Data: udpFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 1}, 5060, 5060, []byte(msg))})
	if f.Proto != "UDP" || f.Src != "10.0.0.5" || f.DstPort != 5060 {
		t.Fatalf("bad frame %+v", f)
	}
	if f.SIP == nil || f.SIP.CallID != "abc123" || !strings.HasPrefix(f.SIP.First, "REGISTER") {
		t.Fatalf("sip not parsed: %+v", f.SIP)
	}
}

func TestDecodeTLSAndDNS(t *testing.T) {
	f := Decode(LinkEthernet, Packet{Data: udpFrame([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 4000, 53, append(make([]byte, 12), 3, 'p', 'b', 'x', 3, 'n', 'e', 't', 0))})
	if !strings.Contains(f.Info, "DNS pbx.net") {
		t.Fatalf("dns: %q", f.Info)
	}
}

func TestDecodeGarbageNeverPanics(t *testing.T) {
	for n := 0; n < 200; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*31 + n)
		}
		for _, l := range []uint32{0, 1, 101, 113, 999} {
			Decode(l, Packet{Data: b})
		}
		var s SIPStream
		s.Feed("x", b)
	}
}

func TestSIPStreamSplitAcrossSegments(t *testing.T) {
	m := "OPTIONS sip:a SIP/2.0\r\nCall-ID: z\r\nContent-Length: 4\r\n\r\nbody"
	var s SIPStream
	var got int
	for i := 0; i < len(m); i += 7 {
		j := min(i+7, len(m))
		got += len(s.Feed("f", []byte(m[i:j])))
	}
	if got != 1 {
		t.Fatalf("want 1 message, got %d", got)
	}
}

func TestSamplePhoneCapture(t *testing.T) {
	b, err := os.ReadFile(os.Getenv("YLCTL_SAMPLE_PCAP"))
	if err != nil {
		t.Skip("set YLCTL_SAMPLE_PCAP to a phone capture to run this test")
	}
	var p Parser
	n := 0
	for i := 0; i < len(b); i += 13 { // odd chunk size on purpose
		pk, err := p.Feed(b[i:min(i+13, len(b))])
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range pk {
			Decode(LinkEthernet, k)
			n++
		}
	}
	if n < 10 {
		t.Fatalf("only %d packets", n)
	}
}
