package discover

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParseSIPReply(t *testing.T) {
	ua, ok := ParseSIPReply([]byte("SIP/2.0 200 OK\r\nVia: x\r\nUser-Agent: Yealink SIP-T41S 66.85.0.79\r\nAllow: INVITE\r\n\r\n"))
	if !ok || ua != "Yealink SIP-T41S 66.85.0.79" {
		t.Fatalf("%q %v", ua, ok)
	}
	if _, ok := ParseSIPReply([]byte("HTTP/1.1 200 OK\r\n\r\n")); ok {
		t.Error("not SIP")
	}
	if ua, ok := ParseSIPReply([]byte("SIP/2.0 405 Method Not Allowed\r\nServer: Asterisk PBX 20\r\n\r\n")); !ok || ua != "Asterisk PBX 20" {
		t.Errorf("%q %v", ua, ok)
	}
	if m := reYealinkUA.FindStringSubmatch("Yealink SIP-T46U 108.86.0.20"); m == nil || m[1] != "T46U" {
		t.Error("model regex")
	}
	_, _ = ParseSIPReply(nil)
	_, _ = ParseSIPReply([]byte("SIP/2.0"))
}

func TestSIPSweepFindsAFakePhone(t *testing.T) {
	// a fake phone on loopback answers OPTIONS; a second address stays silent
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback UDP")
	}
	defer srv.Close()
	port := srv.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:8]) == "OPTIONS " && n > 20 {
				_, _ = srv.WriteTo([]byte("SIP/2.0 200 OK\r\nUser-Agent: Yealink SIP-T41S 66.85.0.79\r\n\r\n"), from)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hits, err := SIPSweep(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, port, 600*time.Millisecond, 1000)
	if err != nil || len(hits) != 1 || hits[0].Model != "T41S" || hits[0].Firmware != "66.85.0.79" {
		t.Fatalf("%+v %v", hits, err)
	}
	// nothing answers on an unused port
	hits, _ = SIPSweep(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, 9, 300*time.Millisecond, 1000)
	if len(hits) != 0 {
		t.Errorf("%+v", hits)
	}
}
