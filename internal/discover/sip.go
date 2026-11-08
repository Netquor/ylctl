package discover

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A phone answers a SIP OPTIONS ping on UDP 5060 with a User-Agent such as
// "Yealink SIP-T41S 66.85.0.79": no login, about 25 ms, one packet each way.
// That makes it the fastest way to find phones and read their model and firmware.
var reYealinkUA = regexp.MustCompile(`(?i)yealink\s+sip-(\S+)\s+([0-9][0-9.]+)`)

// SIPHit is one device that answered the ping.
type SIPHit struct {
	IP        string
	UserAgent string
	Model     string // "T41S" when it is a Yealink, else empty
	Firmware  string
}

const sipPasses = 3

func optionsMessage(target, tag string) []byte {
	return []byte("OPTIONS sip:" + target + " SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5090;branch=z9hG4bK" + tag + ";rport\r\nMax-Forwards: 70\r\n" +
		"From: <sip:ylctl@192.0.2.1>;tag=" + tag + "\r\nTo: <sip:" + target + ">\r\nCall-ID: " + tag + "@ylctl\r\nCSeq: 1 OPTIONS\r\n" +
		"Contact: <sip:ylctl@192.0.2.1:5090>\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n")
}

// ParseSIPReply reads the User-Agent (or Server) of a SIP reply.
func ParseSIPReply(b []byte) (ua string, ok bool) {
	t := string(b)
	if !strings.HasPrefix(t, "SIP/2.0 ") {
		return "", false
	}
	for _, l := range strings.Split(t, "\r\n") {
		k, v, found := strings.Cut(l, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "user-agent", "server":
			return strings.TrimSpace(v), true
		}
	}
	return "", true
}

// SIPSweep sends one OPTIONS to every address on the given UDP port, in three passes (UDP can drop a
// packet, and the first packet to a host often waits for ARP), listens for wait after the last send, and returns the devices that answered.
// rate is packets per second (0 = 2000). Only Yealink phones are marked with Model.
func SIPSweep(ctx context.Context, addrs []netip.Addr, port int, wait time.Duration, rate int) ([]SIPHit, error) {
	if port == 0 {
		port = 5060
	}
	if rate <= 0 {
		rate = 2000
	}
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 << 20) // replies arrive in bursts
		_ = uc.SetWriteBuffer(1 << 20)
	}
	want := map[string]bool{}
	for _, a := range addrs {
		want[a.String()] = true
	}
	var mu sync.Mutex
	hits := map[string]SIPHit{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			ip := from.(*net.UDPAddr).IP.String()
			if !want[ip] {
				continue
			}
			ua, ok := ParseSIPReply(buf[:n])
			if !ok {
				continue
			}
			h := SIPHit{IP: ip, UserAgent: ua}
			if m := reYealinkUA.FindStringSubmatch(ua); m != nil {
				h.Model, h.Firmware = strings.ToUpper(m[1]), m[2]
			}
			mu.Lock()
			hits[ip] = h
			mu.Unlock()
		}
	}()
	// A fresh transaction id per run: a phone treats a repeat of a recent id as a retransmission and
	// answers the old (closed) source port instead of ours.
	nb := make([]byte, 4)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()
send:
	for pass := 0; pass < sipPasses; pass++ {
		for _, a := range addrs {
			select {
			case <-ctx.Done():
				break send
			case <-tick.C:
			}
			_, _ = pc.WriteTo(optionsMessage(a.String(), fmt.Sprintf("%s%08x%d", nonce, a.As4(), pass)), &net.UDPAddr{IP: net.IP(a.AsSlice()), Port: port})
		}
		if pass < sipPasses-1 { // a gap lets ARP resolve and a router recover from the burst
			select {
			case <-ctx.Done():
				break send
			case <-time.After(wait / 3):
			}
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
	_ = pc.Close()
	<-done
	out := make([]SIPHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, h)
	}
	return out, nil
}
