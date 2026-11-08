// Package syslog parses and receives the syslog datagrams a Yealink phone sends.
package syslog

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxDatagram bounds what the receiver reads; longer datagrams are cut.
const MaxDatagram = 8192

var severities = []string{"emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"}

// Message is one parsed syslog line.
type Message struct {
	Received time.Time
	From     string // sender address
	Facility int
	Severity int // 0 emergency .. 7 debug
	Time     string
	Host     string
	Tag      string
	Module   string // the phone's own module name from the text ("SYS", "SIP", ...), when present
	Text     string
	Raw      string
}

var reModule = regexp.MustCompile(`^(?:\[\s*[0-9.:]+\s*)?([A-Za-z][A-Za-z0-9_]{1,15})\s*<`)

// Key is the name used to group and color a line: the module if there is one, else the tag.
func (m Message) Key() string {
	if m.Module != "" {
		return m.Module
	}
	return m.Tag
}

// SeverityName returns the short name of the severity.
func (m Message) SeverityName() string {
	if m.Severity >= 0 && m.Severity < len(severities) {
		return severities[m.Severity]
	}
	return "?"
}

// Parse reads RFC 3164 and RFC 5424 lines tolerantly. It never fails: text it
// cannot understand is returned as the message with severity info.
func Parse(b []byte, from string, now time.Time) Message {
	m := parse(b, from, now)
	if r := reModule.FindStringSubmatch(m.Text); r != nil {
		m.Module = r[1]
	}
	return m
}

func parse(b []byte, from string, now time.Time) Message {
	s := strings.ToValidUTF8(string(b), "�")
	s = strings.TrimRight(s, "\r\n\x00 ")
	m := Message{Received: now, From: from, Severity: 6, Raw: s, Text: s}
	if strings.HasPrefix(s, "<") {
		if i := strings.IndexByte(s, '>'); i > 1 && i <= 5 {
			if pri, err := strconv.Atoi(s[1:i]); err == nil && pri >= 0 && pri < 192 {
				m.Facility, m.Severity = pri/8, pri%8
				s = s[i+1:]
				m.Text = s
			}
		}
	}
	if strings.HasPrefix(s, "1 ") { // RFC 5424: VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG
		f := strings.SplitN(s, " ", 8)
		if len(f) == 8 {
			m.Time, m.Host, m.Tag = f[1], f[2], f[3]
			msg := f[7]
			if strings.HasPrefix(f[6], "[") && !strings.Contains(f[6], "]") { // structured data with spaces: keep it simple
				msg = f[6] + " " + f[7]
			}
			m.Text = strings.TrimPrefix(msg, "\xef\xbb\xbf")
			return m
		}
	}
	// RFC 3164: "Mmm dd hh:mm:ss HOST TAG: text" (host and tag are both optional in practice)
	if len(s) > 16 && s[3] == ' ' && s[6] == ' ' && s[9] == ':' && s[12] == ':' {
		m.Time = s[:15]
		rest := strings.TrimLeft(s[15:], " ")
		if i := strings.IndexByte(rest, ' '); i > 0 {
			m.Host, rest = rest[:i], rest[i+1:]
		}
		if i := strings.Index(rest, ": "); i > 0 && i < 48 && !strings.ContainsAny(rest[:i], " ") {
			m.Tag, rest = strings.TrimSuffix(rest[:i], "]"), rest[i+2:]
			if j := strings.IndexByte(m.Tag, '['); j > 0 {
				m.Tag = m.Tag[:j]
			}
		}
		m.Text = rest
	}
	if !utf8.ValidString(m.Text) {
		m.Text = strings.ToValidUTF8(m.Text, "�")
	}
	return m
}

// Listen receives UDP syslog on addr and sends parsed messages that come from
// the given sender IP (empty accepts any sender). It returns when ctx ends.
func Listen(ctx context.Context, addr, onlyFrom string, out chan<- Message) (net.Addr, func() error, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	run := func() error {
		buf := make([]byte, MaxDatagram)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			host, _, _ := net.SplitHostPort(from.String())
			if onlyFrom != "" && host != onlyFrom {
				continue
			}
			select {
			case out <- Parse(buf[:n], host, time.Now()):
			case <-ctx.Done():
				return nil
			}
		}
	}
	return pc.LocalAddr(), run, nil
}
