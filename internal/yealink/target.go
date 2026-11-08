package yealink

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Target is a parsed phone address.
type Target struct {
	Scheme string // https or http
	Host   string // host or IP without port
	Port   string
}

// ParseTarget accepts "host", "host:port", "https://host[:port]" and "http://host[:port]".
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty host")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("invalid host %q", s)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Target{}, fmt.Errorf("unsupported scheme %q (use https or http)", u.Scheme)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("credentials in the host are not accepted; use the environment or the keychain")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	return Target{Scheme: u.Scheme, Host: u.Hostname(), Port: port}, nil
}

// HostPort is host:port, bracketed for IPv6.
func (t Target) HostPort() string { return net.JoinHostPort(t.Host, t.Port) }

// BaseURL is scheme://host:port without a trailing slash.
func (t Target) BaseURL() string { return t.Scheme + "://" + t.HostPort() }

// Label is how the phone is named in messages and keychain entries.
func (t Target) Label() string {
	if (t.Scheme == "https" && t.Port == "443") || (t.Scheme == "http" && t.Port == "80") {
		return t.Host
	}
	return t.HostPort()
}
