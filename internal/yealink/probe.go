package yealink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ProbeResult is what an unauthenticated probe learned about a host.
type ProbeResult struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Scheme     string `json:"scheme"`
	Model      string `json:"model"`
	Firmware   string `json:"firmware"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

// Probe checks whether ip runs a Yealink web interface. It opens a TCP
// connection to each port in order and fetches the login form; it never logs
// in and never sends credentials. It returns nil, nil for hosts that are not
// phones.
func Probe(ctx context.Context, ip string, ports []int, timeout time.Duration) (*ProbeResult, error) {
	// Dial all ports at once with a short connect timeout, then inspect the open ones in order.
	dialTimeout := timeout
	if dialTimeout > time.Second {
		dialTimeout = time.Second
	}
	open := make([]bool, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			d := net.Dialer{Timeout: dialTimeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err == nil {
				conn.Close()
				open[i] = true
			}
		}(i, port)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, port := range ports {
		if !open[i] {
			continue
		}
		for _, scheme := range []string{"https", "http"} {
			if r := fingerprint(ctx, scheme, ip, port, timeout); r != nil {
				return r, nil
			}
		}
	}
	return nil, nil
}

func fingerprint(ctx context.Context, scheme, ip string, port int, timeout time.Duration) *ProbeResult {
	var fp string
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // fingerprinting only; no credentials are ever sent on a probe
			MinVersion:         tls.VersionTLS10,
			CipherSuites:       phoneCipherSuites(),
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) > 0 {
					fp = Fingerprint(raw[0])
				}
				return nil
			},
		},
	}
	hc := &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/servlet?m=mod_listener&p=login&q=loginForm"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ylctl-discover")
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil
	}
	id, ok := IdentifyLoginPage(string(b))
	if !ok {
		return nil
	}
	return &ProbeResult{IP: ip, Port: port, Scheme: scheme, Model: id.Model, Firmware: id.Firmware, CertSHA256: fp}
}
