package yealink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PushServer reads Features > Remote Control > Push XML Server IP Address: the addresses the phone accepts
// pushed XML from (blank = refuses all, "any" = accepts all).
func (c *Client) PushServer(ctx context.Context) (string, error) {
	p, err := c.load(ctx, "features-remotecontrl", "")
	if err != nil {
		return "", err
	}
	f, ok := FieldMap(ParseFields(p))["PushXMLServerIP"]
	if !ok {
		return "", fmt.Errorf("%w: this phone's Remote Control page has no Push XML Server field", ErrUnexpectedPage)
	}
	return f.Value, nil
}

// WritePushServer sets the Push XML Server IP Address and verifies by reading it back. Only a list of IP addresses
// or host names is accepted here; "any" is refused on purpose.
func (c *Client) WritePushServer(ctx context.Context, v string) error {
	if strings.EqualFold(strings.TrimSpace(v), "any") {
		return errors.New("refusing 'any': name the address that may push (leave it blank to refuse every push)")
	}
	if strings.ContainsAny(v, " \"<>\r\n&") || len(v) > 255 {
		return errors.New("the push server value must be IP addresses or host names separated by commas")
	}
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "features-remotecontrl", "")
		if err != nil {
			return err
		}
		tok, ok := ParseToken(page)
		if !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		body := "PushXMLServerIP=" + url.QueryEscape(v) + "&token=" + url.QueryEscape(tok)
		out, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_data&p=features-remotecontrl&q=write&Rajax="+c.cacheBuster(), body)
		if err != nil {
			return writeErr(err)
		}
		if IsLoginPage(out) {
			return errSessionLost
		}
		return nil
	})
	if err != nil {
		return err
	}
	got, err := c.PushServer(ctx)
	if err != nil {
		return fmt.Errorf("written, but verification failed: %w", err)
	}
	if got != v {
		return fmt.Errorf("%w: the push server is %q after the write, wanted %q", ErrWriteRejected, got, v)
	}
	return nil
}

// LocalIPToward is the address of this computer that routes to host.
func LocalIPToward(host string) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, "9"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	a, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", errors.New("no local address")
	}
	return a.IP.String(), nil
}

// PushXML sends an XML object to the phone the way a push server does (HTTP POST /servlet?push=xml with an
// "xml=" body). The phone must list this computer's address as its Push XML Server. It tries the plain-HTTP port
// first (what the maker's example uses), then HTTPS.
func PushXML(ctx context.Context, host, xml string) error {
	body := "xml=" + xml
	var last error
	for _, base := range []string{"http://" + net.JoinHostPort(host, "80"), "https://" + net.JoinHostPort(host, "443")} {
		hc := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: pushTLS(), DisableKeepAlives: true}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/servlet?push=xml", strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/xml")
		req.Header.Set("Referer", "http://ylctl")
		res, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		res.Body.Close()
		if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
			return nil
		}
		last = fmt.Errorf("the phone answered HTTP %d %s", res.StatusCode, clip(string(b)))
	}
	return fmt.Errorf("the phone did not take the push (is this computer in its Push XML Server list? 'ylctl push allow'): %w", last)
}
