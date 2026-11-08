package yealink

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// SyslogFields are the only settings-config fields ylctl will write for the
// log feature. Anything else is refused.
var SyslogFields = []string{
	"SyslogSwitch", "SyslogServerName", "SyslogServerPort", "SyslogTransportType",
	"SyslogLevel", "SyslogFacility", "SyslogPrependMac",
}

// Syslog is the phone's remote syslog configuration (Settings > Configuration).
// Values are the phone's own codes: Switch 0|1, Transport 0=UDP 1=TCP 2=TLS,
// Level 0 (emergency) to 6 (debug).
type Syslog map[string]string

// Syslog reads the remote syslog settings.
func (c *Client) Syslog(ctx context.Context) (Syslog, error) {
	p, err := c.load(ctx, "settings-config", "")
	if err != nil {
		return nil, err
	}
	fm := FieldMap(ParseFields(p))
	out := Syslog{}
	for _, n := range SyslogFields {
		f, ok := fm[n]
		if !ok {
			return nil, fmt.Errorf("%w: field %s not found on the configuration page", ErrUnexpectedPage, n)
		}
		out[n] = f.Value
	}
	return out, nil
}

// WriteSyslog writes the given syslog fields and verifies by reading them back.
// It sends only the fields given, plus the CSRF token, like the web page does.
func (c *Client) WriteSyslog(ctx context.Context, set map[string]string) error {
	if len(set) == 0 {
		return errors.New("nothing to write")
	}
	allowed := map[string]bool{}
	for _, n := range SyslogFields {
		allowed[n] = true
	}
	names := make([]string, 0, len(set))
	for n, v := range set {
		if !allowed[n] {
			return fmt.Errorf("refusing to write field %q", n)
		}
		if strings.ContainsAny(v, "\r\n&=") {
			return fmt.Errorf("refusing odd value for %s", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-config", "")
		if err != nil {
			return err
		}
		tok, ok := ParseToken(page)
		if !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		var b strings.Builder
		for _, n := range names {
			b.WriteString(n + "=" + url.QueryEscape(set[n]) + "&")
		}
		b.WriteString("token=" + url.QueryEscape(tok))
		out, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_data&p=settings-config&q=write&Rajax="+c.cacheBuster(), b.String())
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
	after, err := c.Syslog(ctx)
	if err != nil {
		return fmt.Errorf("written, but verification failed: %w", err)
	}
	for _, n := range names {
		if after[n] != set[n] {
			return fmt.Errorf("%w: %s is %q after the write, wanted %q", ErrWriteRejected, n, after[n], set[n])
		}
	}
	return nil
}
