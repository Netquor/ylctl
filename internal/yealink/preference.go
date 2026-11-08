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

// PreferenceFields are the only settings-preference fields ylctl reads or writes for the screensaver.
// ScreenSaverType exists only on phones whose page offers it (the color models); the T41S page has just the
// wait time and the XML URL.
var PreferenceFields = []string{"ScreenSaverWaitTime", "XmlScreenSaverURL", "ScreenSaverType"}

// ScreensaverWaits are the wait times (seconds) ylctl will write. The phone's web page lists only Off and
// 30 min to 12 h, but the phone's own menu goes down to 15 seconds (reported by the owner on a T41S), so the
// shorter values are allowed too; the read-back after every write shows whether the phone really took one.
var ScreensaverWaits = []int{0, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 14400, 21600, 28800, 43200}

// Screensaver is the screensaver part of Settings > Preference. Type is "" when the page has no such field.
type Screensaver struct {
	WaitSeconds string `json:"wait_seconds"`
	XMLURL      string `json:"xml_url"`
	Type        string `json:"type,omitempty"`
	HasType     bool   `json:"has_type"`
}

// Screensaver reads the screensaver settings.
func (c *Client) Screensaver(ctx context.Context) (Screensaver, error) {
	p, err := c.load(ctx, "settings-preference", "")
	if err != nil {
		return Screensaver{}, err
	}
	fm := FieldMap(ParseFields(p))
	w, ok1 := fm["ScreenSaverWaitTime"]
	u, ok2 := fm["XmlScreenSaverURL"]
	if !ok1 || !ok2 {
		return Screensaver{}, fmt.Errorf("%w: this phone's preference page has no screensaver fields", ErrUnexpectedPage)
	}
	s := Screensaver{WaitSeconds: w.Value, XMLURL: u.Value}
	if t, ok := fm["ScreenSaverType"]; ok {
		s.Type, s.HasType = t.Value, true
	}
	return s, nil
}

// WriteScreensaver writes the given screensaver fields and verifies by reading them back.
func (c *Client) WriteScreensaver(ctx context.Context, set map[string]string) error {
	if len(set) == 0 {
		return errors.New("nothing to write")
	}
	names := make([]string, 0, len(set))
	for n, v := range set {
		switch n {
		case "ScreenSaverWaitTime":
			ok := false
			for _, w := range ScreensaverWaits {
				if v == fmt.Sprint(w) {
					ok = true
				}
			}
			if !ok {
				return fmt.Errorf("the wait time must be one of 0 (off), 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 14400, 21600, 28800 or 43200 seconds; %q is not", v)
			}
		case "XmlScreenSaverURL":
			if v != "" && !(strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")) {
				return errors.New("the XML URL must start with https:// or http://")
			}
			if len(v) > 511 {
				return errors.New("the XML URL is at most 511 characters")
			}
			if strings.ContainsAny(v, " \r\n\"<>") {
				return errors.New("the XML URL contains characters the phone would mangle")
			}
		case "ScreenSaverType":
			if v != "0" && v != "1" && v != "2" {
				return errors.New("ScreenSaverType is 0, 1 or 2")
			}
		default:
			return fmt.Errorf("refusing to write field %q", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-preference", "")
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
		out, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_data&p=settings-preference&q=write&Rajax="+c.cacheBuster(), b.String())
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
	after, err := c.Screensaver(ctx)
	if err != nil {
		return fmt.Errorf("written, but verification failed: %w", err)
	}
	got := map[string]string{"ScreenSaverWaitTime": after.WaitSeconds, "XmlScreenSaverURL": after.XMLURL, "ScreenSaverType": after.Type}
	for _, n := range names {
		if got[n] != set[n] {
			return fmt.Errorf("%w: %s is %q after the write, wanted %q", ErrWriteRejected, n, got[n], set[n])
		}
	}
	return nil
}
