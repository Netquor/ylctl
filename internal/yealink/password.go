package yealink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Password change: Security > Password. The page posts to
// /servlet?m=mod_password&p=security&q=change with the fields mode,
// editOldPassword and editNewPassword (both encrypted like the login), the
// rsakey and rsaiv of that encryption, and the CSRF token. The confirm field is
// checked by the page's own script only and is not sent. The answer is JSON
// with "result": 0 changed, -1 no permission, -2 old password wrong,
// -4 invalid password, -5 the new password is the default. See docs/password.md.

// PasswordPage is what the Security > Password page tells us before a change.
type PasswordPage struct {
	LoginUser string // g_curruser: the web user this session is
	HasFields bool   // mode, editOldPassword and editNewPassword are on the page
}

// PasswordMeaning explains the phone's result codes.
func PasswordMeaning(code string) string {
	switch code {
	case "0":
		return "changed"
	case "-1":
		return "the phone says this user does not have enough permission"
	case "-2":
		return "the phone says the old password is wrong"
	case "-4":
		return "the phone says the new password is invalid"
	case "-5":
		return "the phone says the new password cannot be the default password"
	}
	return "the phone answered with an unknown result code " + code
}

// PasswordOutcome is how a change attempt ended.
type PasswordOutcome int

const (
	// PasswordUnknown: no usable answer. The phone may or may not have changed.
	PasswordUnknown PasswordOutcome = iota
	// PasswordChanged: the phone said result 0.
	PasswordChanged
	// PasswordRejected: the phone said no with a result code (or HTTP 403 for the token); nothing changed.
	PasswordRejected
)

// PasswordRejectedError carries the phone's refusal.
type PasswordRejectedError struct{ Code string }

func (e *PasswordRejectedError) Error() string {
	if e.Code == "" {
		return "the phone refused the password change"
	}
	return fmt.Sprintf("the phone refused the password change (result %s): %s", e.Code, PasswordMeaning(e.Code))
}

// Talking reports whether a call is active (the check the web UI itself makes
// before actions that need an idle phone). Read-only.
func (c *Client) Talking(ctx context.Context) (bool, error) {
	var talking bool
	err := c.withSession(ctx, func() error {
		body, err := c.fetch(ctx, http.MethodGet, "/servlet?m=mod_webd&p=talking&Rajax="+c.cacheBuster(), "")
		if err != nil {
			return err
		}
		if IsLoginPage(body) {
			return errSessionLost
		}
		s := strings.TrimSpace(body)
		if v, ok := ParseResInfo(body); ok {
			s = v
		}
		var o map[string]any
		if json.Unmarshal([]byte(s), &o) != nil {
			return fmt.Errorf("%w: the call state answer is not JSON", ErrUnexpectedPage)
		}
		v, ok := o["talking"]
		if !ok {
			return fmt.Errorf("%w: the call state answer has no 'talking'", ErrUnexpectedPage)
		}
		talking = fmt.Sprint(v) == "1"
		return nil
	})
	return talking, err
}

// PasswordPreflight reads the password page (a GET) and checks it is what we expect.
func (c *Client) PasswordPreflight(ctx context.Context) (*PasswordPage, error) {
	page, err := c.load(ctx, "security", "")
	if err != nil {
		return nil, err
	}
	return parsePasswordPage(page)
}

func parsePasswordPage(page string) (*PasswordPage, error) {
	fm := FieldMap(ParseFields(page))
	pp := &PasswordPage{LoginUser: JSVars(page)["g_curruser"]}
	_, a := fm["mode"]
	_, b := fm["editOldPassword"]
	_, d := fm["editNewPassword"]
	pp.HasFields = a && b && d
	if !pp.HasFields {
		return nil, fmt.Errorf("%w: the password page lacks the expected fields", ErrUnexpectedPage)
	}
	return pp, nil
}

// ChangeAdminPassword sends the change for the user this session is logged in
// as (which must be the web admin). It loads the page for the CSRF token (and
// may log in again with the OLD password if the session was lost before the
// post), then posts exactly once: after the post it never logs in again with
// the old password. A refusal comes back as *PasswordRejectedError with
// PasswordRejected; an answer we cannot read, or a lost connection, is
// PasswordUnknown, and the caller must find out by logging in.
func (c *Client) ChangeAdminPassword(ctx context.Context, oldPW, newPW string) (PasswordOutcome, error) {
	var tok, rsaN, rsaE string
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "security", "")
		if err != nil {
			return err
		}
		pp, err := parsePasswordPage(page)
		if err != nil {
			return err
		}
		if pp.LoginUser != "admin" {
			return fmt.Errorf("this session is logged in as %q: only the admin password can be changed", pp.LoginUser)
		}
		var ok bool
		if tok, ok = ParseToken(page); !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		v := JSVars(page)
		rsaN, rsaE = v["g_rsa_n"], v["g_rsa_e"]
		return nil
	})
	if err != nil {
		return PasswordRejected, err // nothing was sent
	}
	pub, err := ParseRSAKey(rsaN, rsaE)
	if err != nil {
		return PasswordRejected, err
	}
	sid := c.sessionID()
	if sid == "" {
		return PasswordRejected, fmt.Errorf("%w: no session cookie", ErrUnexpectedPage)
	}
	pwds, rk, ri, err := EncryptSecrets(pub, sid, []string{oldPW, newPW}, nil)
	if err != nil {
		return PasswordRejected, err
	}
	body := "mode=admin&editOldPassword=" + url.QueryEscape(pwds[0]) + "&editNewPassword=" + url.QueryEscape(pwds[1]) +
		"&rsakey=" + url.QueryEscape(rk) + "&rsaiv=" + url.QueryEscape(ri) + "&token=" + url.QueryEscape(tok)
	// c.loggedIn stays true; this is the only request and it is never repeated.
	res, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_password&p=security&q=change&Rajax="+c.cacheBuster(), body)
	if err != nil {
		var he *HTTPError
		if errors.As(err, &he) && he.Status == http.StatusForbidden {
			return PasswordRejected, &PasswordRejectedError{} // bad CSRF token: the phone did nothing
		}
		return PasswordUnknown, fmt.Errorf("no answer from the phone to the password change: %w", err)
	}
	if IsLoginPage(res) {
		return PasswordUnknown, errors.New("the phone answered with its login page instead of a result")
	}
	code, ok := passwordResult(res)
	switch {
	case !ok:
		return PasswordUnknown, errors.New("the phone's answer to the password change could not be read")
	case code == "0":
		return PasswordChanged, nil
	case code == "-1" || code == "-2" || code == "-4" || code == "-5":
		return PasswordRejected, &PasswordRejectedError{Code: code}
	}
	return PasswordUnknown, fmt.Errorf("the phone answered with an unknown result code %s", code)
}

func passwordResult(body string) (string, bool) {
	s := strings.TrimSpace(body)
	if v, ok := ParseResInfo(body); ok {
		s = v
	}
	var o map[string]any
	if json.Unmarshal([]byte(s), &o) != nil {
		return "", false
	}
	v, ok := o["result"]
	if !ok {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		return fmt.Sprint(int(t)), true
	}
	return "", false
}
