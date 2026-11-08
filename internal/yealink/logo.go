package yealink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// LogoMode is Features > General Information > LCD Logo.
type LogoMode string

const (
	LogoOff    LogoMode = "0" // no logo
	LogoSystem LogoMode = "1" // the built-in logo
	LogoCustom LogoMode = "2" // the uploaded .dob file
)

// Logo reads the LCD logo mode.
func (c *Client) Logo(ctx context.Context) (LogoMode, error) {
	p, err := c.load(ctx, "features-general", "")
	if err != nil {
		return "", err
	}
	f, ok := FieldMap(ParseFields(p))["LCDLogo"]
	if !ok {
		return "", fmt.Errorf("%w: this phone's General page has no LCD Logo field", ErrUnexpectedPage)
	}
	return LogoMode(f.Value), nil
}

// SetLogoMode writes the LCD Logo field and verifies by reading it back.
func (c *Client) SetLogoMode(ctx context.Context, m LogoMode) error {
	if m != LogoOff && m != LogoSystem && m != LogoCustom {
		return errors.New("logo mode is 0, 1 or 2")
	}
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "features-general", "")
		if err != nil {
			return err
		}
		tok, ok := ParseToken(page)
		if !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		body := "LCDLogo=" + url.QueryEscape(string(m)) + "&token=" + url.QueryEscape(tok)
		out, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_data&p=features-general&q=write&Rajax="+c.cacheBuster(), body)
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
	got, err := c.Logo(ctx)
	if err != nil {
		return fmt.Errorf("written, but verification failed: %w", err)
	}
	if got != m {
		return fmt.Errorf("%w: the LCD logo mode is %q after the write, wanted %q", ErrWriteRejected, got, m)
	}
	return nil
}

// DeleteLogo removes the uploaded custom logo (the web page's Delete button).
func (c *Client) DeleteLogo(ctx context.Context) error {
	return c.withSession(ctx, func() error {
		out, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_res&p=action&type=del_lcdlogo&Rajax="+c.cacheBuster(), "")
		if err != nil {
			return writeErr(err)
		}
		if IsLoginPage(out) {
			return errSessionLost
		}
		return nil
	})
}

// UploadLogo sends a .dob file the way the web page does: multipart field "UploadName" to
// servlet?m=mod_res&p=upload&type=lcdlogo, with the size limit RSA-encrypted together with the session id.
func (c *Client) UploadLogo(ctx context.Context, dob []byte) error {
	if len(dob) == 0 || len(dob) > 1<<20 {
		return errors.New("the logo file must be between 1 byte and 1 MB")
	}
	if c.rsaPub == nil {
		return errors.New("not logged in")
	}
	return c.withSession(ctx, func() error {
		sid := c.sessionID()
		if sid == "" {
			return fmt.Errorf("%w: no session cookie", ErrUnexpectedPage)
		}
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, c.rsaPub, []byte(sid+";1MB"))
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="UploadName"; filename="logo.dob"`)
		h.Set("Content-Type", "application/octet-stream")
		part, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		if _, err := part.Write(dob); err != nil {
			return err
		}
		if err := mw.Close(); err != nil {
			return err
		}
		path := "/servlet?m=mod_res&p=upload&type=lcdlogo&maxlength=" + url.QueryEscape(hex.EncodeToString(ct))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.t.BaseURL()+path, &buf)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("User-Agent", "ylctl")
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		body := string(b)
		if resp.StatusCode != http.StatusOK {
			return &HTTPError{Status: resp.StatusCode, Path: redactPath(path)}
		}
		if IsLoginPage(body) {
			return errSessionLost
		}
		info, ok := ParseResInfo(body)
		if !ok {
			info = strings.TrimSpace(body)
		}
		return logoUploadResult(info)
	})
}

// logoUploadResult reads {"type":"lcdlogo","result":0}: zero or more is success, -2 means too big.
func logoUploadResult(info string) error {
	var r struct {
		Result json.Number `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(info)), &r); err != nil || r.Result == "" {
		return fmt.Errorf("%w: the upload answer was %q", ErrUnexpectedPage, clip(info))
	}
	n, err := r.Result.Int64()
	if err != nil {
		return fmt.Errorf("%w: the upload answer was %q", ErrUnexpectedPage, clip(info))
	}
	switch {
	case n >= 0:
		return nil
	case n == -2:
		return errors.New("the phone says the file is too big")
	default:
		return errors.New("the phone says the upload failed (is the file a valid .dob for this model?)")
	}
}
