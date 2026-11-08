package yealink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// Endpoints used by the Diagnostics part of Settings > Configuration
// (page_settings-config.js, firmware 66.85 and 66.86):
//
//	GET  servlet?m=mod_configfile&q=getcapturestatus                          -> _RES_INFO_ true|false
//	POST servlet?m=mod_configfile&q=downloadcapture&type=start&pcaptype=1     -> streamed pcap (the browser "download")
//	POST servlet?m=mod_configfile&q=downloadcapture&type=stop&pcaptype=1      -> stop (CSRF token in the body)
//	GET  servlet?m=mod_configfile&q=exportsyslog&type=2                        -> tar of the local log files
const (
	captureBase = "/servlet?m=mod_configfile&q=downloadcapture&pcaptype=1"
	syslogPath  = "/servlet?m=mod_configfile&q=exportsyslog&type=2"
)

// CaptureStream is an open streaming pcap download. Closing it closes the
// connection; the phone keeps capturing until StopCapture is called (verified
// in docs/live-capture.md).
type CaptureStream struct {
	Body   io.ReadCloser
	Status int
	Header http.Header
	// Proto and TransferEncoding describe the response framing (for diagnostics).
	Proto            string
	TransferEncoding []string
	ContentLength    int64
}

// CaptureStatus asks the phone whether a packet capture is running.
func (c *Client) CaptureStatus(ctx context.Context) (bool, error) {
	body, err := c.Get(ctx, "/servlet?m=mod_configfile&q=getcapturestatus&Rajax="+c.cacheBuster())
	if err != nil {
		return false, err
	}
	v, ok := ParseResInfo(body)
	if !ok {
		return false, fmt.Errorf("%w: capture status answer has no result", ErrUnexpectedPage)
	}
	switch strings.ToLower(v) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%w: capture status %q", ErrUnexpectedPage, clip(v))
}

// OpenCapture starts the streaming capture (the same two requests the browser
// makes: checkAging, then a multipart POST) and returns the open response.
// The caller must read and close Body, and call StopCapture when done.
func (c *Client) OpenCapture(ctx context.Context) (*CaptureStream, error) {
	if !c.loggedIn {
		return nil, errors.New("not logged in")
	}
	if _, err := c.Get(ctx, "/servlet?m=mod_data&q=checkAging&Rajax="+c.cacheBuster()); err != nil {
		return nil, err
	}
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	_ = mw.Close() // the browser form has no fields: just the closing boundary
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.t.BaseURL()+captureBase+"&type=start", &form)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("User-Agent", "ylctl")
	// Same transport and cookies as the normal client, but no overall timeout:
	// the download is meant to run for minutes.
	sc := &http.Client{Transport: c.hc.Transport, Jar: c.hc.Jar, CheckRedirect: c.hc.CheckRedirect}
	resp, err := sc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrSessionLost
		}
		return nil, &HTTPError{Status: resp.StatusCode, Path: "downloadcapture start"}
	}
	return &CaptureStream{Body: resp.Body, Status: resp.StatusCode, Header: resp.Header, Proto: resp.Proto, TransferEncoding: resp.TransferEncoding, ContentLength: resp.ContentLength}, nil
}

// StopCapture stops the streaming capture. It needs the CSRF token of the session.
func (c *Client) StopCapture(ctx context.Context) error {
	return c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-config", "")
		if err != nil {
			return err
		}
		tok, ok := ParseToken(page)
		if !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		out, err := c.fetch(ctx, http.MethodPost, captureBase+"&type=stop&Rajax="+c.cacheBuster(), "token="+url.QueryEscape(tok))
		if err != nil {
			return writeErr(err)
		}
		if IsLoginPage(out) {
			return errSessionLost
		}
		return nil
	})
}

// ExportSyslog downloads the local log archive (a tar of log files, about 1 MiB).
func (c *Client) ExportSyslog(ctx context.Context, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	var out []byte
	err := c.withSession(ctx, func() error {
		old := c.o.MaxBody
		c.o.MaxBody = maxBytes
		defer func() { c.o.MaxBody = old }()
		s, err := c.fetch(ctx, http.MethodGet, syslogPath+"&Rajax="+c.cacheBuster(), "")
		if err != nil {
			return err
		}
		if len(s) < 600 && IsLoginPage(s) {
			return errSessionLost
		}
		out = []byte(s)
		return nil
	})
	return out, err
}
