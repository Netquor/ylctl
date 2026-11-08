package yealink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// FirmwareMaxSize is the web page's limit for a .rom upload (filedesp maxlength 100MB).
const FirmwareMaxSize = 100 << 20

// romVersion matches a firmware version such as 66.86.0.180.
var romVersion = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

// ROMHeader is what the phone itself reads from the start of a .rom file.
type ROMHeader struct {
	Model   string // e.g. "T46S" (the combined T46S/T48S/T42S/T41S image says T46S)
	Version string // e.g. "66.86.0.180"
	Size    int
	SHA256  string
}

// ParseROMHeader reads the model and version from a .rom file's header (offsets 0x24 and 0x44,
// NUL-padded ASCII, checked against the layout of the Yealink images we have). It is read-only.
func ParseROMHeader(b []byte) (ROMHeader, error) {
	if len(b) < 0x54 || len(b) > FirmwareMaxSize {
		return ROMHeader{}, fmt.Errorf("the firmware file must be between 84 bytes and %d MB", FirmwareMaxSize>>20)
	}
	h := ROMHeader{
		Model:   strings.TrimRight(string(b[0x24:0x34]), "\x00 "),
		Version: strings.TrimRight(string(b[0x44:0x54]), "\x00 "),
		Size:    len(b),
	}
	if !romVersion.MatchString(h.Version) {
		return ROMHeader{}, fmt.Errorf("the header does not carry a firmware version (found %q)", h.Version)
	}
	if h.Model == "" {
		return ROMHeader{}, errors.New("the header does not name a model")
	}
	return h, nil
}

// ReadROM loads and checks a .rom file.
func ReadROM(path string) ([]byte, ROMHeader, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ROMHeader{}, err
	}
	h, err := ParseROMHeader(b)
	if err != nil {
		return nil, ROMHeader{}, err
	}
	return b, h, nil
}

// FirmwareState is what the upgrade page reports before an upload.
type FirmwareState struct {
	Version string
	Model   string
}

// CurrentFirmware reads the running version from the upgrade page (logged in).
func (c *Client) CurrentFirmware(ctx context.Context) (FirmwareState, error) {
	page, err := c.loadRaw(ctx, "settings-upgrade", "")
	if err != nil {
		return FirmwareState{}, err
	}
	fw, ok := LabelValue(page, "PhoneFirmware")
	if !ok || fw == "" {
		return FirmwareState{}, fmt.Errorf("%w: the upgrade page has no firmware version", ErrUnexpectedPage)
	}
	return FirmwareState{Version: fw, Model: JSVars(page)["g_phonetype"]}, nil
}

// UploadFirmware sends a .rom the way the upgrade page does: BeforeUpgrade first (must answer 0),
// then multipart field "UploadName" to servlet?m=mod_upgrade&q=upgrade&native=true with the size
// limit RSA-encrypted together with the session id. It returns the phone's raw answer.
// The phone reboots itself when the flash succeeds; use WaitFirmware to follow it.
func (c *Client) UploadFirmware(ctx context.Context, rom []byte, filename string) (string, error) {
	if len(rom) == 0 || len(rom) > FirmwareMaxSize {
		return "", fmt.Errorf("the firmware file must be between 1 byte and %d MB", FirmwareMaxSize>>20)
	}
	if c.rsaPub == nil {
		return "", errors.New("not logged in")
	}
	sid := c.sessionID()
	if sid == "" {
		return "", fmt.Errorf("%w: no session cookie", ErrUnexpectedPage)
	}

	// Step 1: the page asks the phone to get ready. Anything but 0 stops here.
	page, err := c.loadRaw(ctx, "settings-upgrade", "")
	if err != nil {
		return "", err
	}
	tok, ok := ParseToken(page)
	if !ok {
		return "", fmt.Errorf("%w: no CSRF token on the upgrade page", ErrUnexpectedPage)
	}
	before, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_upgrade&q=beforeupgrade&Rajax="+c.cacheBuster(), "token="+url.QueryEscape(tok))
	if err != nil {
		return "", writeErr(err)
	}
	if IsLoginPage(before) {
		return "", errSessionLost
	}
	ready, ok := ParseResInfo(before)
	if !ok {
		ready = strings.TrimSpace(before)
	}
	if strings.TrimSpace(ready) != "0" {
		return before, fmt.Errorf("%w: the phone refused the upgrade before any upload (answer %q)", ErrWriteRejected, clip(ready))
	}

	// Step 2: the upload itself.
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, c.rsaPub, []byte(sid+";100MB"))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="UploadName"; filename=%q`, filename))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(rom); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	path := "/servlet?m=mod_upgrade&q=upgrade&native=true&maxlength=" + url.QueryEscape(hex.EncodeToString(ct))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.t.BaseURL()+path, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("User-Agent", "ylctl")
	resp, err := c.hc.Do(req)
	if err != nil {
		// A dropped connection during the upload is not proof of failure: the phone may have
		// received the whole file. The caller must check the version afterwards.
		return "", fmt.Errorf("the upload connection ended early (the phone may still be flashing; check its version before retrying): %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	body := string(b)
	if resp.StatusCode != http.StatusOK {
		return body, &HTTPError{Status: resp.StatusCode, Path: redactPath(path)}
	}
	if IsLoginPage(body) {
		return body, errSessionLost
	}
	return body, nil
}

// FirmwareErrors maps the phone's upgrade result codes (from its own page script).
var FirmwareErrors = map[int]string{
	0: "success", -1: "IO failed", -2: "abnormal memory", -3: "logging failed", -4: "URL invalid",
	-5: "ROM invalid", -6: "device invalid", -7: "ROM version same as the phone's", -8: "OEM version different",
	-9: "tool invalid", -10: "magic invalid", -11: "ROM head format invalid", -12: "ROM head verify failed",
	-13: "ROM block verify failed", -14: "ROM block data invalid", -15: "calling overrun",
	-16: "ROM version lower than the phone's", -96: "get real ROM version error", -97: "upgrade create error",
	-98: "data stream error", -99: "not upgrade error", -100: "network error",
}

// AskUpgrade polls the phone's upgrade status once, the way the page does every 3 seconds.
// It returns the raw answer; an answer in the negative range is a failure code.
func (c *Client) AskUpgrade(ctx context.Context) (string, error) {
	return c.fetch(ctx, http.MethodGet, "/servlet?m=mod_upgrade&p=settings-upgrade&q=askUpgrade&checkupload=true&Rajax="+c.cacheBuster(), "")
}

// WaitFirmware polls until the phone answers again with the new version, or the timeout passes.
// The phone reboots during an upgrade, so connection errors are expected while it is down.
func (c *Client) WaitFirmware(ctx context.Context, want string, timeout time.Duration) (FirmwareState, error) {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return FirmwareState{}, fmt.Errorf("the phone did not answer with %s within %s", want, timeout)
		}
		select {
		case <-ctx.Done():
			return FirmwareState{}, ctx.Err()
		case <-time.After(10 * time.Second):
		}
		// The public login page carries the firmware version; no login needed.
		state, err := c.publicFirmware(ctx)
		if err == nil && state.Version == want {
			return state, nil
		}
	}
}

// publicFirmware reads the version from the login page, which needs no login.
func (c *Client) publicFirmware(ctx context.Context) (FirmwareState, error) {
	body, err := c.fetch(ctx, http.MethodGet, "/servlet?m=mod_listener&p=login&q=loginForm", "")
	if err != nil {
		return FirmwareState{}, err
	}
	id, ok := IdentifyLoginPage(body)
	if !ok || id.Firmware == "" {
		return FirmwareState{}, fmt.Errorf("%w: the login page has no firmware", ErrUnexpectedPage)
	}
	return FirmwareState{Version: id.Firmware, Model: id.Model}, nil
}
