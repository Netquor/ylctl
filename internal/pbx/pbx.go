// Package pbx talks to the NQ Phone server this tool is linked to: pairing
// (a person approves the tool in the browser) and fetching a phone's admin
// password from the server's vault. It never prints or logs a token.
package pbx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is one linked (or linking) server.
type Client struct {
	Base  string // https://host, no path
	Token string // empty while linking
	HTTP  *http.Client
}

// NormalizeServer turns "pbx.example.com" or a full URL into scheme://host[:port].
// Plain http is refused unless allowHTTP is set or the host is this machine.
func NormalizeServer(raw string, allowHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("give the server address, like https://pbx.example.com")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a server address", raw)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("the server address must start with https://")
	}
	if u.Scheme == "http" && !allowHTTP {
		h := u.Hostname()
		if ip := net.ParseIP(h); !(h == "localhost" || (ip != nil && ip.IsLoopback())) {
			return "", errors.New("refusing plain http: the token would cross the network unencrypted (use https, or --allow-http on a trusted lab network)")
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// New builds a client.
func New(base, token string) *Client {
	return &Client{Base: base, Token: token, HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// APIError is an error answer from the server.
type APIError struct {
	Status int
	Msg    string
	Raw    string // the body, for the few callers that read structured errors (never contains a token)
}

func (e *APIError) Error() string { return fmt.Sprintf("server answered %d: %s", e.Status, e.Msg) }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ylctl")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return &APIError{res.StatusCode, clip(strings.TrimSpace(string(data))), string(data)}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("unexpected answer from the server: %w", err)
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// PairStart is the server's answer to a pairing request.
type PairStart struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// PairPoll is what the server says while the person decides.
type PairPoll struct {
	Status    string `json:"status"`
	Token     string `json:"token"`
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
}

// StartPairing asks to be linked.
func (c *Client) StartPairing(ctx context.Context, clientName, clientHost string) (PairStart, error) {
	var out PairStart
	err := c.do(ctx, "POST", "/auth/cli/pair/start", map[string]string{"client_name": clientName, "client_host": clientHost}, &out)
	return out, err
}

// Poll asks whether the person has decided.
func (c *Client) Poll(ctx context.Context, deviceCode string) (PairPoll, error) {
	var out PairPoll
	err := c.do(ctx, "POST", "/auth/cli/pair/poll", map[string]string{"device_code": deviceCode}, &out)
	return out, err
}

// WaitForApproval polls until the pairing is decided, expires, or ctx ends.
func (c *Client) WaitForApproval(ctx context.Context, p PairStart, tick func()) (PairPoll, error) {
	every := time.Duration(p.Interval) * time.Second
	if every < 2*time.Second {
		every = 2 * time.Second
	}
	deadline := time.Now().Add(time.Duration(p.ExpiresIn) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return PairPoll{}, ctx.Err()
		case <-time.After(every):
		}
		if time.Now().After(deadline) {
			return PairPoll{Status: "expired"}, nil
		}
		r, err := c.Poll(ctx, p.DeviceCode)
		var ae *APIError
		if err != nil && !(errors.As(err, &ae) && ae.Status >= 500) && !isTemporary(err) {
			return PairPoll{}, err
		}
		if err == nil && r.Status != "pending" {
			return r, nil
		}
		if tick != nil {
			tick()
		}
	}
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && (ne.Timeout() || ne.Temporary())
}

// Secret is a phone credential from the vault.
type Secret struct {
	Username      string `json:"username"`
	Secret        string `json:"secret"`
	PendingExists bool   `json:"pending_exists"`
}

// PhoneAdmin fetches the web admin login of the phone with this MAC.
func (c *Client) PhoneAdmin(ctx context.Context, mac, reason string) (Secret, error) {
	var out Secret
	m := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	err := c.do(ctx, "POST", "/api/v1/vault/secrets/device/"+url.PathEscape(m)+"/phone_admin/reveal", map[string]string{"reason": reason}, &out)
	return out, err
}

// VaultStatus is a cheap authenticated call that shows the link works.
func (c *Client) VaultStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, "GET", "/api/v1/vault/status", nil, &out)
	return out, err
}

// Device is a phone the server knows about (provisioning device list).
type Device struct {
	ID        string `json:"id"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Model     string `json:"model"`
	Status    string `json:"status"` // unclaimed | claimed | disabled
	Extension string `json:"extension"`
	LastIP    string `json:"last_ip"`
	// ProvisionURL and Token are set only on the answer to rotate-token and are shown once.
	ProvisionURL string `json:"provision_url,omitempty"`
	Token        string `json:"token,omitempty"`
}

// Devices lists the phones the server knows (up to 500), claimed and unclaimed.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out []Device
	err := c.do(ctx, "GET", "/api/v1/provisioning/devices?limit=500", nil, &out)
	return out, err
}

// ProvisioningSettings is the part of the server's provisioning settings recon needs.
type ProvisioningSettings struct {
	ServerURL    string `json:"server_url"`
	EnrollmentOn bool   `json:"enrollment_enabled"`
}

// ProvisioningSettings reads them.
func (c *Client) ProvisioningSettings(ctx context.Context) (ProvisioningSettings, error) {
	var out ProvisioningSettings
	err := c.do(ctx, "GET", "/api/v1/provisioning/settings", nil, &out)
	return out, err
}

// Enrollment is a link any phone can fetch its first configuration from.
type Enrollment struct {
	Token string `json:"token"`
	URL   string `json:"url"`
}

// NewEnrollment makes a new enrollment link. Any earlier link stops working.
func (c *Client) NewEnrollment(ctx context.Context) (Enrollment, error) {
	var out Enrollment
	err := c.do(ctx, "POST", "/api/v1/provisioning/enrollment-token", map[string]string{}, &out)
	return out, err
}

func macPath(mac string) string {
	m := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	return "/api/v1/vault/secrets/device/" + url.PathEscape(m) + "/phone_admin"
}

// Rotation is a proposed new value waiting in the vault.
type Rotation struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at"`
}

// ErrRotationPending means another rotation is already waiting for this phone.
type ErrRotationPending struct{ Rotation Rotation }

func (e *ErrRotationPending) Error() string {
	return "a password change for this phone is already waiting in the vault (id " + e.Rotation.ID + ")"
}

// BeginRotation stores the proposed new password as pending next to the current one.
func (c *Client) BeginRotation(ctx context.Context, mac, proposed, reason string) (Rotation, error) {
	var out struct {
		Rotation Rotation `json:"rotation"`
	}
	err := c.do(ctx, "POST", macPath(mac)+"/rotation", map[string]any{"secret": proposed, "reason": reason}, &out)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == 409 {
		var conflict struct {
			Rotation Rotation `json:"rotation"`
		}
		_ = json.Unmarshal([]byte(strings.TrimSpace(ae.Raw)), &conflict)
		return Rotation{}, &ErrRotationPending{conflict.Rotation}
	}
	return out.Rotation, err
}

// CommitRotation promotes the pending value to be the current one.
func (c *Client) CommitRotation(ctx context.Context, mac, id, reason string) error {
	return c.do(ctx, "POST", macPath(mac)+"/rotation/"+url.PathEscape(id)+"/commit", map[string]string{"reason": reason}, nil)
}

// AbortRotation drops the pending value.
func (c *Client) AbortRotation(ctx context.Context, mac, id, reason string) error {
	return c.do(ctx, "POST", macPath(mac)+"/rotation/"+url.PathEscape(id)+"/abort", map[string]string{"reason": reason}, nil)
}

// PendingSecret is the proposed value of an unfinished rotation.
type PendingSecret struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
	ID       string `json:"rotation_id"`
	State    string `json:"rotation_state"` // pending or expired
}

// PendingRotation reveals the proposed value of an unfinished rotation, for recovery.
func (c *Client) PendingRotation(ctx context.Context, mac, reason string) (PendingSecret, error) {
	var out PendingSecret
	err := c.do(ctx, "POST", macPath(mac)+"/reveal", map[string]string{"reason": reason, "which": "pending"}, &out)
	return out, err
}

// DeviceByMAC finds a phone the server knows by its MAC (any spelling). It returns nil, nil when the server does not know it.
func (c *Client) DeviceByMAC(ctx context.Context, mac string) (*Device, error) {
	want := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	ds, err := c.Devices(ctx)
	if err != nil {
		return nil, err
	}
	for i := range ds {
		if strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(ds[i].MAC)) == want {
			return &ds[i], nil
		}
	}
	return nil, nil
}

// IssueDeviceURL gives a claimed phone a NEW private provisioning URL (the old one stops working)
// and returns it once. The SIP password is not touched.
func (c *Client) IssueDeviceURL(ctx context.Context, deviceID string) (Device, error) {
	var out Device
	err := c.do(ctx, "POST", "/api/v1/provisioning/devices/"+url.PathEscape(deviceID)+"/rotate-token", map[string]bool{"rotate_secret": false}, &out)
	return out, err
}
