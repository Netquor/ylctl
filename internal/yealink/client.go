package yealink

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBody bounds every response (the real pages are about 40 KiB).
const DefaultMaxBody = 4 << 20

// Options configure a Client.
type Options struct {
	Timeout  time.Duration // per request, default 10s
	Pins     *PinStore     // trust-on-first-use store; nil means every certificate is refused unless Insecure
	TrustNew bool          // pin unknown certificates without asking
	Insecure bool          // skip certificate checks entirely (explicit escape hatch)
	Confirm  func(host, fingerprint string) bool
	MaxBody  int64
	Rand     *rand.Rand // for Rajax cache busters only
}

// Client talks to the web interface of one phone.
type Client struct {
	t           Target
	o           Options
	hc          *http.Client
	jar         http.CookieJar
	user        string
	pass        string
	loggedIn    bool
	relogged    bool
	firstStatus string
	rsaPub      *rsa.PublicKey // the phone's login key, kept for the encrypted upload size parameter

	mu      sync.Mutex
	certFP  string
	decided map[string]bool
}

// New prepares a Client. It does not contact the phone.
func New(target string, o Options) (*Client, error) {
	t, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	c := &Client{t: t, o: o, decided: map[string]bool{}}
	c.hc = &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: o.Timeout,
			TLSClientConfig: &tls.Config{
				// Verification is done by verifyCert (pinned fingerprint), not by a CA chain.
				InsecureSkipVerify:    true, //nolint:gosec // see verifyCert
				VerifyPeerCertificate: c.verifyCert,
				MinVersion:            tls.VersionTLS10,
				CipherSuites:          phoneCipherSuites(),
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	c.resetJar()
	return c, nil
}

func (c *Client) resetJar() {
	c.jar, _ = cookiejar.New(nil)
	c.hc.Jar = c.jar
}

// Target returns the parsed address.
func (c *Client) Target() Target { return c.t }

// CertFingerprint is the SHA-256 of the certificate seen on the last handshake.
func (c *Client) CertFingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.certFP
}

func (c *Client) verifyCert(raw [][]byte, _ [][]*x509.Certificate) error {
	if len(raw) == 0 {
		return errors.New("phone presented no certificate")
	}
	fp := Fingerprint(raw[0])
	c.mu.Lock()
	c.certFP = fp
	c.mu.Unlock()
	if c.o.Insecure {
		return nil
	}
	key := c.t.HostPort()
	if c.o.Pins != nil {
		if p, ok := c.o.Pins.Get(key); ok {
			if p.SHA256 != fp {
				return &CertChangedError{Host: key, Pinned: p.SHA256, Presented: fp}
			}
			return nil
		}
	}
	c.mu.Lock()
	ok, asked := c.decided[fp]
	c.mu.Unlock()
	if !asked {
		ok = c.o.TrustNew
		if !ok && c.o.Confirm != nil {
			ok = c.o.Confirm(key, fp)
		}
		c.mu.Lock()
		c.decided[fp] = ok
		c.mu.Unlock()
		if ok && c.o.Pins != nil {
			if err := c.o.Pins.Add(key, fp); err != nil {
				return fmt.Errorf("cannot save pin: %w", err)
			}
		}
	}
	if !ok {
		return &UntrustedError{Host: key, Fingerprint: fp}
	}
	return nil
}

func (c *Client) cacheBuster() string {
	if c.o.Rand != nil {
		return strconv.FormatFloat(c.o.Rand.Float64(), 'f', 16, 64)
	}
	return strconv.FormatFloat(rand.Float64(), 'f', 16, 64) //nolint:gosec // cache buster only
}

// fetch performs one request and returns the bounded body.
func (c *Client) fetch(ctx context.Context, method, path, body string) (string, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.t.BaseURL()+path, rd)
	if err != nil {
		return "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "ylctl")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.o.MaxBody+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > c.o.MaxBody {
		return "", ErrTooLarge
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return string(b), errSessionLost
		}
		return string(b), &HTTPError{Status: resp.StatusCode, Path: redactPath(path)}
	}
	return string(b), nil
}

func redactPath(p string) string {
	if i := strings.Index(p, "&Rajax="); i >= 0 {
		return p[:i]
	}
	return p
}

func (c *Client) sessionID() string {
	u, _ := url.Parse(c.t.BaseURL())
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == "JSESSIONID" {
			return ck.Value
		}
	}
	return ""
}

// loginResult is the JSON in the login answer.
type loginResult struct {
	AuthStatus string `json:"authstatus"`
	ErrorNo    string `json:"errorno"`
}

// Login performs exactly one login attempt and then lands on the status page
// (the phone answers other pages with the login page until it has).
// Wrong passwords are never retried.
func (c *Client) Login(ctx context.Context, user, pass string) error {
	c.user, c.pass, c.loggedIn, c.firstStatus = user, pass, false, ""
	c.resetJar()
	form, err := c.fetch(ctx, http.MethodGet, "/servlet?m=mod_listener&p=login&q=loginForm", "")
	if err != nil {
		return err
	}
	if _, ok := IdentifyLoginPage(form); !ok {
		return ErrNotYealink
	}
	v := JSVars(form)
	pub, err := ParseRSAKey(v["g_rsa_n"], v["g_rsa_e"])
	if err != nil {
		return err
	}
	c.rsaPub = pub
	// Two login flows, chosen from the login form itself (no password is sent to decide):
	//   legacy (66.85, 66.86.0.15): the form sets JSESSIONID; the password travels inside an
	//   encrypted blob that includes the session id, with rsakey and rsaiv.
	//   post-login (66.86.0.180): the form sets no cookie; the password is only RSA-encrypted,
	//   and the server sets JSESSIONID in its answer to the login POST.
	var body string
	if sid := c.sessionID(); sid != "" {
		sec, err := EncryptLogin(pub, sid, pass, nil)
		if err != nil {
			return err
		}
		body = "username=" + url.QueryEscape(user) + "&pwd=" + url.QueryEscape(sec.Pwd) +
			"&rsakey=" + url.QueryEscape(sec.RSAKey) + "&rsaiv=" + url.QueryEscape(sec.RSAIV)
	} else {
		enc, err := rsa.EncryptPKCS1v15(crand.Reader, pub, []byte(pass))
		if err != nil {
			return fmt.Errorf("rsa: %w", err)
		}
		body = "username=" + url.QueryEscape(user) + "&pwd=" + url.QueryEscape(hex.EncodeToString(enc))
	}
	res, err := c.fetch(ctx, http.MethodPost, "/servlet?m=mod_listener&p=login&q=login", body)
	if err != nil {
		var he *HTTPError
		if errors.As(err, &he) && he.Status == http.StatusForbidden {
			return fmt.Errorf("%w (HTTP 403)", ErrLocked)
		}
		return err
	}
	info, ok := ParseResInfo(res)
	if !ok {
		info = strings.TrimSpace(res)
	}
	var lr loginResult
	if err := json.Unmarshal([]byte(info), &lr); err != nil {
		return fmt.Errorf("%w: login answer is not JSON", ErrUnexpectedPage)
	}
	switch lr.AuthStatus {
	case "done":
	case "lock":
		return ErrLocked
	default:
		if lr.ErrorNo != "" {
			return fmt.Errorf("%w (phone code %s)", ErrAuthFailed, lr.ErrorNo)
		}
		return ErrAuthFailed
	}
	c.loggedIn = true
	page, err := c.loadRaw(ctx, "status", "")
	if err != nil {
		if errors.Is(err, errSessionLost) {
			return ErrSessionLost
		}
		return err
	}
	c.firstStatus = page
	return nil
}

// loadRaw loads a mod_data page and checks that it is a complete phone page.
func (c *Client) loadRaw(ctx context.Context, page, extra string) (string, error) {
	path := "/servlet?m=mod_data&p=" + url.QueryEscape(page) + "&q=load" + extra + "&Rajax=" + c.cacheBuster()
	body, err := c.fetch(ctx, http.MethodGet, path, "")
	if err != nil {
		return "", err
	}
	if IsLoginPage(body) {
		return "", errSessionLost
	}
	if !strings.Contains(strings.ToLower(body[max(0, len(body)-64):]), "</html>") {
		return "", ErrTruncated
	}
	return body, nil
}

// withSession runs fn; if the phone answered with its login page, it logs in
// once more (one re-login per Client) and runs fn again.
func (c *Client) withSession(ctx context.Context, fn func() error) error {
	if !c.loggedIn {
		return errors.New("not logged in")
	}
	err := fn()
	if !errors.Is(err, errSessionLost) {
		return err
	}
	if c.relogged || c.user == "" {
		return ErrSessionLost
	}
	c.relogged = true
	if err := c.Login(ctx, c.user, c.pass); err != nil {
		return fmt.Errorf("re-login after session loss: %w", err)
	}
	if err := fn(); err != nil {
		if errors.Is(err, errSessionLost) {
			return ErrSessionLost
		}
		return err
	}
	return nil
}

func (c *Client) load(ctx context.Context, page, extra string) (string, error) {
	var out string
	err := c.withSession(ctx, func() error {
		if page == "status" && c.firstStatus != "" {
			out, c.firstStatus = c.firstStatus, ""
			return nil
		}
		var err error
		out, err = c.loadRaw(ctx, page, extra)
		return err
	})
	return out, err
}

// Status reads the status page.
func (c *Client) Status(ctx context.Context) (*StatusPage, error) {
	p, err := c.load(ctx, "status", "")
	if err != nil {
		return nil, err
	}
	return ParseStatus(p)
}

// Autop reads the Auto Provision settings.
func (c *Client) Autop(ctx context.Context) (*Autop, error) {
	p, err := c.load(ctx, "settings-autop", "")
	if err != nil {
		return nil, err
	}
	return ParseAutop(p)
}

// Account reads the Register page of account n (1-based).
func (c *Client) Account(ctx context.Context, n int) (*Account, error) {
	if n < 1 || n > 16 {
		return nil, fmt.Errorf("account must be between 1 and 16")
	}
	p, err := c.load(ctx, "account-register", "&acc="+strconv.Itoa(n-1))
	if err != nil {
		return nil, err
	}
	return ParseAccount(p, n)
}

// ProvisionNow triggers "Auto Provision Now".
func (c *Client) ProvisionNow(ctx context.Context) error {
	return c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-autop", "")
		if err != nil {
			return err
		}
		tok, ok := ParseToken(page)
		if !ok {
			return fmt.Errorf("%w: no CSRF token", ErrUnexpectedPage)
		}
		path := "/servlet?m=mod_data&p=settings-autop&q=autopnow&Rajax=" + c.cacheBuster()
		res, err := c.fetch(ctx, http.MethodPost, path, "token="+url.QueryEscape(tok))
		if err != nil {
			return writeErr(err)
		}
		if IsLoginPage(res) {
			return errSessionLost
		}
		if !ackOK(res) {
			return fmt.Errorf("%w: autopnow answered %q", ErrWriteRejected, clip(res))
		}
		return nil
	})
}

// Reboot restarts the phone, the way the web interface's Reboot does it (POST servlet?m=mod_upgrade&q=reboot).
// It refuses while a call is in progress unless force is set. The phone starts going down while it answers, so
// a cut connection counts as success.
func (c *Client) Reboot(ctx context.Context, force bool) error {
	if !force {
		busy, err := c.Talking(ctx)
		if err != nil {
			return fmt.Errorf("could not tell whether a call is active, so not rebooting (--force skips the check): %w", err)
		}
		if busy {
			return errors.New("the phone has a call in progress; not rebooting (--force to do it anyway)")
		}
	}
	return c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-upgrade", "")
		if err != nil {
			return err
		}
		tok, _ := ParseToken(page)
		path := "/servlet?m=mod_upgrade&q=reboot"
		if force {
			path += "&forcereboot=true"
		}
		body := ""
		if tok != "" {
			body = "token=" + url.QueryEscape(tok)
		}
		res, err := c.fetch(ctx, http.MethodPost, path+"&Rajax="+c.cacheBuster(), body)
		if err != nil {
			if isConnCut(err) {
				return nil
			}
			return writeErr(err)
		}
		if IsLoginPage(res) {
			return errSessionLost
		}
		return nil
	})
}

func isConnCut(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "eof") || strings.Contains(m, "connection reset") || strings.Contains(m, "broken pipe")
}

// ackOK understands {"ret":"ok"} (any case), also inside _RES_INFO_.
func ackOK(body string) bool {
	s := strings.TrimSpace(body)
	if v, ok := ParseResInfo(body); ok {
		s = v
	}
	var o map[string]any
	if json.Unmarshal([]byte(s), &o) == nil {
		if r, _ := o["ret"].(string); strings.EqualFold(r, "ok") {
			return true
		}
	}
	return strings.EqualFold(s, "ok")
}

// writeErr explains the phone's HTTP 403 answer to a POST with a bad CSRF token.
func writeErr(err error) error {
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusForbidden {
		return fmt.Errorf("%w: HTTP 403 (the phone rejected the CSRF token)", ErrWriteRejected)
	}
	return err
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

var fieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// WriteResult describes a settings write.
type WriteResult struct {
	Response string // the phone's answer, clipped
}

// WriteAutop posts the given AutoProvision* fields to settings-autop and
// verifies by re-reading the page. Like the web UI, it sends the CSRF token
// and only the fields given. Secret fields are refused.
func (c *Client) WriteAutop(ctx context.Context, set map[string]string) (*WriteResult, error) {
	if len(set) == 0 {
		return nil, errors.New("nothing to write")
	}
	names := make([]string, 0, len(set))
	for n := range set {
		if !fieldName.MatchString(n) || !strings.HasPrefix(n, "AutoProvision") {
			return nil, fmt.Errorf("refusing to write field %q", n)
		}
		if IsSecretName(n) {
			return nil, fmt.Errorf("refusing to write secret field %q", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	res := &WriteResult{}
	err := c.withSession(ctx, func() error {
		page, err := c.loadRaw(ctx, "settings-autop", "")
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
		path := "/servlet?m=mod_data&p=settings-autop&q=write&Rajax=" + c.cacheBuster()
		out, err := c.fetch(ctx, http.MethodPost, path, b.String())
		if err != nil {
			return writeErr(err)
		}
		if IsLoginPage(out) {
			return errSessionLost
		}
		res.Response = clip(out)
		return nil
	})
	if err != nil {
		return nil, err
	}
	after, err := c.Autop(ctx)
	if err != nil {
		return res, fmt.Errorf("written, but verification failed: %w", err)
	}
	for _, n := range names {
		if got, _ := after.Get(n); got != set[n] {
			return res, fmt.Errorf("%w: %s is %q after the write, wanted %q (answer: %s)", ErrWriteRejected, n, Display(n, got, false), Display(n, set[n], false), res.Response)
		}
	}
	return res, nil
}

// Get performs an authenticated GET of a path on the phone (for read-only
// pages and exports). It never sends a body. Use Post-style helpers for writes.
func (c *Client) Get(ctx context.Context, path string) (string, error) {
	var out string
	err := c.withSession(ctx, func() error {
		var err error
		out, err = c.fetch(ctx, http.MethodGet, path, "")
		if err == nil && IsLoginPage(out) {
			return errSessionLost
		}
		return err
	})
	return out, err
}
