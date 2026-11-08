// Package fakephone is an httptest server that behaves like the web interface
// of a Yealink T4x phone: hybrid RSA+AES login that is really decrypted and
// verified, the status-first quirk, login lock, CSRF token and the settings
// write endpoints. Pages are served from sanitized fixtures captured from
// real phones.
package fakephone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed testdata/phoneB_66.85/* testdata/phoneA_66.86/*
var fixtures embed.FS

// Fixture returns a sanitized page captured from a real phone, e.g.
// Fixture(p.dir, "status.html").
func Fixture(dir, name string) string {
	b, err := fixtures.ReadFile("testdata/" + dir + "/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Options configure a fake phone.
type Options struct {
	User          string // default admin
	Password      string // default admin
	MaxFailures   int    // failed logins before lock; default 5
	NoStatusFirst bool   // disable the status-first quirk
	Plain         bool   // serve plain HTTP instead of TLS
	Variant       string // "B" (T41S 66.85.0.79, default) or "A" (T41S 66.86.0.15: PnP and DHCP option on, empty URL)
}

type session struct {
	authed bool
	landed bool
	token  string
}

// Phone is a running fake phone.
type Phone struct {
	*httptest.Server
	opts Options
	dir  string
	key  *rsa.PrivateKey

	mu       sync.Mutex
	cert     tls.Certificate
	sessions map[string]*session
	failures int
	locked   bool
	autop    map[string]string // overrides applied to the settings-autop fixture

	// Observations for tests.
	LoginAttempts int
	Logins        int
	Writes        []url.Values
	AutopNow      int
	PageLoads     map[string]int

	// Fault injection.
	DropSessions    int // next N page loads answer with the login page and invalidate the session
	AlwaysLoginPage bool
	TruncatePages   bool
	HugeBody        bool
	Junk            bool // answer everything with non-phone content
	RejectWrites    bool // acknowledge writes but do not apply them
	FailAutopNow    bool // answer autopnow with a failure

	// Password change (Security > Password) fault injection, see password.go.
	InCall            bool // the call-state endpoint says a call is active
	TalkingJunk       bool // the call-state endpoint answers something unreadable
	PwWriteRejected   bool // the change endpoint answers HTTP 500 and changes nothing
	PwWeakRejected    bool // the phone refuses any new password with result -4
	PwDropAfterChange bool // the phone applies the change, then closes the connection without answering
	PwDropBeforeApply bool // the phone closes the connection without answering and changes nothing
	PwSilentNoApply   bool // the phone answers result 0 but does not change anything
	PwVerifyFails     bool // the phone answers result 0 and changes, but then refuses logins with the new password
	PwKeepSessions    bool // do not end sessions after a change (real behaviour unknown)
	PwGarbageAnswer   bool // the phone applies the change and answers something unreadable
	PwChanges         int  // successful changes
	PwAttempts        int  // posts to the change endpoint that passed the token check
}

// New starts a fake phone. Call Close when done.
func New(o Options) *Phone {
	if o.User == "" {
		o.User = "admin"
	}
	if o.Password == "" {
		o.Password = "admin"
	}
	if o.MaxFailures == 0 {
		o.MaxFailures = 5
	}
	if o.Variant == "" {
		o.Variant = "B"
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	p := &Phone{dir: map[string]string{"A": "phoneA_66.86", "B": "phoneB_66.85"}[o.Variant], opts: o, key: key, sessions: map[string]*session{}, autop: map[string]string{}, PageLoads: map[string]int{}}
	p.cert = newCert()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(p.handle))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if o.Plain {
		srv.Start()
	} else {
		// GetConfigForClient (not GetCertificate) so that the swapped certificate is used even for IP-address clients.
		srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			return &tls.Config{Certificates: []tls.Certificate{p.cert}, NextProtos: []string{"http/1.1"}}, nil
		}}
		srv.StartTLS()
	}
	p.Server = srv
	return p
}

// SwapCertificate makes the phone present a different certificate from now on.
func (p *Phone) SwapCertificate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cert = newCert()
}

// Snapshot is a copy of the observation counters.
type Snapshot struct {
	LoginAttempts int
	Logins        int
	Writes        []url.Values
	AutopNow      int
	PageLoads     map[string]int
}

// Snapshot returns the counters under lock.
func (p *Phone) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Snapshot{LoginAttempts: p.LoginAttempts, Logins: p.Logins, AutopNow: p.AutopNow, PageLoads: map[string]int{}}
	s.Writes = append(s.Writes, p.Writes...)
	for k, v := range p.PageLoads {
		s.PageLoads[k] = v
	}
	return s
}

// Do runs fn with the phone's lock held; use it to switch fault injection on and off.
func (p *Phone) Do(fn func(p *Phone)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

// Locked reports whether the web login is locked.
func (p *Phone) Locked() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.locked
}

// Autop returns the current value of an AutoProvision field as the phone would show it.
func (p *Phone) Autop(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fieldValue(p.autopPage(), name)
}

// SetAutop changes a field directly (test setup).
func (p *Phone) SetAutop(name, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.autop[name] = value
}

func newCert() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "fake-yealink"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

var (
	reRSAN = regexp.MustCompile(`(var g_rsa_n = ")[0-9A-Fa-f]+(")`)
	reRSAE = regexp.MustCompile(`(var g_rsa_e = ")[0-9A-Fa-f]+(")`)
)

func (p *Phone) loginForm() string {
	f := Fixture(p.dir, "loginform.html")
	f = reRSAN.ReplaceAllString(f, "${1}"+strings.ToUpper(p.key.N.Text(16))+"${2}")
	f = reRSAE.ReplaceAllString(f, "${1}"+fmt.Sprintf("%06X", p.key.E)+"${2}")
	return f
}

func (p *Phone) handle(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Junk {
		w.Write([]byte("<html><body>hello</body></html>"))
		return
	}
	if p.HugeBody {
		w.Write([]byte(strings.Repeat("A", 8<<20)))
		return
	}
	q := r.URL.Query()
	if r.URL.Path != "/servlet" {
		http.NotFound(w, r)
		return
	}
	sid, sess := p.sessionFor(r)
	switch q.Get("m") {
	case "mod_listener":
		if q.Get("q") == "loginForm" {
			if sess == nil {
				sid, sess = newSession()
				p.sessions[sid] = sess
			}
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: sid, Path: "/"})
			w.Write([]byte(p.loginForm()))
			return
		}
		if q.Get("q") == "login" {
			p.login(w, r, sid, sess)
			return
		}
	case "mod_data":
		p.data(w, r, q, sess)
		return
	case "mod_webd":
		if q.Get("p") == "talking" {
			p.talking(w, sess)
			return
		}
	case "mod_password":
		p.changePassword(w, r, q, sid, sess)
		return
	}
	http.NotFound(w, r)
}

func newSession() (string, *session) {
	b := make([]byte, 16)
	rand.Read(b)
	t := make([]byte, 9)
	rand.Read(t)
	return strings.ToUpper(hex.EncodeToString(b)), &session{token: hex.EncodeToString(t)}
}

func (p *Phone) sessionFor(r *http.Request) (string, *session) {
	c, err := r.Cookie("JSESSIONID")
	if err != nil {
		return "", nil
	}
	s := p.sessions[c.Value]
	return c.Value, s
}

func (p *Phone) login(w http.ResponseWriter, r *http.Request, sid string, sess *session) {
	p.LoginAttempts++
	reply := func(s string) {
		fmt.Fprintf(w, `<html><body><div id="_RES_INFO_" style="display:none;">%s</div></body></html>`, s)
	}
	if p.locked {
		reply(`{"authstatus":"lock"}`)
		return
	}
	if sess == nil || r.ParseForm() != nil {
		reply(`{"authstatus":"error","errorno":"-3"}`)
		return
	}
	user, pw, err := p.decrypt(r.PostForm, sid)
	if err != nil || user != p.opts.User || pw != p.opts.Password {
		p.failures++
		if p.failures >= p.opts.MaxFailures {
			p.locked = true
			reply(`{"authstatus":"lock"}`)
			return
		}
		reply(`{"authstatus":"error","errorno":"-3"}`)
		return
	}
	p.failures = 0
	p.Logins++
	sess.authed, sess.landed = true, false
	reply(`{"authstatus":"done"}`)
}

// decrypt verifies the hybrid scheme exactly as a real phone has to.
func (p *Phone) decrypt(f url.Values, sid string) (user, password string, err error) {
	user = f.Get("username")
	dec := func(hexs string) ([]byte, error) {
		raw, err := hex.DecodeString(hexs)
		if err != nil {
			return nil, err
		}
		pt, err := rsa.DecryptPKCS1v15(rand.Reader, p.key, raw)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(string(pt))
		if err != nil || len(b) != 16 {
			return nil, fmt.Errorf("bad key material")
		}
		return b, nil
	}
	key, err := dec(f.Get("rsakey"))
	if err != nil {
		return
	}
	iv, err := dec(f.Get("rsaiv"))
	if err != nil {
		return
	}
	ct, err := base64.StdEncoding.DecodeString(f.Get("pwd"))
	if err != nil || len(ct) == 0 || len(ct)%16 != 0 {
		return "", "", fmt.Errorf("bad ciphertext")
	}
	blk, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	s := strings.TrimRight(string(pt), "\x00")
	parts := strings.SplitN(s, ";", 3)
	if len(parts) != 3 || parts[1] != sid {
		return "", "", fmt.Errorf("session mismatch")
	}
	return user, parts[2], nil
}

func (p *Phone) data(w http.ResponseWriter, r *http.Request, q url.Values, sess *session) {
	loginPage := func() {
		w.Write([]byte(strings.Replace(p.loginForm(), `{"authstatus":"none"}`, `{"authstatus":"none"}`, 1)))
	}
	if sess == nil || !sess.authed || p.AlwaysLoginPage {
		loginPage()
		return
	}
	page := q.Get("p")
	if q.Get("q") == "load" {
		if p.DropSessions > 0 {
			p.DropSessions--
			sess.authed = false
			loginPage()
			return
		}
		if page != "status" && !sess.landed && !p.opts.NoStatusFirst {
			loginPage()
			return
		}
		var body string
		switch page {
		case "status":
			sess.landed = true
			body = Fixture(p.dir, "status.html")
		case "settings-autop":
			body = p.autopPage()
		case "account-register":
			body = Fixture(p.dir, "account-register.html")
		case "security":
			body = securityPage(p)
		default:
			http.NotFound(w, r)
			return
		}
		p.PageLoads[page]++
		body = strings.ReplaceAll(body, `g_strToken = "<token>"`, `g_strToken = "`+sess.token+`"`)
		if p.TruncatePages {
			body = body[:len(body)/2]
		}
		w.Write([]byte(body))
		return
	}
	// POST endpoints
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("token") != sess.token {
		http.Error(w, "Forbidden", http.StatusForbidden) // what the real phone does
		return
	}
	switch {
	case page == "settings-autop" && q.Get("q") == "autopnow":
		if p.FailAutopNow {
			fmt.Fprint(w, `{"ret":"fail"}`)
			return
		}
		p.AutopNow++
		fmt.Fprint(w, `{"ret":"ok","data":"6"}`)
	case page == "settings-autop" && q.Get("q") == "write":
		p.Writes = append(p.Writes, r.PostForm)
		if !p.RejectWrites {
			for k, v := range r.PostForm {
				if strings.HasPrefix(k, "AutoProvision") {
					p.autop[k] = v[0]
				}
			}
		}
		fmt.Fprint(w, "<html>\n<body>\n\t<div id=\"_RES_INFO_\"></div>\n</body>\n</html>")
	default:
		http.NotFound(w, r)
	}
}

var (
	reInputTag = regexp.MustCompile(`(?is)<input\b(?:[^>"']|"[^"]*"|'[^']*')*>`)
	reDValue   = regexp.MustCompile(`dvalue="[^"]*"`)
	reValue    = regexp.MustCompile(`(\s)value="[^"]*"`)
)

func (p *Phone) autopPage() string {
	page := Fixture(p.dir, "settings-autop.html")
	for name, val := range p.autop {
		page = setField(page, name, val)
	}
	return page
}

func setField(page, name, val string) string {
	needle := `name="` + name + `"`
	return reInputTag.ReplaceAllStringFunc(page, func(tag string) string {
		if !strings.Contains(tag, needle) {
			return tag
		}
		tag = reDValue.ReplaceAllLiteralString(tag, `dvalue="`+val+`"`)
		if !strings.Contains(tag, `type="radio"`) {
			tag = reValue.ReplaceAllStringFunc(tag, func(m string) string { return m[:1] + `value="` + val + `"` })
		}
		return tag
	})
}

func fieldValue(page, name string) string {
	needle := `name="` + name + `"`
	for _, tag := range reInputTag.FindAllString(page, -1) {
		if strings.Contains(tag, needle) {
			if m := regexp.MustCompile(`dvalue="([^"]*)"`).FindStringSubmatch(tag); m != nil {
				return m[1]
			}
		}
	}
	return ""
}
