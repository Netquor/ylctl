package fakephone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Password returns the web password the phone accepts now (test inspection).
func (p *Phone) Password() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opts.Password
}

// securityPage is a small page with the fields of Security > Password, the
// phone's RSA key, the CSRF token and the logged-in user, as the real page has.
func securityPage(p *Phone) string {
	return `<!DOCTYPE html><html><head><title>Yealink T41S Phone</title></head><body>
<script>
var g_rsa_n = "` + strings.ToUpper(p.key.N.Text(16)) + `";
var g_rsa_e = "` + fmt.Sprintf("%06X", p.key.E) + `";
var g_phonetype = "T41S";
var g_strToken = "<token>";
var g_curruser = "` + p.opts.User + `";
</script>
<select class='item-width' name="mode" yltype="post" dvalue="" defvalue="" effect=""></select>
<input type="password" reg="RegMaxlen32" yltype="post" value="" dvalue="" name="editOldPassword" effect="forcesub"/>
<input type="password" reg="RegMaxlen32" yltype="post" value="" dvalue="" name="editNewPassword" effect="forcesub"/>
<input type="password" reg="RegMaxlen32" yltype="post" value="" dvalue="" name="editConfirmPassword" effect=""/>
</body></html>`
}

func (p *Phone) talking(w http.ResponseWriter, sess *session) {
	if sess == nil || !sess.authed {
		w.Write([]byte(p.loginForm()))
		return
	}
	switch {
	case p.TalkingJunk:
		w.Write([]byte("<html>no</html>"))
	case p.InCall:
		fmt.Fprint(w, `{"talking":"1"}`)
	default:
		fmt.Fprint(w, `{"talking":"0"}`)
	}
}

var reDefaultlike = regexp.MustCompile(`^[A-Za-z0-9_-]{6,32}$`)

// changePassword mirrors /servlet?m=mod_password&p=security&q=change: the CSRF
// token is checked, both password fields are really decrypted with the shared
// rsakey/rsaiv, the old password must match, and a change ends every session.
func (p *Phone) changePassword(w http.ResponseWriter, r *http.Request, q url.Values, sid string, sess *session) {
	if q.Get("p") != "security" || q.Get("q") != "change" || r.Method != http.MethodPost || r.ParseForm() != nil {
		http.NotFound(w, r)
		return
	}
	if sess == nil || !sess.authed {
		w.Write([]byte(p.loginForm()))
		return
	}
	f := r.PostForm
	if f.Get("token") != sess.token {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	p.PwAttempts++
	if p.PwWriteRejected {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	reply := func(code string) { fmt.Fprintf(w, `{"result":"%s"}`, code) }
	if f.Get("mode") != "admin" {
		reply("-1")
		return
	}
	oldPW, err1 := p.decryptField(f, "editOldPassword", sid)
	newPW, err2 := p.decryptField(f, "editNewPassword", sid)
	if err1 != nil || err2 != nil {
		reply("-4")
		return
	}
	if oldPW != p.opts.Password {
		reply("-2")
		return
	}
	if newPW == "admin" {
		reply("-5")
		return
	}
	if p.PwWeakRejected || !reDefaultlike.MatchString(newPW) {
		reply("-4")
		return
	}
	if p.PwDropBeforeApply {
		p.hangUp(w)
		return
	}
	if p.PwSilentNoApply {
		reply("0")
		return
	}
	p.opts.Password = newPW
	p.PwChanges++
	p.failures = 0
	if !p.PwKeepSessions {
		for _, s := range p.sessions {
			s.authed = false
		}
	}
	if p.PwVerifyFails {
		p.opts.Password = "\x00unreachable-password"
	}
	switch {
	case p.PwDropAfterChange:
		p.hangUp(w)
	case p.PwGarbageAnswer:
		w.Write([]byte("<html><body>done</body></html>"))
	default:
		reply("0")
	}
}

func (p *Phone) hangUp(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if conn, _, err := h.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// decryptField decrypts one password-type field of a form post: the AES key and
// IV are shared (rsakey, rsaiv), the plain text is "<random>;<session>;<value>".
func (p *Phone) decryptField(f url.Values, name, sid string) (string, error) {
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
		return "", err
	}
	iv, err := dec(f.Get("rsaiv"))
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(f.Get(name))
	if err != nil || len(ct) == 0 || len(ct)%16 != 0 {
		return "", fmt.Errorf("bad ciphertext")
	}
	blk, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	parts := strings.SplitN(strings.TrimRight(string(pt), "\x00"), ";", 3)
	if len(parts) != 3 || parts[1] != sid {
		return "", fmt.Errorf("session mismatch")
	}
	return parts[2], nil
}

// SetPassword changes the accepted web password directly (test setup).
func (p *Phone) SetPassword(pw string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts.Password = pw
}
