package fakephone

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	r, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestLoginRejectsGarbageAndPagesNeedLogin(t *testing.T) {
	p := New(Options{})
	defer p.Close()
	c := client()
	form := get(t, c, p.URL+"/servlet?m=mod_listener&p=login&q=loginForm")
	if !strings.Contains(form, "g_rsa_n") {
		t.Fatal("no login form")
	}
	// garbage "encrypted" password is not accepted
	r, err := c.PostForm(p.URL+"/servlet?m=mod_listener&p=login&q=login", url.Values{"username": {"admin"}, "pwd": {"YWRtaW4="}, "rsakey": {"00"}, "rsaiv": {"00"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(b), `"authstatus":"error"`) {
		t.Fatalf("%s", b)
	}
	// without login every data page is the login page
	if body := get(t, c, p.URL+"/servlet?m=mod_data&p=status&q=load"); !strings.Contains(body, "page_login.js") {
		t.Fatal("status served without login")
	}
}
