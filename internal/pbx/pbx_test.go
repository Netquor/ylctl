package pbx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeServer(t *testing.T) {
	ok := map[string]string{
		"pbx.example.com":                        "https://pbx.example.com",
		"https://pbx.example.com/":               "https://pbx.example.com",
		"https://pbx.example.com:8443/some/path": "https://pbx.example.com:8443",
		"http://localhost:3000":                  "http://localhost:3000",
		"http://127.0.0.1:3000":                  "http://127.0.0.1:3000",
	}
	for in, want := range ok {
		if got, err := NormalizeServer(in, false); err != nil || got != want {
			t.Errorf("%q -> %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", "http://pbx.example.com", "ftp://x", "https://", "://x"} {
		if _, err := NormalizeServer(bad, false); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if got, err := NormalizeServer("http://10.0.0.5", true); err != nil || got != "http://10.0.0.5" {
		t.Errorf("--allow-http: %q %v", got, err)
	}
}

func fakeServer(t *testing.T, approveAfter int32) (*httptest.Server, *int32) {
	var polls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/cli/pair/start", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["client_name"] == "" {
			http.Error(w, "no name", 400)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(PairStart{DeviceCode: "dev-code-0123456789-abcdef", UserCode: "ABCD-EFGH", VerificationURI: "https://pbx/cli?code=ABCD-EFGH", ExpiresIn: 600, Interval: 1})
	})
	mux.HandleFunc("/auth/cli/pair/poll", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&polls, 1)
		if n < approveAfter {
			_ = json.NewEncoder(w).Encode(PairPoll{Status: "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(PairPoll{Status: "approved", Token: "nqk_test_token", Name: "cli-ylctl-ab12", ExpiresAt: "2027-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/api/v1/vault/secrets/device/805ec000000a/phone_admin/reveal", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nqk_test_token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(Secret{Username: "admin", Secret: "Correct-Horse-9"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func TestPairingClientFlow(t *testing.T) {
	srv, polls := fakeServer(t, 2)
	c := New(srv.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := c.StartPairing(ctx, "ylctl", "mac")
	if err != nil || p.UserCode != "ABCD-EFGH" {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := c.WaitForApproval(ctx, p, nil)
	if err != nil || r.Status != "approved" || r.Token != "nqk_test_token" {
		t.Fatalf("%+v %v", r, err)
	}
	if atomic.LoadInt32(polls) < 2 {
		t.Error("should have polled until approved")
	}
	c.Token = r.Token
	s, err := c.PhoneAdmin(ctx, "80:5E:C0:00:00:0A", "test")
	if err != nil || s.Secret != "Correct-Horse-9" || s.Username != "admin" {
		t.Fatalf("%+v %v", s, err)
	}
	c.Token = "wrong"
	if _, err := c.PhoneAdmin(ctx, "805ec000000a", ""); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong token must give the server's 401, got %v", err)
	}
}

func TestWaitStopsWhenCancelled(t *testing.T) {
	srv, _ := fakeServer(t, 1000)
	c := New(srv.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	p, _ := c.StartPairing(ctx, "ylctl", "")
	if _, err := c.WaitForApproval(ctx, p, nil); err == nil {
		t.Error("cancellation must end the wait")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hit int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hit, 1) }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, 302) }))
	defer srv.Close()
	c := New(srv.URL, "nqk_secret_token")
	if _, err := c.PhoneAdmin(context.Background(), "805ec000000a", ""); err == nil {
		t.Error("a redirect is an error, not something to follow with the token")
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Error("the token must never be sent to a redirect target")
	}
}

func TestLinkFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadLink(dir); err != ErrNotLinked {
		t.Fatalf("%v", err)
	}
	l := Link{Server: "https://pbx", KeyName: "cli-x", LinkedAt: "2026-11-07T00:00:00Z", ExpiresAt: "2026-11-08T00:00:00Z"}
	if err := SaveLink(dir, l); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLink(dir)
	if err != nil || got != l {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Expired(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)) || !got.Expired(time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)) {
		t.Error("expiry check")
	}
	if (Link{}).Expired(time.Now()) {
		t.Error("no expiry means never")
	}
	if err := ForgetLink(dir); err != nil {
		t.Fatal(err)
	}
	if err := ForgetLink(dir); err != nil {
		t.Errorf("forgetting twice is fine: %v", err)
	}
}

func TestDeviceByMACAndIssueURL(t *testing.T) {
	var rotated int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/provisioning/devices", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]Device{
			{ID: "d1", MAC: "805ec000000c", Status: "claimed"},
			{ID: "d2", MAC: "805ec000000a", Status: "unclaimed"},
		})
	})
	mux.HandleFunc("/api/v1/provisioning/devices/d1/rotate-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", 401)
			return
		}
		atomic.AddInt32(&rotated, 1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(Device{ID: "d1", ProvisionURL: "https://pbx/webhooks/provision/newtoken/", Token: "newtoken"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(srv.URL, "tok")
	ctx := context.Background()
	d, err := c.DeviceByMAC(ctx, "80:5E:C0:00:00:0C")
	if err != nil || d == nil || d.ID != "d1" || d.Status != "claimed" {
		t.Fatalf("%+v %v", d, err)
	}
	if d, err := c.DeviceByMAC(ctx, "00:00:00:00:00:01"); err != nil || d != nil {
		t.Fatalf("unknown MAC must be nil, nil: %+v %v", d, err)
	}
	iss, err := c.IssueDeviceURL(ctx, "d1")
	if err != nil || iss.ProvisionURL != "https://pbx/webhooks/provision/newtoken/" || atomic.LoadInt32(&rotated) != 1 {
		t.Fatalf("%+v %v", iss, err)
	}
	c.Token = "bad"
	if _, err := c.IssueDeviceURL(ctx, "d1"); err == nil {
		t.Error("a bad token must fail")
	}
}
