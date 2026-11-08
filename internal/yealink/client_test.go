package yealink_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Netquor/ylctl/internal/fakephone"
	"github.com/Netquor/ylctl/internal/yealink"
)

func newClient(t *testing.T, p *fakephone.Phone, o yealink.Options) *yealink.Client {
	t.Helper()
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Pins == nil && !o.Insecure {
		ps, err := yealink.OpenPinStore(filepath.Join(t.TempDir(), "pins.json"))
		if err != nil {
			t.Fatal(err)
		}
		o.Pins = ps
		o.TrustNew = true
	}
	c, err := yealink.New(p.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loggedIn(t *testing.T, p *fakephone.Phone) *yealink.Client {
	t.Helper()
	c := newClient(t, p, yealink.Options{})
	if err := c.Login(context.Background(), "admin", "admin"); err != nil {
		t.Fatalf("login: %v", err)
	}
	return c
}

func TestLoginVerifiesHybridCrypto(t *testing.T) {
	p := fakephone.New(fakephone.Options{Password: "s3cret;with;semicolons"})
	defer p.Close()
	c := newClient(t, p, yealink.Options{})
	if err := c.Login(context.Background(), "admin", "s3cret;with;semicolons"); err != nil {
		t.Fatalf("a correct password must be accepted by a server that really decrypts it: %v", err)
	}
	s := p.Snapshot()
	if s.Logins != 1 || s.LoginAttempts != 1 {
		t.Fatalf("logins=%d attempts=%d", s.Logins, s.LoginAttempts)
	}
	if s.PageLoads["status"] != 1 {
		t.Fatalf("status must be loaded first (quirk): %v", s.PageLoads)
	}
}

func TestWrongPasswordIsNotRetried(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := newClient(t, p, yealink.Options{})
	err := c.Login(context.Background(), "admin", "nope")
	if !errors.Is(err, yealink.ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
	if n := p.Snapshot().LoginAttempts; n != 1 {
		t.Fatalf("exactly one attempt expected, got %d", n)
	}
}

func TestLockIsReportedAndStops(t *testing.T) {
	p := fakephone.New(fakephone.Options{MaxFailures: 2})
	defer p.Close()
	c := newClient(t, p, yealink.Options{})
	if err := c.Login(context.Background(), "admin", "x"); !errors.Is(err, yealink.ErrAuthFailed) {
		t.Fatalf("first: %v", err)
	}
	if err := c.Login(context.Background(), "admin", "x"); !errors.Is(err, yealink.ErrLocked) {
		t.Fatalf("second should report the lock: %v", err)
	}
	if !p.Locked() {
		t.Fatal("phone should be locked")
	}
	// even the right password is refused by a locked phone, and the client says so
	if err := c.Login(context.Background(), "admin", "admin"); !errors.Is(err, yealink.ErrLocked) {
		t.Fatalf("third: %v", err)
	}
}

func TestReadPages(t *testing.T) {
	for _, tc := range []struct {
		variant, fw, mac, user, pnp, dhcp string
	}{
		{"B", "66.85.0.79", "80:5E:C0:00:00:0B", "1004", "0", "0"},
		{"A", "66.86.0.15", "80:5E:C0:00:00:0A", "1002", "1", "1"},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			p := fakephone.New(fakephone.Options{Variant: tc.variant})
			defer p.Close()
			c := loggedIn(t, p)
			ctx := context.Background()
			st, err := c.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if st.Info.Firmware != tc.fw || st.Info.MAC != tc.mac || st.Info.Model != "T41S" {
				t.Fatalf("info %+v", st.Info)
			}
			if len(st.Accounts) == 0 || st.Accounts[0].State.Name != "registered" || st.Accounts[0].Label[:4] != tc.user {
				t.Fatalf("accounts %+v", st.Accounts)
			}
			ap, err := c.Autop(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := ap.Get(yealink.FieldEnablePNP); v != tc.pnp {
				t.Fatalf("pnp %q", v)
			}
			if v, _ := ap.Get(yealink.FieldEnableDHCP); v != tc.dhcp {
				t.Fatalf("dhcp %q", v)
			}
			acc, err := c.Account(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			if acc.Label != tc.user || acc.Password != yealink.Masked || acc.Servers[0].Transport != "TLS" || acc.Servers[0].Port != "5061" {
				t.Fatalf("account %+v", acc)
			}
		})
	}
}

func TestSessionLostRelogsInOnce(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	p.Do(func(p *fakephone.Phone) { p.DropSessions = 1 })
	if _, err := c.Autop(context.Background()); err != nil {
		t.Fatalf("one dropped session must be healed by one re-login: %v", err)
	}
	if n := p.Snapshot().Logins; n != 2 {
		t.Fatalf("logins %d", n)
	}
	// a second loss in the same run is not healed again
	p.Do(func(p *fakephone.Phone) { p.DropSessions = 1 })
	if _, err := c.Autop(context.Background()); !errors.Is(err, yealink.ErrSessionLost) {
		t.Fatalf("got %v", err)
	}
}

func TestSessionLostTwiceInARow(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	p.Do(func(p *fakephone.Phone) { p.DropSessions = 2 })
	if _, err := c.Autop(context.Background()); !errors.Is(err, yealink.ErrSessionLost) {
		t.Fatalf("got %v", err)
	}
}

func TestAlwaysLoginPage(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	p.Do(func(p *fakephone.Phone) { p.AlwaysLoginPage = true })
	c := newClient(t, p, yealink.Options{})
	if err := c.Login(context.Background(), "admin", "admin"); !errors.Is(err, yealink.ErrSessionLost) {
		t.Fatalf("got %v", err)
	}
}

func TestBadBodies(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		p := fakephone.New(fakephone.Options{})
		defer p.Close()
		c := loggedIn(t, p)
		p.Do(func(p *fakephone.Phone) { p.TruncatePages = true })
		if _, err := c.Autop(context.Background()); !errors.Is(err, yealink.ErrTruncated) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("huge", func(t *testing.T) {
		p := fakephone.New(fakephone.Options{})
		defer p.Close()
		p.Do(func(p *fakephone.Phone) { p.HugeBody = true })
		c := newClient(t, p, yealink.Options{MaxBody: 1 << 20})
		if err := c.Login(context.Background(), "admin", "admin"); !errors.Is(err, yealink.ErrTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("not a phone", func(t *testing.T) {
		p := fakephone.New(fakephone.Options{})
		defer p.Close()
		p.Do(func(p *fakephone.Phone) { p.Junk = true })
		c := newClient(t, p, yealink.Options{})
		if err := c.Login(context.Background(), "admin", "admin"); !errors.Is(err, yealink.ErrNotYealink) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCertificatePinning(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	path := filepath.Join(t.TempDir(), "sub", "known_phones.json")
	ctx := context.Background()

	open := func() *yealink.PinStore {
		ps, err := yealink.OpenPinStore(path)
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	// unknown certificate without --trust-new and without a prompt: refused
	c, _ := yealink.New(p.URL, yealink.Options{Pins: open()})
	var ue *yealink.UntrustedError
	if err := c.Login(ctx, "admin", "admin"); !errors.As(err, &ue) {
		t.Fatalf("want UntrustedError, got %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing should have been pinned")
	}
	// a prompt that says no
	c, _ = yealink.New(p.URL, yealink.Options{Pins: open(), Confirm: func(string, string) bool { return false }})
	if err := c.Login(ctx, "admin", "admin"); !errors.As(err, &ue) {
		t.Fatalf("want UntrustedError, got %v", err)
	}
	// a prompt that says yes pins it
	c, _ = yealink.New(p.URL, yealink.Options{Pins: open(), Confirm: func(string, string) bool { return true }})
	if err := c.Login(ctx, "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("pin file mode %v err %v", fi, err)
		}
	}
	// later runs need no flag
	c, _ = yealink.New(p.URL, yealink.Options{Pins: open()})
	if err := c.Login(ctx, "admin", "admin"); err != nil {
		t.Fatalf("pinned certificate must be accepted: %v", err)
	}
	// the certificate changes: hard error, even with --trust-new
	p.SwapCertificate()
	var ce *yealink.CertChangedError
	c, _ = yealink.New(p.URL, yealink.Options{Pins: open(), TrustNew: true})
	if err := c.Login(ctx, "admin", "admin"); !errors.As(err, &ce) {
		t.Fatalf("want CertChangedError, got %v", err)
	}
	if p.Snapshot().LoginAttempts != 2 {
		t.Fatal("no credentials may be sent to a phone whose certificate changed")
	}
	// the explicit escape hatch still works
	c, _ = yealink.New(p.URL, yealink.Options{Insecure: true})
	if err := c.Login(ctx, "admin", "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAutopAndVerify(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	ctx := context.Background()
	if _, err := c.WriteAutop(ctx, map[string]string{yealink.FieldRepeatMinutes: "61"}); err != nil {
		t.Fatal(err)
	}
	if got := p.Autop(yealink.FieldRepeatMinutes); got != "61" {
		t.Fatalf("phone has %q", got)
	}
	w := p.Snapshot().Writes
	if len(w) != 1 || w[0].Get("token") == "" || w[0].Get(yealink.FieldRepeatMinutes) != "61" || len(w[0]) != 2 {
		t.Fatalf("unexpected write body %v", w)
	}
	if _, err := c.WriteAutop(ctx, map[string]string{yealink.FieldRepeatMinutes: "60"}); err != nil {
		t.Fatal(err)
	}
	if got := p.Autop(yealink.FieldRepeatMinutes); got != "60" {
		t.Fatalf("restore failed: %q", got)
	}
}

func TestWriteIsVerified(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	p.Do(func(p *fakephone.Phone) { p.RejectWrites = true })
	_, err := c.WriteAutop(context.Background(), map[string]string{yealink.FieldRepeatMinutes: "61"})
	if !errors.Is(err, yealink.ErrWriteRejected) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteRefusals(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	for _, name := range []string{"AutoProvisionPassword", "AutoProvisionAESKey16", "SomethingElse", "AutoProvision Evil&x"} {
		if _, err := c.WriteAutop(context.Background(), map[string]string{name: "x"}); err == nil {
			t.Fatalf("%q must be refused", name)
		}
	}
	if n := len(p.Snapshot().Writes); n != 0 {
		t.Fatalf("%d writes reached the phone", n)
	}
}

func TestProvisionNow(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	c := loggedIn(t, p)
	if err := c.ProvisionNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.Snapshot().AutopNow != 1 {
		t.Fatal("autopnow not called")
	}
}

func TestProbe(t *testing.T) {
	p := fakephone.New(fakephone.Options{Variant: "A"})
	defer p.Close()
	tg, _ := yealink.ParseTarget(p.URL)
	port := 0
	for _, c := range tg.Port {
		port = port*10 + int(c-'0')
	}
	r, err := yealink.Probe(context.Background(), tg.Host, []int{1, port}, time.Second)
	if err != nil || r == nil {
		t.Fatalf("probe: %v %v", r, err)
	}
	if r.Model != "T41S" || r.Firmware != "66.86.0.15" || r.CertSHA256 == "" || r.Scheme != "https" {
		t.Fatalf("%+v", r)
	}
	if n := p.Snapshot().LoginAttempts; n != 0 {
		t.Fatalf("a probe must never log in (%d attempts)", n)
	}
	p.Do(func(p *fakephone.Phone) { p.Junk = true })
	r, err = yealink.Probe(context.Background(), tg.Host, []int{port}, time.Second)
	if err != nil || r != nil {
		t.Fatalf("non-phone must give nil: %v %v", r, err)
	}
}
