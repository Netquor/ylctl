package yealink_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Netquor/ylctl/internal/fakephone"
	"github.com/Netquor/ylctl/internal/yealink"
)

func pwClient(t *testing.T, p *fakephone.Phone, pw string) *yealink.Client {
	t.Helper()
	c, err := yealink.New(strings.TrimPrefix(p.URL, "https://"), yealink.Options{TrustNew: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(context.Background(), "admin", pw); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestChangeAdminPasswordOutcomes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		knob    func(*fakephone.Phone)
		oldPW   string
		newPW   string
		want    yealink.PasswordOutcome
		code    string
		changed bool
	}{
		{name: "ok", oldPW: "Old-Pass-1234", newPW: "New-Pass-5678", want: yealink.PasswordChanged, changed: true},
		{name: "wrong old password (-2)", oldPW: "Wrong-Pass-1", newPW: "New-Pass-5678", want: yealink.PasswordRejected, code: "-2"},
		{name: "the default is refused (-5)", oldPW: "Old-Pass-1234", newPW: "admin", want: yealink.PasswordRejected, code: "-5"},
		{name: "weak refused (-4)", knob: func(p *fakephone.Phone) { p.PwWeakRejected = true }, oldPW: "Old-Pass-1234", newPW: "New-Pass-5678", want: yealink.PasswordRejected, code: "-4"},
		{name: "HTTP 500 is not a clear answer", knob: func(p *fakephone.Phone) { p.PwWriteRejected = true }, oldPW: "Old-Pass-1234", newPW: "New-Pass-5678", want: yealink.PasswordUnknown},
		{name: "connection dropped after the change", knob: func(p *fakephone.Phone) { p.PwDropAfterChange = true }, oldPW: "Old-Pass-1234", newPW: "New-Pass-5678", want: yealink.PasswordUnknown, changed: true},
		{name: "unreadable answer", knob: func(p *fakephone.Phone) { p.PwGarbageAnswer = true }, oldPW: "Old-Pass-1234", newPW: "New-Pass-5678", want: yealink.PasswordUnknown, changed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fakephone.New(fakephone.Options{Password: "Old-Pass-1234"})
			defer p.Close()
			if tc.knob != nil {
				p.Do(tc.knob)
			}
			c := pwClient(t, p, "Old-Pass-1234")
			out, err := c.ChangeAdminPassword(ctx, tc.oldPW, tc.newPW)
			if out != tc.want {
				t.Fatalf("outcome %v (%v), want %v", out, err, tc.want)
			}
			var rej *yealink.PasswordRejectedError
			if tc.code != "" && (!errors.As(err, &rej) || rej.Code != tc.code) {
				t.Errorf("err %v, want code %s", err, tc.code)
			}
			if (p.Password() == tc.newPW) != tc.changed {
				t.Errorf("phone password changed = %v, want %v", p.Password() == tc.newPW, tc.changed)
			}
			if err != nil && (strings.Contains(err.Error(), tc.oldPW) || strings.Contains(err.Error(), tc.newPW)) {
				t.Errorf("a password is in the error: %v", err)
			}
		})
	}
}

func TestChangeEndsTheSessionAndOldLoginFails(t *testing.T) {
	ctx := context.Background()
	p := fakephone.New(fakephone.Options{Password: "Old-Pass-1234"})
	defer p.Close()
	c := pwClient(t, p, "Old-Pass-1234")
	if out, err := c.ChangeAdminPassword(ctx, "Old-Pass-1234", "New-Pass-5678"); out != yealink.PasswordChanged {
		t.Fatalf("%v %v", out, err)
	}
	// the session is gone: the next request must not silently log in again with the OLD password
	before := p.Snapshot().LoginAttempts
	if _, err := c.Status(ctx); err == nil {
		t.Log("status still answered from the cached first page")
	}
	if _, err := c.Talking(ctx); err == nil {
		t.Error("the old session must not work after a change")
	}
	if n := p.Snapshot().LoginAttempts - before; n > 1 {
		t.Errorf("%d login attempts with the old password after the change", n)
	}
	fresh, _ := yealink.New(strings.TrimPrefix(p.URL, "https://"), yealink.Options{TrustNew: true})
	if err := fresh.Login(ctx, "admin", "New-Pass-5678"); err != nil {
		t.Errorf("new password: %v", err)
	}
	other, _ := yealink.New(strings.TrimPrefix(p.URL, "https://"), yealink.Options{TrustNew: true})
	if err := other.Login(ctx, "admin", "Old-Pass-1234"); !errors.Is(err, yealink.ErrAuthFailed) {
		t.Errorf("old password: %v", err)
	}
}

func TestTalking(t *testing.T) {
	ctx := context.Background()
	p := fakephone.New(fakephone.Options{Password: "Old-Pass-1234"})
	defer p.Close()
	c := pwClient(t, p, "Old-Pass-1234")
	if on, err := c.Talking(ctx); err != nil || on {
		t.Fatalf("%v %v", on, err)
	}
	p.Do(func(p *fakephone.Phone) { p.InCall = true })
	if on, err := c.Talking(ctx); err != nil || !on {
		t.Fatalf("%v %v", on, err)
	}
	p.Do(func(p *fakephone.Phone) { p.TalkingJunk = true })
	if _, err := c.Talking(ctx); !errors.Is(err, yealink.ErrUnexpectedPage) {
		t.Fatalf("%v", err)
	}
}

func TestPasswordPreflight(t *testing.T) {
	p := fakephone.New(fakephone.Options{Password: "Old-Pass-1234"})
	defer p.Close()
	c := pwClient(t, p, "Old-Pass-1234")
	pp, err := c.PasswordPreflight(context.Background())
	if err != nil || pp.LoginUser != "admin" || !pp.HasFields {
		t.Fatalf("%+v %v", pp, err)
	}
}

func TestChangeRefusesWhenNotAdmin(t *testing.T) {
	p := fakephone.New(fakephone.Options{User: "user", Password: "Old-Pass-1234"})
	defer p.Close()
	c, _ := yealink.New(strings.TrimPrefix(p.URL, "https://"), yealink.Options{TrustNew: true})
	if err := c.Login(context.Background(), "user", "Old-Pass-1234"); err != nil {
		t.Fatal(err)
	}
	if out, err := c.ChangeAdminPassword(context.Background(), "Old-Pass-1234", "New-Pass-5678"); out != yealink.PasswordRejected || err == nil {
		t.Fatalf("%v %v", out, err)
	}
	if p.Password() != "Old-Pass-1234" {
		t.Error("nothing may be sent")
	}
	var n int
	p.Do(func(p *fakephone.Phone) { n = p.PwAttempts })
	if n != 0 {
		t.Error("the change endpoint must not be reached")
	}
}

func TestEncryptSecretsSharesOneKey(t *testing.T) {
	// the phone decrypts both fields with ONE rsakey/rsaiv: the fake phone does exactly that
	p := fakephone.New(fakephone.Options{Password: "Old-Pass-1234"})
	defer p.Close()
	c := pwClient(t, p, "Old-Pass-1234")
	if out, err := c.ChangeAdminPassword(context.Background(), "Old-Pass-1234", "New-Pass-5678"); out != yealink.PasswordChanged {
		t.Fatalf("%v %v", out, err)
	}
}
