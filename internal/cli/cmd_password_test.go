package cli

import (
	"context"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Netquor/ylctl/internal/fakephone"
	"github.com/Netquor/ylctl/internal/fakevault"
	"github.com/Netquor/ylctl/internal/pbx"
)

const (
	rigMAC    = "80:5e:c0:00:00:0b"
	rigOldPW  = "Old-Pass-1234"
	rigOtherM = "80:5e:c0:00:00:01"
)

func init() { pwRetryDelay = 0 }

// kcRunner is a keychain that works for both the macOS and the Linux helper commands.
type kcRunner struct{ store map[string]string }

func (k *kcRunner) LookPath(n string) (string, error) {
	if (runtime.GOOS == "darwin" && n == "security") || (runtime.GOOS == "linux" && n == "secret-tool") {
		return "/bin/" + n, nil
	}
	return "", errors.New("not found")
}

var reQuoted = regexp.MustCompile(`"((?:\\.|[^"\\])*)"`)

func (k *kcRunner) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	switch name {
	case "security":
		if len(args) > 0 && args[0] == "-i" { // add-generic-password -U -s ylctl -a "acct" -w "pw"
			q := reQuoted.FindAllStringSubmatch(stdin, -1)
			k.store[q[0][1]] = q[1][1]
			return "", nil
		}
		acct := args[4]
		switch args[0] {
		case "find-generic-password":
			if v, ok := k.store[acct]; ok {
				return v + "\n", nil
			}
			return "", errors.New("not found")
		case "delete-generic-password":
			delete(k.store, acct)
		}
	case "secret-tool":
		switch args[0] {
		case "store":
			k.store[args[len(args)-1]] = stdin
		case "lookup":
			if v, ok := k.store[args[len(args)-1]]; ok {
				return v + "\n", nil
			}
			return "", errors.New("not found")
		case "clear":
			delete(k.store, args[len(args)-1])
		}
	}
	return "", nil
}

type rig struct {
	t  *testing.T
	h  *harness
	p  *fakephone.Phone
	v  *fakevault.Server
	kc *kcRunner
	at map[string]int // phone password changes seen when a vault call happened
}

func newRig(t *testing.T, po fakephone.Options) *rig {
	t.Helper()
	po.Password = rigOldPW
	p := fakephone.New(po)
	t.Cleanup(p.Close)
	v := fakevault.New(rigMAC, "admin", rigOldPW)
	t.Cleanup(v.Close)
	h := newHarness(t)
	h.env["YLCTL_PASSWORD"] = rigOldPW
	h.env["YLCTL_PBX_TOKEN"] = fakevault.Token
	if err := pbx.SaveLink(h.env["YLCTL_CONFIG_DIR"], pbx.Link{Server: v.URL, KeyName: "cli-ylctl-test", LinkedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, h: h, p: p, v: v, kc: &kcRunner{store: map[string]string{}}, at: map[string]int{}}
	h.runner = r.kc
	r.pin()
	return r
}

func (r *rig) pin() {
	r.t.Helper()
	if res := r.h.run("--trust-new", "info", host(r.p)); res.code != 0 {
		r.t.Fatalf("pin: %d %s", res.code, res.err)
	}
}

// watch records, at each vault call, how many password changes the phone had made.
func (r *rig) watch() {
	r.v.Do(func(s *fakevault.Server) {
		s.OnCall = func(name string) {
			var n int
			r.p.Do(func(p *fakephone.Phone) { n = p.PwChanges })
			r.at[name] = n
		}
	})
}

// set runs "password set" against the vault.
func (r *rig) set(extra ...string) result {
	r.t.Helper()
	args := append([]string{"--mac", rigMAC, "password", "set", host(r.p), "--yes", "--yes-i-understand"}, extra...)
	return r.h.run(args...)
}

func (r *rig) seq() string { return strings.Join(r.v.Sequence(), ",") }

// noSecrets fails when any secret appears in the output.
func noSecrets(t *testing.T, res result, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && (strings.Contains(res.stdout, s) || strings.Contains(res.err, s)) {
			t.Fatalf("a password appeared in the output:\n%s\n%s", res.stdout, res.err)
		}
	}
}

func TestPasswordSetVaultGenerate(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	r.watch()
	res := r.set("--generate")
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.err)
	}
	newPW := r.p.Password()
	if newPW == rigOldPW || len(newPW) != 20 {
		t.Fatalf("phone password %q", newPW)
	}
	if got := r.v.Current(rigMAC); got != newPW {
		t.Fatal("the vault and the phone disagree after a successful change")
	}
	if _, _, _, pending := r.v.Pending(rigMAC); pending {
		if _, _, st, _ := r.v.Pending(rigMAC); st == "pending" {
			t.Error("a pending value is left")
		}
	}
	// the order: current read, pending recorded BEFORE the phone changed, committed AFTER
	if got := r.seq(); got != "reveal:current,begin,commit" {
		t.Errorf("vault calls %s", got)
	}
	if r.at["begin"] != 0 || r.at["commit"] != 1 {
		t.Errorf("begin must precede and commit follow the phone change: %v", r.at)
	}
	s := r.p.Snapshot()
	if s.Logins != 3 { // pin, the change session, the verification session
		t.Errorf("logins %d", s.Logins)
	}
	noSecrets(t, res, rigOldPW, newPW)
	if !strings.Contains(res.stdout, "password changed") {
		t.Errorf("stdout: %s", res.stdout)
	}
	// the new password really works, the old one no longer does
	r.h.env["YLCTL_PASSWORD"] = newPW
	if x := r.h.run("info", host(r.p)); x.code != 0 {
		t.Errorf("login with the new password: %d %s", x.code, x.err)
	}
	delete(r.h.env, "YLCTL_PASSWORD")
	if x := r.h.run("--mac", rigMAC, "info", host(r.p)); x.code != 0 {
		t.Errorf("the vault now supplies the new one: %d %s", x.code, x.err)
	}
}

func TestPasswordSetJSONHasNoSecrets(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	res := r.set("--generate", "--json")
	if res.code != 0 {
		t.Fatal(res.err)
	}
	for _, want := range []string{`"changed": true`, `"verified": true`, `"committed": true`} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("missing %s in %s", want, res.stdout)
		}
	}
	noSecrets(t, res, rigOldPW, r.p.Password())
}

func TestPasswordSetPromptKeychain(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	r.h.pwIn = []string{"Typed-Pass-5678", "Typed-Pass-5678"}
	res := r.h.run("password", "set", host(r.p), "--prompt", "--keychain", "--yes", "--yes-i-understand")
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.err)
	}
	if r.p.Password() != "Typed-Pass-5678" {
		t.Fatal("phone not changed")
	}
	acct := "admin@" + host(r.p)
	if r.kc.store[acct] != "Typed-Pass-5678" {
		t.Errorf("keychain %v", r.kc.store)
	}
	if _, ok := r.kc.store[acct+"#pending"]; ok {
		t.Error("the pending keychain entry must be gone after the commit")
	}
	noSecrets(t, res, rigOldPW, "Typed-Pass-5678")
}

func TestPasswordSetPromptNowhere(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	r.h.pwIn = []string{"Typed-Pass-5678", "Typed-Pass-5678"}
	res := r.h.run("password", "set", host(r.p), "--prompt", "--yes", "--yes-i-understand")
	if res.code != 0 || r.p.Password() != "Typed-Pass-5678" {
		t.Fatalf("exit %d: %s", res.code, res.err)
	}
	if !strings.Contains(res.err, "must remember it") {
		t.Errorf("the plan should say nothing keeps the password:\n%s", res.err)
	}
	noSecrets(t, res, rigOldPW, "Typed-Pass-5678")
}

func TestPasswordSetKeychainAutoWhenOldCameFromKeychain(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	delete(r.h.env, "YLCTL_PASSWORD")
	acct := "admin@" + host(r.p)
	r.kc.store[acct] = rigOldPW
	r.h.pwIn = []string{"Typed-Pass-5678", "Typed-Pass-5678"}
	res := r.h.run("password", "set", host(r.p), "--prompt", "--yes", "--yes-i-understand")
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.err)
	}
	if r.kc.store[acct] != "Typed-Pass-5678" {
		t.Error("a password that came from the keychain must be updated there, or the next run locks the phone")
	}
}

// Every ordering and rollback case: what the phone does, what the vault must end up as.
func TestPasswordSetCases(t *testing.T) {
	cases := []struct {
		name        string
		phone       fakephone.Options
		vault       func(*fakevault.Server)
		wantCode    int
		wantSeq     string // vault calls
		phoneChange bool   // the phone ends with a different password
		vaultCur    string // "old" or "new": what the vault holds as current
		pendingLeft bool   // a pending value stays in the vault
		unknowable  bool   // the fake phone itself ends in a state nobody could know (verify-fails knob)
		errHas      string
	}{
		{name: "phone rejects the write (HTTP 500): rolled back", phone: fakephone.Options{}, wantCode: ExitError, wantSeq: "reveal:current,begin,abort", vaultCur: "old", errHas: "NOT changed"},
		{name: "phone rejects a weak password (-4): rolled back without guessing", wantCode: ExitError, wantSeq: "reveal:current,begin,abort", vaultCur: "old", errHas: "invalid"},
		{name: "phone drops the connection before applying: old still works, rolled back", wantCode: ExitError, wantSeq: "reveal:current,begin,abort", vaultCur: "old", errHas: "NOT changed"},
		{name: "phone applies then drops the connection: verified, committed", wantCode: 0, wantSeq: "reveal:current,begin,commit", phoneChange: true, vaultCur: "new"},
		{name: "phone applies and answers garbage: verified, committed", wantCode: 0, wantSeq: "reveal:current,begin,commit", phoneChange: true, vaultCur: "new"},
		{name: "phone says 0 but changes nothing: state reported, pending kept", wantCode: ExitPartial, wantSeq: "reveal:current,begin", vaultCur: "old", pendingLeft: true, errHas: "recover"},
		{name: "phone changes but refuses the new login: state reported, pending kept", wantCode: ExitPartial, wantSeq: "reveal:current,begin", phoneChange: true, vaultCur: "old", pendingLeft: true, unknowable: true, errHas: "recover"},
		{name: "vault cannot record first: the phone is never touched", wantCode: ExitError, wantSeq: "reveal:current,begin", vaultCur: "old", errHas: "NOT changed"},
		{name: "vault commit fails once: retried and committed", wantCode: 0, wantSeq: "reveal:current,begin,commit,commit", phoneChange: true, vaultCur: "new"},
		{name: "vault commit answer lost: retry is idempotent", wantCode: 0, wantSeq: "reveal:current,begin,commit,commit", phoneChange: true, vaultCur: "new"},
		{name: "vault commit keeps failing: new password stays pending, told how to finish", wantCode: ExitPartial, wantSeq: "reveal:current,begin,commit,commit,commit", phoneChange: true, vaultCur: "old", pendingLeft: true, errHas: "NOT lost"},
		{name: "rollback abort also fails: only a warning, nothing lost", phone: fakephone.Options{}, wantCode: ExitError, wantSeq: "reveal:current,begin,abort", vaultCur: "old", pendingLeft: true, errHas: "could not drop the pending"},
	}
	// per-case knobs
	phoneKnob := []func(*fakephone.Phone){
		func(p *fakephone.Phone) { p.PwWriteRejected = true },
		func(p *fakephone.Phone) { p.PwWeakRejected = true },
		func(p *fakephone.Phone) { p.PwDropBeforeApply = true },
		func(p *fakephone.Phone) { p.PwDropAfterChange = true },
		func(p *fakephone.Phone) { p.PwGarbageAnswer = true },
		func(p *fakephone.Phone) { p.PwSilentNoApply = true },
		func(p *fakephone.Phone) { p.PwVerifyFails = true },
		nil,
		nil, nil, nil,
		func(p *fakephone.Phone) { p.PwWriteRejected = true },
	}
	vaultKnob := []func(*fakevault.Server){
		nil, nil, nil, nil, nil, nil, nil,
		func(s *fakevault.Server) { s.BeginFails = true },
		func(s *fakevault.Server) { s.CommitFails = 1 },
		func(s *fakevault.Server) { s.CommitLost = true },
		func(s *fakevault.Server) { s.CommitFails = 99 },
		func(s *fakevault.Server) { s.AbortFails = true },
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.phone)
			if phoneKnob[i] != nil {
				r.p.Do(func(p *fakephone.Phone) { phoneKnob[i](p) })
			}
			if vaultKnob[i] != nil {
				r.v.Do(vaultKnob[i])
			}
			res := r.set("--generate")
			if res.code != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s", res.code, tc.wantCode, res.err)
			}
			if got := r.seq(); got != tc.wantSeq {
				t.Errorf("vault calls %q, want %q", got, tc.wantSeq)
			}
			if changed := r.p.Password() != rigOldPW; changed != tc.phoneChange {
				t.Errorf("phone changed=%v, want %v", changed, tc.phoneChange)
			}
			cur := r.v.Current(rigMAC)
			phonePW := r.p.Password()
			switch tc.vaultCur {
			case "old":
				if cur != rigOldPW {
					t.Error("the vault must still hold the OLD password as current")
				}
			case "new":
				if cur != phonePW {
					t.Error("the vault must hold what the phone has")
				}
			}
			_, pend, state, ok := r.v.Pending(rigMAC)
			if left := ok && state == "pending"; left != tc.pendingLeft {
				t.Errorf("pending left = %v, want %v (state %q)", left, tc.pendingLeft, state)
			}
			// the password is never lost: the phone's password is the vault's current OR its pending value
			if !tc.unknowable && phonePW != rigOldPW && cur != phonePW && pend != phonePW {
				t.Error("PASSWORD LOST: the phone has a password the vault knows nowhere")
			}
			if tc.errHas != "" && !strings.Contains(res.err, tc.errHas) {
				t.Errorf("stderr lacks %q:\n%s", tc.errHas, res.err)
			}
			noSecrets(t, res, rigOldPW, phonePW, pend)
		})
	}
}

func TestPasswordRejectionCodeNoGuessLogins(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	r.p.Do(func(p *fakephone.Phone) { p.PwWeakRejected = true })
	before := r.p.Snapshot().LoginAttempts
	res := r.set("--generate")
	if res.code == 0 {
		t.Fatal("must fail")
	}
	// a clear refusal needs no further logins: exactly the one session of the change
	if n := r.p.Snapshot().LoginAttempts - before; n != 1 {
		t.Errorf("%d login attempts, want 1", n)
	}
}

func TestPasswordSetNoLockout(t *testing.T) {
	// the worst case (phone says 0, new login refused) must stay within three failed logins' worth of attempts
	r := newRig(t, fakephone.Options{MaxFailures: 3})
	r.p.Do(func(p *fakephone.Phone) { p.PwVerifyFails = true })
	before := r.p.Snapshot().LoginAttempts
	res := r.set("--generate")
	if res.code != ExitPartial {
		t.Fatal(res.err)
	}
	if n := r.p.Snapshot().LoginAttempts - before; n != 2 {
		t.Errorf("%d login attempts after the start, want 2 (the change session and one verification)", n)
	}
	if r.p.Locked() {
		t.Error("the phone must not be locked by our own attempts")
	}
}

func TestPasswordRefusals(t *testing.T) {
	type tc struct {
		name   string
		args   []string // after "password set <host>"
		global []string
		setup  func(*rig)
		code   int
		has    string
		nomac  bool
		noBeg  bool // the vault must see no begin and the phone no write
	}
	cases := []tc{
		{name: "neither source", args: []string{"--yes", "--yes-i-understand"}, code: ExitUsage, has: "exactly one of --generate and --prompt"},
		{name: "both sources", args: []string{"--generate", "--prompt", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "exactly one"},
		{name: "bad length", args: []string{"--generate", "--length", "5", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "--length"},
		{name: "generate with nowhere to keep it", nomac: true, args: []string{"--generate", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "somewhere to keep", noBeg: true},
		{name: "insecure", global: []string{"--insecure"}, args: []string{"--generate", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "--insecure"},
		{name: "trust-new", global: []string{"--trust-new"}, args: []string{"--generate", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "--trust-new"},
		{name: "other web user", global: []string{"--user", "bob"}, args: []string{"--generate", "--yes", "--yes-i-understand"}, code: ExitUsage, has: "'admin'"},
		{name: "no terminal and no --yes", args: []string{"--generate"}, code: ExitUsage, has: "--yes", noBeg: true},
		{name: "--yes alone is not enough without a terminal", args: []string{"--generate", "--yes"}, code: ExitUsage, has: "--yes-i-understand", noBeg: true},
		{name: "call active", args: []string{"--generate", "--yes", "--yes-i-understand"}, setup: func(r *rig) { r.p.Do(func(p *fakephone.Phone) { p.InCall = true }) }, code: ExitError, has: "call is active", noBeg: true},
		{name: "call state unreadable", args: []string{"--generate", "--yes", "--yes-i-understand"}, setup: func(r *rig) { r.p.Do(func(p *fakephone.Phone) { p.TalkingJunk = true }) }, code: ExitError, has: "cannot tell whether a call is active", noBeg: true},
		{name: "unfinished change already waiting", args: []string{"--generate", "--yes", "--yes-i-understand"}, code: ExitError, has: "recover"},
		{name: "link may not rotate (read-only key)", args: []string{"--generate", "--yes", "--yes-i-understand"}, setup: func(r *rig) { r.v.Do(func(s *fakevault.Server) { s.ReadOnlyKey = true }) }, code: ExitError, has: "may not take part"},
		{name: "wrong MAC for this phone", global: []string{"--mac", rigOtherM}, args: []string{"--generate", "--yes", "--yes-i-understand"}, setup: func(r *rig) { r.v.Add(rigOtherM, "admin", rigOldPW) }, code: ExitError, has: "is not this phone", noBeg: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, fakephone.Options{})
			if c.name == "unfinished change already waiting" {
				// leave a pending value behind with a failed run first
				r.p.Do(func(p *fakephone.Phone) { p.PwSilentNoApply = true })
				if x := r.set("--generate"); x.code != ExitPartial {
					t.Fatalf("setup run: %d %s", x.code, x.err)
				}
				r.p.Do(func(p *fakephone.Phone) { p.PwSilentNoApply = false })
				r.v.Do(func(s *fakevault.Server) { s.Calls = nil })
			}
			if c.setup != nil {
				c.setup(r)
			}
			args := []string{}
			if !c.nomac && (len(c.global) == 0 || c.global[0] != "--mac") {
				args = append(args, "--mac", rigMAC)
			}
			args = append(args, c.global...)
			args = append(args, "password", "set", host(r.p))
			args = append(args, c.args...)
			res := r.h.run(args...)
			if res.code != c.code {
				t.Fatalf("exit %d, want %d\n%s", res.code, c.code, res.err)
			}
			if !strings.Contains(res.err, c.has) {
				t.Errorf("stderr lacks %q:\n%s", c.has, res.err)
			}
			if r.p.Password() != rigOldPW {
				t.Error("the phone was changed")
			}
			if c.noBeg && strings.Contains(r.seq(), "begin") {
				t.Errorf("nothing may be recorded: %s", r.seq())
			}
			noSecrets(t, res, rigOldPW)
		})
	}
}

func TestPasswordWrongMACRefusalNeedsVaultEntry(t *testing.T) {
	// a vault that has an entry for another MAC must not be used for this phone
	r := newRig(t, fakephone.Options{})
	res := r.h.run("--mac", rigOtherM, "password", "set", host(r.p), "--generate", "--yes", "--yes-i-understand")
	if res.code == 0 || r.p.Password() != rigOldPW {
		t.Fatalf("%d %s", res.code, res.err)
	}
}

func TestPasswordNotPinnedNeverLogsIn(t *testing.T) {
	p := fakephone.New(fakephone.Options{Password: rigOldPW})
	defer p.Close()
	h := newHarness(t)
	h.env["YLCTL_PASSWORD"] = rigOldPW
	h.pwIn = []string{"Typed-Pass-5678", "Typed-Pass-5678"}
	res := h.run("password", "set", host(p), "--prompt", "--yes", "--yes-i-understand")
	if res.code == 0 || !strings.Contains(res.err, "not a phone you have trusted") {
		t.Fatalf("%d %s", res.code, res.err)
	}
	if s := p.Snapshot(); s.LoginAttempts != 0 {
		t.Errorf("the password was sent to an unpinned phone (%d logins)", s.LoginAttempts)
	}
}

func TestPasswordNewValueChecks(t *testing.T) {
	for name, in := range map[string][]string{
		"same as the old one":    {rigOldPW, rigOldPW},
		"the factory default":    {"admin", "admin"},
		"too short":              {"Ab1", "Ab1"},
		"no digit":               {"OnlyLettersHere", "OnlyLettersHere"},
		"no letter":              {"123456789012", "123456789012"},
		"a semicolon":            {"Abcd1234;xyz", "Abcd1234;xyz"},
		"a space":                {"Abcd 12345678", "Abcd 12345678"},
		"too long":               {strings.Repeat("a1", 17), strings.Repeat("a1", 17)},
		"non ascii":              {"Pässwort1234", "Pässwort1234"},
		"the two entries differ": {"Typed-Pass-5678", "Typed-Pass-5679"},
		"the user name reversed": {"nimda", "nimda"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, fakephone.Options{})
			r.h.pwIn = in
			res := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--prompt", "--yes", "--yes-i-understand")
			if res.code != ExitUsage {
				t.Fatalf("exit %d: %s", res.code, res.err)
			}
			if strings.Contains(r.seq(), "begin") || r.p.Password() != rigOldPW {
				t.Error("nothing may be recorded or changed")
			}
			noSecrets(t, res, rigOldPW)
			if in[0] != "admin" && in[0] != "nimda" {
				noSecrets(t, res, in[0], in[1])
			}
		})
	}
}

func TestPasswordTypedConfirmation(t *testing.T) {
	for name, c := range map[string]struct {
		stdin string
		ok    bool
	}{
		"wrong word":        {"yes\n", false},
		"empty":             {"\n", false},
		"no input":          {"", false},
		"the address":       {"HOST\n", true},
		"the last 4 of MAC": {"000B\n", true},
		"last 4 lowercase":  {"000b\n", true},
		"last 4 of another": {"0001\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, fakephone.Options{})
			r.h.tty = true
			r.h.stdin = strings.ReplaceAll(c.stdin, "HOST", host(r.p))
			res := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--generate")
			if (res.code == 0) != c.ok {
				t.Fatalf("exit %d: %s", res.code, res.err)
			}
			if !c.ok && (strings.Contains(r.seq(), "begin") || r.p.Password() != rigOldPW) {
				t.Error("a wrong confirmation must change and record nothing")
			}
			if !strings.Contains(res.err, "type the phone's address") {
				t.Errorf("no prompt:\n%s", res.err)
			}
		})
	}
}

func TestPasswordYesWithoutUnderstandNeedsTypedWord(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	r.h.tty = false
	r.h.stdin = "000B\n"
	// not a terminal: even with the right word on stdin, --yes alone is refused
	res := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--generate", "--yes")
	if res.code == 0 || r.p.Password() != rigOldPW {
		t.Fatalf("%d %s", res.code, res.err)
	}
}

func TestPasswordDryRun(t *testing.T) {
	r := newRig(t, fakephone.Options{})
	before := r.p.Snapshot()
	res := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--generate", "--dry-run")
	if res.code != 0 {
		t.Fatalf("%d %s", res.code, res.err)
	}
	after := r.p.Snapshot()
	if len(after.Writes) != len(before.Writes) || after.Logins-before.Logins != 1 {
		t.Errorf("a dry run makes one read-only login and no write: %+v -> %+v", before, after)
	}
	var attempts int
	r.p.Do(func(p *fakephone.Phone) { attempts = p.PwAttempts })
	if attempts != 0 || r.p.Password() != rigOldPW {
		t.Error("the change endpoint was used in a dry run")
	}
	if got := r.seq(); got != "reveal:current" {
		t.Errorf("a dry run records nothing in the vault: %s", got)
	}
	for _, want := range []string{"Password change for", "T41S", "80:5E:C0:00:00:0B", "PENDING", "dry run", "Nothing was changed"} {
		if !strings.Contains(res.err, want) {
			t.Errorf("plan lacks %q:\n%s", want, res.err)
		}
	}
	noSecrets(t, res, rigOldPW)
	// it does not need a terminal or --yes, and does not prompt for a new password
	r.h.pwIn = nil
	if x := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--prompt", "--dry-run"); x.code != 0 {
		t.Errorf("dry run with --prompt: %d %s", x.code, x.err)
	}
	// a call in progress shows up in the dry run too
	r.p.Do(func(p *fakephone.Phone) { p.InCall = true })
	if x := r.h.run("--mac", rigMAC, "password", "set", host(r.p), "--generate", "--dry-run"); x.code == 0 {
		t.Error("the dry run must report a call in progress")
	}
}

func TestPasswordFromFactoryDefault(t *testing.T) {
	p := fakephone.New(fakephone.Options{Password: "admin"})
	defer p.Close()
	v := fakevault.New(rigMAC, "admin", "admin")
	defer v.Close()
	h := newHarness(t)
	delete(h.env, "YLCTL_PASSWORD")
	h.env["YLCTL_PBX_TOKEN"] = fakevault.Token
	_ = pbx.SaveLink(h.env["YLCTL_CONFIG_DIR"], pbx.Link{Server: v.URL, KeyName: "cli-ylctl-test", LinkedAt: time.Now().UTC().Format(time.RFC3339)})
	if r := h.run("--trust-new", "--try-default", "info", host(p)); r.code != 0 {
		t.Fatal(r.err)
	}
	res := h.run("--mac", rigMAC, "password", "set", host(p), "--generate", "--yes", "--yes-i-understand")
	if res.code != 0 || p.Password() == "admin" || v.Current(rigMAC) != p.Password() {
		t.Fatalf("%d %s", res.code, res.err)
	}
	noSecrets(t, res, p.Password())
}

func TestPasswordRecover(t *testing.T) {
	t.Run("commit failed earlier: recover commits", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		r.v.Do(func(s *fakevault.Server) { s.CommitFails = 99 })
		if x := r.set("--generate"); x.code != ExitPartial {
			t.Fatal(x.err)
		}
		r.v.Do(func(s *fakevault.Server) { s.CommitFails = 0 })
		res := r.h.run("--mac", rigMAC, "password", "recover", host(r.p))
		if res.code != 0 {
			t.Fatalf("%d %s", res.code, res.err)
		}
		if r.v.Current(rigMAC) != r.p.Password() {
			t.Error("recover must leave the vault holding what the phone has")
		}
		noSecrets(t, res, rigOldPW, r.p.Password())
	})
	t.Run("phone never changed: recover drops the pending value", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		r.p.Do(func(p *fakephone.Phone) { p.PwSilentNoApply = true })
		if x := r.set("--generate"); x.code != ExitPartial {
			t.Fatal(x.err)
		}
		res := r.h.run("--mac", rigMAC, "password", "recover", host(r.p))
		if res.code != 0 || !strings.Contains(res.stdout, "old password") {
			t.Fatalf("%d %s %s", res.code, res.stdout, res.err)
		}
		if _, _, st, _ := r.v.Pending(rigMAC); st == "pending" {
			t.Error("pending must be dropped")
		}
		if r.v.Current(rigMAC) != rigOldPW {
			t.Error("current must stay the old one")
		}
	})
	t.Run("pending expired but the phone has it: recommitted", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		r.v.Do(func(s *fakevault.Server) { s.CommitFails = 99 })
		if x := r.set("--generate"); x.code != ExitPartial {
			t.Fatal(x.err)
		}
		r.v.Do(func(s *fakevault.Server) { s.CommitFails = 0 })
		r.v.ExpirePending(rigMAC)
		res := r.h.run("--mac", rigMAC, "password", "recover", host(r.p))
		if res.code != 0 || r.v.Current(rigMAC) != r.p.Password() {
			t.Fatalf("%d %s", res.code, res.err)
		}
	})
	t.Run("neither works: pending is kept", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		r.p.Do(func(p *fakephone.Phone) { p.PwVerifyFails = true })
		if x := r.set("--generate"); x.code != ExitPartial {
			t.Fatal(x.err)
		}
		before := r.p.Snapshot().LoginAttempts
		res := r.h.run("--mac", rigMAC, "password", "recover", host(r.p))
		if res.code != ExitAuth {
			t.Fatalf("%d %s", res.code, res.err)
		}
		if n := r.p.Snapshot().LoginAttempts - before; n != 2 {
			t.Errorf("at most two attempts, made %d", n)
		}
		if _, _, st, _ := r.v.Pending(rigMAC); st != "pending" {
			t.Error("the pending value must be kept")
		}
	})
	t.Run("nothing pending", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		res := r.h.run("--mac", rigMAC, "password", "recover", host(r.p))
		if res.code != ExitNoChange {
			t.Fatalf("%d %s", res.code, res.err)
		}
	})
	t.Run("keychain", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		acct := "admin@" + host(r.p)
		r.kc.store[acct+"#pending"] = "Pending-Pass-777"
		r.p.SetPassword("Pending-Pass-777")
		r.h.env["YLCTL_PASSWORD"] = rigOldPW
		res := r.h.run("password", "recover", host(r.p), "--keychain")
		if res.code != 0 || r.kc.store[acct] != "Pending-Pass-777" {
			t.Fatalf("%d %s %v", res.code, res.err, r.kc.store)
		}
		if _, ok := r.kc.store[acct+"#pending"]; ok {
			t.Error("pending entry must be gone")
		}
	})
	t.Run("needs a place", func(t *testing.T) {
		r := newRig(t, fakephone.Options{})
		if res := r.h.run("password", "recover", host(r.p)); res.code != ExitUsage {
			t.Fatalf("%d", res.code)
		}
	})
}

func TestPasswordRaceConcurrentRuns(t *testing.T) {
	// two runs at once: the vault allows one pending value, so one wins and the other is refused
	r := newRig(t, fakephone.Options{})
	done := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			h := *r.h
			h.env = map[string]string{}
			for k, v := range r.h.env {
				h.env[k] = v
			}
			done <- h.run("--mac", rigMAC, "password", "set", host(r.p), "--generate", "--yes", "--yes-i-understand")
		}()
	}
	a, b := <-done, <-done
	wins := 0
	for _, x := range []result{a, b} {
		if x.code == 0 {
			wins++
		}
	}
	if wins < 1 {
		t.Fatalf("one run must succeed: %d %d\n%s\n%s", a.code, b.code, a.err, b.err)
	}
	if r.v.Current(rigMAC) != r.p.Password() {
		t.Error("vault and phone disagree after concurrent runs")
	}
}
