package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/fakephone"
	"github.com/Netquor/ylctl/internal/yealink"
)

var update = flag.Bool("update", false, "rewrite golden files")

type harness struct {
	t      *testing.T
	env    map[string]string
	tty    bool
	stdin  string
	runner creds.Runner
	pwIn   []string // answers for password prompts, in order
}

func newHarness(t *testing.T) *harness {
	return &harness{t: t, env: map[string]string{"YLCTL_CONFIG_DIR": t.TempDir(), "YLCTL_PASSWORD": "admin"}}
}

type result struct {
	code        int
	stdout, err string
}

func (h *harness) run(args ...string) result {
	h.t.Helper()
	var out, errb bytes.Buffer
	env := &Env{
		Stdin: strings.NewReader(h.stdin), Stdout: &out, Stderr: &errb,
		Getenv:     func(k string) string { return h.env[k] },
		StdinIsTTY: h.tty, StdoutIsTTY: h.tty, Runner: h.runner,
	}
	if h.pwIn != nil {
		in := h.pwIn
		env.ReadPassword = func(string) (string, error) {
			if len(in) == 0 {
				return "", errors.New("no more prompt answers")
			}
			v := in[0]
			in = in[1:]
			return v, nil
		}
	}
	code := RunContext(context.Background(), args, env)
	return result{code, out.String(), errb.String()}
}

var (
	reFP   = regexp.MustCompile(`[0-9a-f]{16}\.\.\.`)
	reFull = regexp.MustCompile(`"cert_sha256": "[0-9a-f]{64}"`)
	rePort = regexp.MustCompile(`\b(\d{4,5})/https`)
	reJPrt = regexp.MustCompile(`"port": \d+`)
	reAddr = regexp.MustCompile(`127\.0\.0\.1:\d+`)
)

func normalize(s string) string {
	s = reAddr.ReplaceAllString(s, "PHONE")
	s = reFull.ReplaceAllString(s, `"cert_sha256": "<fp>"`)
	s = reFP.ReplaceAllString(s, "<fp>")
	s = rePort.ReplaceAllString(s, "<port>/https")
	s = reJPrt.ReplaceAllString(s, `"port": 0`)
	return s
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	got = normalize(got)
	if *update {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("golden %s differs\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

func host(p *fakephone.Phone) string { return strings.TrimPrefix(p.URL, "https://") }

func TestGoldenReadCommands(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	pa := fakephone.New(fakephone.Options{Variant: "A"})
	defer pa.Close()
	h := newHarness(t)
	cases := []struct {
		name string
		args []string
	}{
		{"info_table", []string{"info"}},
		{"info_json", []string{"--json", "info"}},
		{"status_table", []string{"status"}},
		{"status_json", []string{"--json", "status"}},
		{"autop_show_table", []string{"autop", "show"}},
		{"autop_show_json", []string{"--json", "autop", "show"}},
		{"account_show_table", []string{"account", "show"}},
		{"account_show_json", []string{"--json", "account", "show"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := h.run(append([]string{"--trust-new"}, reorder(tc.args, host(p))...)...)
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.err)
			}
			golden(t, tc.name, r.stdout)
		})
	}
	t.Run("phone A", func(t *testing.T) {
		r := h.run("--trust-new", "status", host(pa))
		if r.code != 0 {
			t.Fatal(r.err)
		}
		golden(t, "status_phoneA_table", r.stdout)
		r = h.run("--trust-new", "autop", "show", host(pa))
		golden(t, "autop_show_phoneA_table", r.stdout)
	})
	t.Run("version", func(t *testing.T) {
		r := h.run("--json", "version")
		golden(t, "version_json", r.stdout)
	})
}

// reorder puts host after the subcommand words but before flags.
func reorder(args []string, host string) []string {
	out := append([]string{}, args...)
	// every case here is "[--json] cmd [sub]"; the host is the last positional
	return append(out, host)
}

func TestExitCodes(t *testing.T) {
	p := fakephone.New(fakephone.Options{MaxFailures: 3})
	defer p.Close()
	h := newHarness(t)
	hp := host(p)

	if r := h.run("--trust-new", "info", hp); r.code != ExitOK {
		t.Fatalf("ok: %d %s", r.code, r.err)
	}
	if r := h.run("bogus"); r.code != ExitUsage {
		t.Errorf("unknown command: %d", r.code)
	}
	if r := h.run("info"); r.code != ExitUsage {
		t.Errorf("missing host: %d", r.code)
	}
	if r := h.run("info", "--nope", hp); r.code != ExitUsage {
		t.Errorf("bad flag: %d", r.code)
	}
	if r := h.run("adopt", hp); r.code != ExitUsage {
		t.Errorf("adopt without url: %d", r.code)
	}
	if r := h.run("adopt", hp, "--url", "not a url"); r.code != ExitUsage {
		t.Errorf("adopt bad url: %d", r.code)
	}
	if r := h.run("--timeout", "1s", "info", "127.0.0.1:1"); r.code != ExitUnreachable {
		t.Errorf("unreachable: %d %s", r.code, r.err)
	}
	h.env["YLCTL_PASSWORD"] = "wrong"
	if r := h.run("info", hp); r.code != ExitAuth {
		t.Errorf("auth: %d %s", r.code, r.err)
	}
	if r := h.run("info", hp); r.code != ExitAuth {
		t.Errorf("auth 2: %d %s", r.code, r.err)
	}
	r := h.run("info", hp)
	if r.code != ExitLocked {
		t.Errorf("lock: %d %s", r.code, r.err)
	}
	if n := p.Snapshot().LoginAttempts; n != 1+3 {
		t.Errorf("one login for the ok run and three failing attempts expected, got %d", n)
	}
}

func TestNoPasswordNoGuessing(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	h := newHarness(t)
	delete(h.env, "YLCTL_PASSWORD")
	r := h.run("--trust-new", "info", host(p))
	if r.code != ExitUsage || !strings.Contains(r.err, "--try-default") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	if n := p.Snapshot().LoginAttempts; n != 0 {
		t.Fatalf("the default password must not be tried without --try-default (%d attempts)", n)
	}
}

func TestTryDefaultWarns(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	h := newHarness(t)
	delete(h.env, "YLCTL_PASSWORD")
	r := h.run("--trust-new", "--try-default", "info", host(p))
	if r.code != 0 || !strings.Contains(r.err, "default password in use") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	// a phone with a changed password: exactly one attempt, then exit 4
	q := fakephone.New(fakephone.Options{Password: "changed"})
	defer q.Close()
	r = h.run("--trust-new", "--try-default", "info", host(q))
	if r.code != ExitAuth || q.Snapshot().LoginAttempts != 1 {
		t.Fatalf("%d attempts=%d", r.code, q.Snapshot().LoginAttempts)
	}
	if r := h.run("--trust-new", "--try-default", "--user", "root", "info", host(q)); r.code == 0 {
		t.Fatal("--try-default with another user must fail")
	}
}

func TestSecretsNeverPrinted(t *testing.T) {
	const pw = "sentinel-Pw-9f3a1c"
	const tok = "SECRETTOKEN0123456789abcdefghijklmnop"
	p := fakephone.New(fakephone.Options{Password: pw})
	defer p.Close()
	p.SetAutop(yealink.FieldServerURL, "https://pbx.example.net/webhooks/provision/"+tok+"/")
	h := newHarness(t)
	h.env["YLCTL_PASSWORD"] = pw
	hp := host(p)
	all := ""
	for _, args := range [][]string{
		{"--trust-new", "info", hp}, {"status", hp}, {"--json", "autop", "show", hp}, {"autop", "show", hp}, {"account", "show", hp},
		{"adopt", hp, "--url", "https://pbx.example.net/webhooks/provision/" + tok + "/", "--dry-run"},
		{"--json", "adopt", hp, "--url", "https://pbx.example.net/webhooks/provision/" + tok + "/", "--force"},
		{"autop", "set", hp, "RepeatMinutes=61"},
		{"autop", "set", hp, "Password=x"}, // refused
		{"provision-now", hp},
	} {
		r := h.run(args...)
		all += r.stdout + r.err
	}
	for _, leak := range []string{pw, tok, "jhtO"} {
		if strings.Contains(all, leak) {
			t.Errorf("output leaked %q", leak)
		}
	}
	// --reveal shows the URL on request
	r := h.run("--reveal", "autop", "show", hp)
	if !strings.Contains(r.stdout, tok) {
		t.Error("--reveal should show the full URL")
	}
	if strings.Contains(r.stdout, "AESKey16") && !strings.Contains(r.stdout, "********") {
		t.Error("secrets must stay masked even with --reveal")
	}
}

func TestAdopt(t *testing.T) {
	// phone A: empty URL, PnP and DHCP option on
	p := fakephone.New(fakephone.Options{Variant: "A"})
	defer p.Close()
	h := newHarness(t)
	hp := host(p)
	u := "https://pbx.example.net/webhooks/provision/abcdefghijklmnopqrstuvwxyz012345/"

	r := h.run("--trust-new", "adopt", hp, "--url", u, "--disable-dhcp", "--disable-pnp", "--dry-run")
	if r.code != 0 || !strings.Contains(r.err, "dry run") || !strings.Contains(r.err, "EnablePNP") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	golden(t, "adopt_dry_run_stderr", r.err)
	s := p.Snapshot()
	if len(s.Writes) != 0 || s.AutopNow != 0 {
		t.Fatal("a dry run must not write or provision")
	}

	r = h.run("adopt", hp, "--url", u, "--disable-dhcp", "--disable-pnp")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.err)
	}
	if p.Autop(yealink.FieldServerURL) != u || p.Autop(yealink.FieldEnableDHCP) != "0" || p.Autop(yealink.FieldEnablePNP) != "0" {
		t.Fatal("settings not applied")
	}
	s = p.Snapshot()
	if len(s.Writes) != 1 || s.AutopNow != 1 {
		t.Fatalf("writes=%d autopnow=%d", len(s.Writes), s.AutopNow)
	}
	if !s.Writes[0].Has("token") {
		t.Fatal("write without CSRF token")
	}

	// nothing to change: exit 6, nothing sent
	r = h.run("adopt", hp, "--url", u, "--disable-dhcp")
	if r.code != ExitNoChange {
		t.Fatalf("want 6, got %d %s", r.code, r.err)
	}
	if got := p.Snapshot(); len(got.Writes) != 1 || got.AutopNow != 1 {
		t.Fatal("unchanged adopt must send nothing")
	}
	// --force rewrites
	r = h.run("adopt", hp, "--url", u, "--force")
	if r.code != 0 {
		t.Fatalf("force: %d %s", r.code, r.err)
	}
	if got := p.Snapshot(); len(got.Writes) != 2 || got.AutopNow != 2 {
		t.Fatalf("force should write once more: %+v", got)
	}
	// only the requested fields travel
	last := p.Snapshot().Writes[1]
	if len(last) != 2 || last.Get(yealink.FieldServerURL) != u {
		t.Fatalf("body %v", last)
	}
	// JSON result
	r = h.run("--json", "adopt", hp, "--url", u, "--force", "--dry-run")
	golden(t, "adopt_dry_run_json", r.stdout)
}

func TestAdoptPartial(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	p.Do(func(p *fakephone.Phone) { p.FailAutopNow = true })
	h := newHarness(t)
	r := h.run("--trust-new", "adopt", host(p), "--url", "https://pbx.example.net/p/", "--force")
	if r.code != ExitPartial {
		t.Fatalf("want 7, got %d %s", r.code, r.err)
	}
}

func TestAdoptRejectedWrite(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	p.Do(func(p *fakephone.Phone) { p.RejectWrites = true })
	h := newHarness(t)
	r := h.run("--trust-new", "adopt", host(p), "--url", "https://pbx.example.net/p/")
	if r.code != ExitError || p.Snapshot().AutopNow != 0 {
		t.Fatalf("%d %s autopnow=%d", r.code, r.err, p.Snapshot().AutopNow)
	}
}

func TestAutopSet(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	h := newHarness(t)
	hp := host(p)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--trust-new", "autop", "set", hp, "RepeatMinutes=61", "--dry-run"}, 0},
		{[]string{"autop", "set", hp, "RepeatMinutes=61"}, 0},
		{[]string{"autop", "set", hp, "AutoProvisionRepeatMinutes=61"}, ExitNoChange},
		{[]string{"autop", "set", hp, "RepeatMinutes=60"}, 0},
		{[]string{"autop", "set", hp, "AESKey16=abc"}, ExitUsage},
		{[]string{"autop", "set", hp, "Nonexistent=1"}, ExitError},
		{[]string{"autop", "set", hp, "RepeatMinutes"}, ExitUsage},
	} {
		if r := h.run(tc.args...); r.code != tc.code {
			t.Errorf("%v: want %d got %d (%s)", tc.args, tc.code, r.code, r.err)
		}
	}
	if p.Autop("AutoProvisionRepeatMinutes") != "60" {
		t.Error("not restored")
	}
	if n := len(p.Snapshot().Writes); n != 2 {
		t.Errorf("writes %d", n)
	}
}

func TestProvisionNowCmd(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	h := newHarness(t)
	if r := h.run("--trust-new", "provision-now", host(p)); r.code != 0 {
		t.Fatal(r.err)
	}
	if p.Snapshot().AutopNow != 1 {
		t.Fatal("not called")
	}
}

func TestTrustOnFirstUse(t *testing.T) {
	p := fakephone.New(fakephone.Options{})
	defer p.Close()
	h := newHarness(t)
	r := h.run("info", host(p))
	if r.code != ExitError || !strings.Contains(r.err, "--trust-new") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	// interactive: answer yes
	h.tty, h.stdin = true, "y\n"
	h.env["YLCTL_PASSWORD"] = "admin"
	r = h.run("info", host(p))
	if r.code != 0 || !strings.Contains(r.err, "SHA-256 fingerprint") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	h.tty = false
	if r := h.run("info", host(p)); r.code != 0 {
		t.Fatalf("pinned phone needs no flag: %s", r.err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(h.env["YLCTL_CONFIG_DIR"], "known_phones.json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%v %v", fi, err)
		}
	}
	p.SwapCertificate()
	r = h.run("--trust-new", "info", host(p))
	if r.code != ExitError || !strings.Contains(r.err, "changed") {
		t.Fatalf("cert change must be a hard error: %d %s", r.code, r.err)
	}
	if r := h.run("--insecure", "info", host(p)); r.code != 0 {
		t.Fatalf("--insecure: %s", r.err)
	}
}

func TestDiscover(t *testing.T) {
	p := fakephone.New(fakephone.Options{Variant: "A"})
	defer p.Close()
	u, _ := url.Parse(p.URL)
	port := u.Port()
	h := newHarness(t)

	// consent
	if r := h.run("discover", "127.0.0.1/32", "--ports", port); r.code != ExitUsage || !strings.Contains(r.err, "--yes") {
		t.Errorf("no tty, no --yes: %d %s", r.code, r.err)
	}
	h.tty, h.stdin = true, "n\n"
	if r := h.run("discover", "127.0.0.1/32", "--ports", port); r.code != ExitError || !strings.Contains(r.err, "nothing was sent") {
		t.Errorf("declined: %d %s", r.code, r.err)
	}
	h.tty, h.stdin = true, "y\n"
	r := h.run("discover", "127.0.0.1/32", "--ports", port)
	if r.code != 0 || !strings.Contains(r.stdout, "T41S") {
		t.Errorf("accepted: %d %s %s", r.code, r.err, r.stdout)
	}
	h.tty = false
	r = h.run("discover", "--yes", "127.0.0.1/32", "--ports", port)
	golden(t, "discover_table", r.stdout)
	r = h.run("discover", "--yes", "--json", "127.0.0.1/32", "--ports", port)
	golden(t, "discover_json", r.stdout)
	if n := p.Snapshot().LoginAttempts; n != 0 {
		t.Errorf("discover must never log in (%d)", n)
	}
	// nothing there
	r = h.run("discover", "--yes", "127.0.0.2/32", "--ports", "1")
	if r.code != 0 || !strings.Contains(r.stdout, "no Yealink phones found") {
		t.Errorf("%d %s", r.code, r.stdout)
	}
	// safety rails
	for _, args := range [][]string{
		{"discover", "--yes", "8.8.8.0/24"},
		{"discover", "--yes", "10.0.0.0/8"},
		{"discover", "--yes", "10.0.0.0/21", "--ports", "1"}, // /21 > /22 range allowed? no: larger than /22
		{"discover", "--yes", "nonsense"},
		{"discover", "--yes", "::1/128"},
	} {
		if r := h.run(args...); r.code != ExitUsage {
			t.Errorf("%v: want usage error, got %d %s", args, r.code, r.err)
		}
	}
}

func TestDiscoverLocalSubnetDefault(t *testing.T) {
	h := newHarness(t)
	var out, errb bytes.Buffer
	env := &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return h.env[k] },
		Subnets: func() ([]string, error) { return []string{"127.0.0.0/30"}, nil }}
	if code := RunContext(context.Background(), []string{"discover", "--yes", "--ports", "1"}, env); code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "scanning 2 addresses in 127.0.0.0/30") {
		t.Fatal(errb.String())
	}
}

type fakeRunner struct {
	have  map[string]bool
	store map[string]string
	calls []string
	stdin []string
}

func (f *fakeRunner) LookPath(n string) (string, error) {
	if f.have[n] {
		return "/bin/" + n, nil
	}
	return "", errors.New("not found")
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.stdin = append(f.stdin, stdin)
	if len(args) > 0 && (args[0] == "find-generic-password" || args[0] == "lookup") {
		acct := args[len(args)-2]
		if name == "security" {
			acct = args[4]
		}
		if v, ok := f.store[acct]; ok {
			return v + "\n", nil
		}
		return "", errors.New("not found")
	}
	return "", nil
}

func TestPasswordFromKeychain(t *testing.T) {
	p := fakephone.New(fakephone.Options{Password: "from-keychain"})
	defer p.Close()
	h := newHarness(t)
	delete(h.env, "YLCTL_PASSWORD")
	hp := host(p)
	h.runner = &fakeRunner{have: map[string]bool{"security": true, "secret-tool": true}, store: map[string]string{"admin@" + hp: "from-keychain"}}
	if runtime.GOOS == "windows" {
		t.Skip("no keychain on windows")
	}
	r := h.run("--trust-new", "info", hp)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.err)
	}
	// the password must never be on a command line
	for _, c := range h.runner.(*fakeRunner).calls {
		if strings.Contains(c, "from-keychain") {
			t.Errorf("password in argv: %s", c)
		}
	}
}

func TestAuthSave(t *testing.T) {
	h := newHarness(t)
	fr := &fakeRunner{have: map[string]bool{"security": true, "secret-tool": true}, store: map[string]string{}}
	h.runner = fr
	var out, errb bytes.Buffer
	env := &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return "" }, Runner: fr,
		ReadPassword: func(string) (string, error) { return "hunter2-secret", nil }}
	code := RunContext(context.Background(), []string{"auth", "save", "10.1.2.3"}, env)
	if code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	for i, c := range fr.calls {
		if strings.Contains(c, "hunter2-secret") {
			t.Errorf("password in argv: %s", c)
		}
		_ = i
	}
	found := false
	for _, s := range fr.stdin {
		if strings.Contains(s, "hunter2-secret") {
			found = true
		}
	}
	if !found {
		t.Error("password should be passed on stdin")
	}
	if strings.Contains(out.String()+errb.String(), "hunter2-secret") {
		t.Error("password echoed")
	}
	// no terminal: refuse
	env.ReadPassword = nil
	if code := RunContext(context.Background(), []string{"auth", "save", "10.1.2.3"}, env); code != ExitUsage {
		t.Errorf("no terminal: %d", code)
	}
}
