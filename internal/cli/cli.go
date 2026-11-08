// Package cli implements the ylctl command line.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/yealink"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitUnreachable = 3
	ExitAuth        = 4
	ExitLocked      = 5
	ExitNoChange    = 6
	ExitPartial     = 7
)

// Build information, set with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Env is everything the commands take from the outside world.
type Env struct {
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
	Getenv       func(string) string
	StdinIsTTY   bool
	StdoutIsTTY  bool                                // output is a terminal (a change that cannot be undone needs one, or --yes)
	ReadPassword func(prompt string) (string, error) // nil when there is no terminal
	Runner       creds.Runner
	Subnets      func() ([]string, error) // local subnets for discover; nil uses the real ones
	NoColor      bool
}

// OSEnv is the environment of a real process.
func OSEnv() *Env {
	tty := term.IsTerminal(int(os.Stdin.Fd()))
	e := &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, StdinIsTTY: tty, StdoutIsTTY: term.IsTerminal(int(os.Stdout.Fd())), Runner: creds.ExecRunner{}}
	if tty {
		e.ReadPassword = func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
	}
	return e
}

type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string { return e.err.Error() }
func (e *exitErr) Unwrap() error { return e.err }

func usageErr(format string, a ...any) error {
	return &exitErr{ExitUsage, fmt.Errorf(format, a...)}
}

// classify turns any error into an exit code.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var ee *exitErr
	if errors.As(err, &ee) {
		return err
	}
	code := ExitError
	var ne net.Error
	var op *net.OpError
	switch {
	case errors.Is(err, yealink.ErrLocked):
		code = ExitLocked
	case errors.Is(err, yealink.ErrAuthFailed):
		code = ExitAuth
	case errors.Is(err, creds.ErrNoPassword):
		code = ExitUsage
	case errors.As(err, new(*yealink.CertChangedError)), errors.As(err, new(*yealink.UntrustedError)):
		code = ExitError
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne), errors.As(err, &op):
		code = ExitUnreachable
	}
	return &exitErr{code, err}
}

type app struct {
	env *Env
	// global flags
	user       string
	jsonOut    bool
	timeout    time.Duration
	trustNew   bool
	noColor    bool
	insecure   bool
	tryDefault bool
	reveal     bool
	mac        string
	rd         *bufio.Reader
	crlf       bool // raw terminal: output needs \r\n
	firstPin   bool
	barRows    int // >0 while the key bar is pinned to this terminal row
	ctx        context.Context
	in         *bufio.Reader // shared reader of stdin for line prompts
}

// Run executes the command line and returns the process exit code.
func Run(args []string, env *Env) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunContext(ctx, args, env)
}

// RunContext is Run with a caller supplied context.
func RunContext(ctx context.Context, args []string, env *Env) int {
	a := &app{env: env, ctx: ctx}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *exitErr
	if !errors.As(err, &ee) {
		// cobra's own errors: unknown command, bad flag, wrong argument count
		ee = &exitErr{ExitUsage, err}
	}
	fmt.Fprintf(env.Stderr, "ylctl: %s\n", ee.err)
	if ee.code == ExitUsage {
		fmt.Fprintln(env.Stderr, "Run 'ylctl --help' for usage.")
	}
	return ee.code
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ylctl",
		Short:         "Diagnose and bring up Yealink desk phones from a laptop on the same network",
		Long:          "ylctl talks to the web interface of Yealink desk phones on your own network.\nIt is not affiliated with Yealink. Passwords come from the environment (YLCTL_PASSWORD),\nthe OS keychain or a prompt, never from a flag.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.isInteractive() {
				return a.interactive()
			}
			return cmd.Help()
		},
	}
	f := root.PersistentFlags()
	f.StringVar(&a.user, "user", "", "web user name (default admin, or $YLCTL_USER)")
	f.BoolVar(&a.jsonOut, "json", false, "machine readable JSON output")
	f.DurationVar(&a.timeout, "timeout", 10*time.Second, "timeout per request")
	f.BoolVar(&a.trustNew, "trust-new", false, "pin the TLS certificate of a phone seen for the first time without asking")
	f.BoolVar(&a.noColor, "no-color", false, "disable colored output")
	f.BoolVar(&a.insecure, "insecure", false, "do not verify the phone's TLS certificate at all (escape hatch)")
	f.BoolVar(&a.tryDefault, "try-default", false, "try the factory login admin/admin once instead of a stored password")
	f.StringVar(&a.mac, "mac", "", "fetch this phone's admin password (by MAC) from the linked server's vault; see 'ylctl login'")
	f.BoolVar(&a.reveal, "reveal", false, "show provisioning URLs in full (they contain a token)")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &exitErr{ExitUsage, err} })

	defHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if a.helpToViewer() {
			// On a terminal, help opens on the alternate screen (like man): closing it leaves the
			// terminal exactly as it was, with only the command you typed. 'p' keeps it on screen.
			var buf bytes.Buffer
			if c.Parent() == nil {
				a.bannerTo(func(s string) { buf.WriteString(s) })
			}
			orig := c.OutOrStdout()
			c.SetOut(&buf)
			defHelp(c, args)
			c.SetOut(orig)
			if a.showInViewer("ylctl "+strings.TrimPrefix(c.CommandPath(), "ylctl "), buf.String()) {
				fmt.Fprint(a.out(), buf.String())
			}
			return
		}
		if c.Parent() == nil {
			a.banner()
		}
		defHelp(c, args)
	})
	root.AddCommand(a.versionCmd(), a.discoverCmd(), a.infoCmd(), a.statusCmd(), a.autopCmd(),
		a.accountCmd(), a.provisionNowCmd(), a.rebootCmd(), a.pushCmd(), a.logoCmd(), a.adoptCmd(), a.authCmd(), a.screensaverCmd(), a.captureCmd(), a.logsCmd(), a.passwordCmd(), a.loginCmd(), a.logoutCmd(), a.whoamiCmd(), a.reconCmd())
	return root
}

// ---- helpers ----

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

func (a *app) out() io.Writer {
	if a.crlf {
		return crlfWriter{a.env.Stdout}
	}
	return a.env.Stdout
}
func (a *app) errw() io.Writer {
	if a.crlf {
		return crlfWriter{a.env.Stderr}
	}
	return a.env.Stderr
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.out())
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func (a *app) table() *tabwriter.Writer { return tabwriter.NewWriter(a.out(), 0, 8, 2, ' ', 0) }

func (a *app) color(code, s string) string {
	if a.noColor || a.env.NoColor || a.env.Getenv("NO_COLOR") != "" {
		return s
	}
	f, ok := a.env.Stderr.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (a *app) warnf(format string, args ...any) {
	fmt.Fprintln(a.errw(), a.color("33", "warning: ")+fmt.Sprintf(format, args...))
}

// confirm asks a yes/no question on stderr; it only works when stdin is a terminal.
func (a *app) confirm(question string) bool {
	if !a.env.StdinIsTTY {
		return false
	}
	fmt.Fprintf(a.errw(), "%s [y/N] ", question)
	line, _ := bufio.NewReader(a.env.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func (a *app) pinStore() (*yealink.PinStore, error) {
	d, err := yealink.ConfigDir(a.env.Getenv)
	if err != nil {
		return nil, err
	}
	return yealink.OpenPinStore(filepath.Join(d, "known_phones.json"))
}

// newClient builds a client for host (no network traffic yet).
func (a *app) newClient(host string) (*yealink.Client, error) {
	pins, err := a.pinStore()
	if err != nil {
		return nil, err
	}
	opts := yealink.Options{Timeout: a.timeout, Pins: pins, TrustNew: a.trustNew, Insecure: a.insecure}
	if a.env.StdinIsTTY {
		opts.Confirm = func(h, fp string) bool {
			fmt.Fprintf(a.errw(), "The phone %s presents a certificate you have not trusted before.\nSHA-256 fingerprint: %s\n", h, fp)
			return a.confirm("Trust this certificate and remember it?")
		}
	}
	c, err := yealink.New(host, opts)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	return c, nil
}

// connect opens a logged-in client for host.
func (a *app) connect(host string) (*yealink.Client, *creds.Credentials, error) {
	c, err := a.newClient(host)
	if err != nil {
		return nil, nil, err
	}
	co := creds.Options{Host: c.Target().Label(), User: a.user, TryDefault: a.tryDefault, Getenv: a.env.Getenv, Runner: a.env.Runner}
	if a.env.ReadPassword != nil {
		co.Prompt = a.env.ReadPassword
	}
	var cr *creds.Credentials
	if a.mac != "" {
		cr, err = a.vaultCreds(a.mac)
	} else {
		cr, err = creds.Resolve(a.ctx, co)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := c.Login(a.ctx, cr.User, cr.Password); err != nil {
		return nil, nil, err
	}
	if cr.IsDefault {
		a.warnf("default password in use on %s: the factory login admin/admin worked. Change it.", c.Target().Label())
	}
	return c, cr, nil
}

// run wraps a RunE so that every error gets an exit code.
func run(f func(cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error { return classify(f(cmd, args)) }
}

func hostArg(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return usageErr("%s needs exactly one <host> argument", cmd.CommandPath())
	}
	return nil
}
