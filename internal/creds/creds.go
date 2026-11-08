// Package creds finds the phone web password. It is never read from a flag or
// an argument: environment, OS keychain (when the helper exists), or a prompt.
package creds

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Runner runs an external command (the keychain helpers). It exists so tests
// can fake the OS.
type Runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, stdin string, name string, args ...string) (string, error)
}

// ExecRunner is the real Runner.
type ExecRunner struct{}

// LookPath implements Runner.
func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// Service is the keychain service name.
const Service = "ylctl"

// Credentials are what the login uses.
type Credentials struct {
	User      string
	Password  string
	Source    string // flag-free: env, keychain, prompt, default
	IsDefault bool   // the factory default admin/admin
}

// Options for Resolve.
type Options struct {
	Host       string // label used for the keychain entry
	User       string // from --user, may be empty
	TryDefault bool
	Getenv     func(string) string
	Runner     Runner
	GOOS       string
	Prompt     func(label string) (string, error) // nil when no terminal
}

// ErrNoPassword means nothing supplied a password.
var ErrNoPassword = errors.New("no password: set YLCTL_PASSWORD, store one with 'ylctl auth save <host>', run on a terminal for a prompt, or pass --try-default to try the factory default once")

// Resolve picks the user and password.
func Resolve(ctx context.Context, o Options) (*Credentials, error) {
	user := o.User
	if user == "" && o.Getenv != nil {
		user = o.Getenv("YLCTL_USER")
	}
	if user == "" {
		user = "admin"
	}
	if o.TryDefault {
		if user != "admin" {
			return nil, fmt.Errorf("--try-default only applies to the factory user admin, not %q", user)
		}
		return &Credentials{User: "admin", Password: "admin", Source: "default", IsDefault: true}, nil
	}
	if o.Getenv != nil {
		if pw := o.Getenv("YLCTL_PASSWORD"); pw != "" {
			return &Credentials{User: user, Password: pw, Source: "env"}, nil
		}
	}
	if pw, ok := lookup(ctx, o, user); ok {
		return &Credentials{User: user, Password: pw, Source: "keychain"}, nil
	}
	if o.Prompt != nil {
		pw, err := o.Prompt(fmt.Sprintf("Password for %s@%s: ", user, o.Host))
		if err != nil {
			return nil, err
		}
		if pw == "" {
			return nil, ErrNoPassword
		}
		return &Credentials{User: user, Password: pw, Source: "prompt"}, nil
	}
	return nil, ErrNoPassword
}

func goos(o Options) string {
	if o.GOOS != "" {
		return o.GOOS
	}
	return runtime.GOOS
}

func accounts(host, user string) []string {
	return []string{user + "@" + host, user}
}

func lookup(ctx context.Context, o Options, user string) (string, bool) {
	if o.Runner == nil {
		return "", false
	}
	for _, acct := range accounts(o.Host, user) {
		switch goos(o) {
		case "darwin":
			if _, err := o.Runner.LookPath("security"); err != nil {
				return "", false
			}
			out, err := o.Runner.Run(ctx, "", "security", "find-generic-password", "-s", Service, "-a", acct, "-w")
			if err == nil && strings.TrimRight(out, "\r\n") != "" {
				return strings.TrimRight(out, "\r\n"), true
			}
		case "linux":
			if _, err := o.Runner.LookPath("secret-tool"); err != nil {
				return "", false
			}
			out, err := o.Runner.Run(ctx, "", "secret-tool", "lookup", "service", Service, "account", acct)
			if err == nil && strings.TrimRight(out, "\r\n") != "" {
				return strings.TrimRight(out, "\r\n"), true
			}
		default:
			return "", false
		}
	}
	return "", false
}

// ErrNoKeychain means this system has no supported keychain helper.
var ErrNoKeychain = errors.New("no supported keychain helper found (macOS 'security' or Linux 'secret-tool')")

// Save stores a password for user@host. The password goes to the helper on
// stdin, never in an argument list.
func Save(ctx context.Context, o Options, user, password string) error {
	acct := user + "@" + o.Host
	if strings.ContainsAny(password, "\r\n") {
		return errors.New("password contains a line break")
	}
	switch goos(o) {
	case "darwin":
		if _, err := o.Runner.LookPath("security"); err != nil {
			return ErrNoKeychain
		}
		// 'security -i' reads commands from stdin, so the secret is not visible in 'ps'.
		cmd := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", Service, shellQuote(acct), shellQuote(password))
		_, err := o.Runner.Run(ctx, cmd, "security", "-i")
		return err
	case "linux":
		if _, err := o.Runner.LookPath("secret-tool"); err != nil {
			return ErrNoKeychain
		}
		_, err := o.Runner.Run(ctx, password, "secret-tool", "store", "--label=ylctl "+acct, "service", Service, "account", acct)
		return err
	}
	return ErrNoKeychain
}

// Forget removes a stored password.
func Forget(ctx context.Context, o Options, user string) error {
	acct := user + "@" + o.Host
	switch goos(o) {
	case "darwin":
		if _, err := o.Runner.LookPath("security"); err != nil {
			return ErrNoKeychain
		}
		_, err := o.Runner.Run(ctx, "", "security", "delete-generic-password", "-s", Service, "-a", acct)
		return err
	case "linux":
		if _, err := o.Runner.LookPath("secret-tool"); err != nil {
			return ErrNoKeychain
		}
		_, err := o.Runner.Run(ctx, "", "secret-tool", "clear", "service", Service, "account", acct)
		return err
	}
	return ErrNoKeychain
}

func shellQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Get returns a stored secret for user@host from the keychain, if there is one.
func Get(ctx context.Context, o Options, user string) (string, bool) { return lookup(ctx, o, user) }
