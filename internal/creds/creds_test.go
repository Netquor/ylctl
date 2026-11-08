package creds

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fake struct {
	have  map[string]bool
	store map[string]string
	calls [][]string
	stdin []string
}

func (f *fake) LookPath(n string) (string, error) {
	if f.have[n] {
		return "/x/" + n, nil
	}
	return "", errors.New("missing")
}

func (f *fake) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	f.stdin = append(f.stdin, stdin)
	for i, a := range args {
		if a == "-a" || a == "account" {
			if v, ok := f.store[args[i+1]]; ok && (args[0] == "find-generic-password" || args[0] == "lookup") {
				return v + "\n", nil
			}
		}
	}
	if args[0] == "find-generic-password" || args[0] == "lookup" {
		return "", errors.New("not found")
	}
	return "", nil
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolveOrder(t *testing.T) {
	ctx := context.Background()
	f := &fake{have: map[string]bool{"security": true, "secret-tool": true}, store: map[string]string{"admin@10.0.0.1": "kc"}}
	prompted := 0
	prompt := func(string) (string, error) { prompted++; return "typed", nil }

	// env wins over keychain and prompt
	c, err := Resolve(ctx, Options{Host: "10.0.0.1", Getenv: env(map[string]string{"YLCTL_PASSWORD": "fromenv", "YLCTL_USER": "bob"}), Runner: f, GOOS: "darwin", Prompt: prompt})
	if err != nil || c.Password != "fromenv" || c.User != "bob" || c.Source != "env" {
		t.Fatalf("%+v %v", c, err)
	}
	// --user flag beats YLCTL_USER
	c, _ = Resolve(ctx, Options{Host: "h", User: "alice", Getenv: env(map[string]string{"YLCTL_PASSWORD": "x", "YLCTL_USER": "bob"})})
	if c.User != "alice" {
		t.Fatalf("%+v", c)
	}
	// keychain next (darwin and linux)
	for _, goos := range []string{"darwin", "linux"} {
		c, err = Resolve(ctx, Options{Host: "10.0.0.1", Getenv: env(nil), Runner: f, GOOS: goos, Prompt: prompt})
		if err != nil || c.Password != "kc" || c.Source != "keychain" {
			t.Fatalf("%s: %+v %v", goos, c, err)
		}
	}
	// then the prompt
	c, err = Resolve(ctx, Options{Host: "other", Getenv: env(nil), Runner: f, GOOS: "darwin", Prompt: prompt})
	if err != nil || c.Password != "typed" || prompted != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	// no keychain helper: straight to the prompt; no prompt: error
	f2 := &fake{have: map[string]bool{}}
	if _, err = Resolve(ctx, Options{Host: "h", Getenv: env(nil), Runner: f2, GOOS: "linux"}); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("%v", err)
	}
	if len(f2.calls) != 0 {
		t.Fatal("helper missing: must not run anything")
	}
	// windows: no keychain
	if _, err = Resolve(ctx, Options{Host: "h", Getenv: env(nil), Runner: f, GOOS: "windows"}); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("%v", err)
	}
}

func TestTryDefault(t *testing.T) {
	c, err := Resolve(context.Background(), Options{TryDefault: true, Getenv: env(map[string]string{"YLCTL_PASSWORD": "ignored"})})
	if err != nil || !c.IsDefault || c.Password != "admin" || c.User != "admin" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err = Resolve(context.Background(), Options{TryDefault: true, User: "root"}); err == nil {
		t.Fatal("only for admin")
	}
}

func TestSaveKeepsSecretOffTheCommandLine(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		f := &fake{have: map[string]bool{"security": true, "secret-tool": true}}
		if err := Save(context.Background(), Options{Host: "10.0.0.1", Runner: f, GOOS: goos}, "admin", `pa"ss\word`); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.calls {
			if strings.Contains(strings.Join(c, " "), "pa") && strings.Contains(strings.Join(c, " "), "word") {
				t.Errorf("%s: secret in argv %v", goos, c)
			}
		}
		if !strings.Contains(f.stdin[0], "word") {
			t.Errorf("%s: secret not on stdin", goos)
		}
	}
	f := &fake{have: map[string]bool{}}
	if err := Save(context.Background(), Options{Host: "h", Runner: f, GOOS: "linux"}, "admin", "x"); !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("%v", err)
	}
	if err := Save(context.Background(), Options{Host: "h", Runner: f, GOOS: "darwin"}, "admin", "a\nb"); err == nil {
		t.Fatal("line break must be refused")
	}
}
