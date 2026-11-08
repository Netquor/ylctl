package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/pbx"
	"github.com/Netquor/ylctl/internal/yealink"
)

// pwRetryDelay is the pause between tries of the vault commit (a variable so tests need no waiting).
var pwRetryDelay = 2 * time.Second

// pendingPW is a new password recorded before the phone was changed.
type pendingPW struct {
	ID       string
	Password string
	Expired  bool
}

// pwStore is where the new password is kept in step with the phone.
type pwStore interface {
	Name() string
	Persistent() bool
	// Begin records newPW as pending, leaving the current value alone.
	Begin(ctx context.Context, newPW string) (id string, err error)
	// Commit makes the pending value the current one.
	Commit(ctx context.Context, id, newPW string) error
	// Abort drops the pending value.
	Abort(ctx context.Context, id string) error
	// Pending returns an unfinished change, or nil.
	Pending(ctx context.Context) (*pendingPW, error)
}

// ---- store: nothing (the person typed it and keeps it) ----

type nullStore struct{}

func (nullStore) Name() string                                  { return "nowhere (you typed it and must remember it)" }
func (nullStore) Persistent() bool                              { return false }
func (nullStore) Begin(context.Context, string) (string, error) { return "", nil }
func (nullStore) Commit(context.Context, string, string) error  { return nil }
func (nullStore) Abort(context.Context, string) error           { return nil }
func (nullStore) Pending(context.Context) (*pendingPW, error)   { return nil, nil }

// ---- store: the linked server's vault ----

type vaultStore struct {
	c      *pbx.Client
	server string
	mac    string
	reason string
}

func (v *vaultStore) Name() string     { return "the vault on " + v.server }
func (v *vaultStore) Persistent() bool { return true }

func (v *vaultStore) Begin(ctx context.Context, pw string) (string, error) {
	r, err := v.c.BeginRotation(ctx, v.mac, pw, v.reason)
	var pend *pbx.ErrRotationPending
	if errors.As(err, &pend) {
		return "", fmt.Errorf("the vault already holds an unfinished password change for this phone (id %s). Finish or undo it first: ylctl password recover <host> --mac %s", pend.Rotation.ID, v.mac)
	}
	var ae *pbx.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 403:
			return "", errors.New("the server refused: this link may not take part in a password change (a read-only link cannot; relink with a normal one)")
		case 404:
			return "", errors.New("the server has no stored admin password for that phone to rotate; set the current one on the server first")
		case 400:
			return "", fmt.Errorf("the server refused the new value: %s", ae.Msg)
		}
	}
	return r.ID, err
}

func (v *vaultStore) Commit(ctx context.Context, id, pw string) error {
	err := v.c.CommitRotation(ctx, v.mac, id, v.reason)
	var ae *pbx.APIError
	if errors.As(err, &ae) && ae.Status == 410 {
		// The pending value timed out (the change took over an hour to finish). The phone has this
		// password, so record it again as a fresh pending value and commit that.
		nid, berr := v.Begin(ctx, pw)
		if berr != nil {
			return berr
		}
		return v.c.CommitRotation(ctx, v.mac, nid, v.reason)
	}
	return err
}

func (v *vaultStore) Abort(ctx context.Context, id string) error {
	return v.c.AbortRotation(ctx, v.mac, id, v.reason)
}

func (v *vaultStore) Pending(ctx context.Context) (*pendingPW, error) {
	p, err := v.c.PendingRotation(ctx, v.mac, v.reason)
	var ae *pbx.APIError
	if errors.As(err, &ae) && ae.Status == 404 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pendingPW{ID: p.ID, Password: p.Secret, Expired: p.State == "expired"}, nil
}

// ---- store: the OS keychain ----

type keychainStore struct {
	ctx  context.Context
	o    creds.Options // Host is the phone's label
	user string
}

func (k *keychainStore) Name() string     { return "the OS keychain" }
func (k *keychainStore) Persistent() bool { return true }
func (k *keychainStore) pendingOpts() creds.Options {
	o := k.o
	o.Host += "#pending"
	return o
}

func (k *keychainStore) Begin(ctx context.Context, pw string) (string, error) {
	return "keychain", creds.Save(ctx, k.pendingOpts(), k.user, pw)
}
func (k *keychainStore) Commit(ctx context.Context, _, pw string) error {
	if err := creds.Save(ctx, k.o, k.user, pw); err != nil {
		return err
	}
	_ = creds.Forget(ctx, k.pendingOpts(), k.user)
	return nil
}
func (k *keychainStore) Abort(ctx context.Context, _ string) error {
	return creds.Forget(ctx, k.pendingOpts(), k.user)
}
func (k *keychainStore) Pending(ctx context.Context) (*pendingPW, error) {
	if pw, ok := creds.Get(ctx, k.pendingOpts(), k.user); ok {
		return &pendingPW{ID: "keychain", Password: pw}, nil
	}
	return nil, nil
}

// ---- commands ----

type pwFlags struct {
	generate, prompt, dry, yes, understand, keychain bool
	length                                           int
}

func (a *app) passwordCmd() *cobra.Command {
	pw := &cobra.Command{Use: "password", Short: "Change the phone's web admin password safely, keeping the server vault or keychain in step",
		Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	var f pwFlags
	set := &cobra.Command{
		Use: "set <host>", Short: "Change the web admin password (cannot be undone from here; read the plan)", Args: hostArg,
		Long: "Changes the phone's web admin password (Security > Password) and keeps the place that holds it in step,\n" +
			"in an order that cannot lose the password:\n\n" +
			"  1. the new password is recorded as PENDING in the server vault (--mac) or the OS keychain (--keychain);\n" +
			"  2. the phone is changed;\n" +
			"  3. a fresh session logs in with the new password to prove it;\n" +
			"  4. the pending value is committed. If the phone refuses, the pending value is dropped and the old one stays.\n\n" +
			"The new password is either generated (--generate: 20 characters, no look-alikes) or typed twice at a prompt\n" +
			"(--prompt). It is never accepted on the command line and never printed. The old password comes from the usual\n" +
			"places (--mac vault, YLCTL_PASSWORD, keychain, prompt). Needs a terminal or --yes, an idle phone, a phone you\n" +
			"already trust (run 'ylctl info' once), and you typing the phone's address or the last 4 characters of its MAC\n" +
			"unless --yes-i-understand is given. --dry-run does every read-only check and the plan, and changes nothing.\n" +
			"Only the 'admin' web user is supported.",
		RunE: run(func(_ *cobra.Command, args []string) error { return a.passwordSet(args[0], f) }),
	}
	set.Flags().BoolVar(&f.generate, "generate", false, "make a strong random password (needs --mac or --keychain to keep it)")
	set.Flags().BoolVar(&f.prompt, "prompt", false, "type the new password twice at a prompt (no echo)")
	set.Flags().IntVar(&f.length, "length", 20, "length of a generated password (12 to 32)")
	set.Flags().BoolVar(&f.keychain, "keychain", false, "keep the new password in the OS keychain instead of the server vault")
	set.Flags().BoolVar(&f.dry, "dry-run", false, "do the read-only checks, show the plan, change nothing")
	set.Flags().BoolVar(&f.yes, "yes", false, "run without a terminal (the typed confirmation is still needed unless --yes-i-understand)")
	set.Flags().BoolVar(&f.understand, "yes-i-understand", false, "skip typing the phone's address: you know this changes the only way into the phone")

	var rf pwFlags
	rec := &cobra.Command{
		Use: "recover <host>", Short: "Finish or undo a password change that was interrupted", Args: hostArg,
		Long: "If 'password set' was interrupted (or could not verify), the new password is still pending in the vault\n" +
			"(--mac) or the keychain (--keychain). This logs in with the pending value: if the phone accepts it the change\n" +
			"is committed; if not, it logs in with the current value and, if that works, drops the pending one. At most\n" +
			"two login attempts are made. If neither works the pending value stays and you are told how to proceed.",
		RunE: run(func(_ *cobra.Command, args []string) error { return a.passwordRecover(args[0], rf) }),
	}
	rec.Flags().BoolVar(&rf.keychain, "keychain", false, "the pending password is in the OS keychain")
	pw.AddCommand(set, rec)
	return pw
}

func (a *app) line() (string, error) {
	if a.in == nil {
		a.in = bufio.NewReader(a.env.Stdin)
	}
	s, err := a.in.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func normMAC(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(s))
}

// pwStoreFor picks where the new password is kept.
func (a *app) pwStoreFor(label string, f pwFlags, user string, canBeNothing bool, oldSource string) (pwStore, error) {
	switch {
	case a.mac != "" && f.keychain:
		return nil, usageErr("choose one place to keep the password: --mac (server vault) or --keychain, not both")
	case a.mac != "":
		c, l, err := a.pbxClient()
		if err != nil {
			return nil, err
		}
		return &vaultStore{c: c, server: l.Server, mac: normMAC(a.mac), reason: "ylctl password set"}, nil
	case f.keychain || oldSource == "keychain":
		o := creds.Options{Host: label, Getenv: a.env.Getenv, Runner: a.env.Runner}
		if !creds.KeychainAvailable(o) {
			return nil, usageErr("this system has no supported keychain helper (macOS 'security' or Linux 'secret-tool'); use --mac with a linked server instead")
		}
		return &keychainStore{ctx: a.ctx, o: o, user: user}, nil
	case canBeNothing:
		return nullStore{}, nil
	}
	return nil, usageErr("--generate needs somewhere to keep the new password, because you will never see it: use --mac (server vault) or --keychain")
}

// requirePinned refuses a phone whose certificate has not been trusted before.
func (a *app) requirePinned(host string) (yealink.Target, error) {
	t, err := yealink.ParseTarget(host)
	if err != nil {
		return t, usageErr("%v", err)
	}
	pins, err := a.pinStore()
	if err != nil {
		return t, err
	}
	if _, ok := pins.Get(t.HostPort()); !ok {
		return t, fmt.Errorf("%s is not a phone you have trusted yet. Check its certificate with 'ylctl info %s' first (this command never pins a new phone)", t.Label(), host)
	}
	return t, nil
}

func (a *app) passwordSet(host string, f pwFlags) error {
	if f.generate == f.prompt {
		return usageErr("choose exactly one of --generate and --prompt (the new password is never taken from the command line)")
	}
	if f.generate && (f.length < 12 || f.length > creds.MaxNewLength) {
		return usageErr("--length must be 12 to %d", creds.MaxNewLength)
	}
	if a.insecure || a.trustNew {
		return usageErr("--insecure and --trust-new are refused here: a password change only goes to a phone whose certificate you already trust")
	}
	if a.user != "" && a.user != "admin" {
		return usageErr("only the 'admin' web user's password can be changed")
	}
	if a.tryDefault && a.mac != "" {
		return usageErr("--try-default and --mac cannot be combined")
	}
	if f.prompt && !f.dry && a.env.ReadPassword == nil {
		return usageErr("--prompt needs a terminal to read the password from")
	}
	interactive := a.env.StdinIsTTY && a.env.StdoutIsTTY
	if !interactive && !f.yes && !f.dry {
		return usageErr("this needs a terminal, or --yes (plus --yes-i-understand) when run from a script")
	}
	t, err := a.requirePinned(host)
	if err != nil {
		return err
	}
	w := a.errw()

	// The old password and the first login: read-only from here to the plan.
	c, cr, err := a.connect(host)
	if err != nil {
		return err
	}
	if cr.User != "admin" {
		return usageErr("this session logged in as %q; only the admin password can be changed", cr.User)
	}
	st, err := c.Status(a.ctx)
	if err != nil {
		return err
	}
	info := st.Info
	if info.Model == "" || len(normMAC(info.MAC)) != 12 {
		return fmt.Errorf("%s does not answer like a phone I recognise (model %q, MAC %q): refusing", t.Label(), info.Model, info.MAC)
	}
	if a.mac != "" && normMAC(a.mac) != normMAC(info.MAC) {
		return fmt.Errorf("--mac %s is not this phone: %s has MAC %s. Refusing, so the wrong vault entry is never touched", a.mac, t.Label(), info.MAC)
	}
	talking, err := c.Talking(a.ctx)
	if err != nil {
		return fmt.Errorf("cannot tell whether a call is active, so not changing anything: %w", err)
	}
	if talking {
		return errors.New("a call is active on the phone: not changing the password now")
	}
	pp, err := c.PasswordPreflight(a.ctx)
	if err != nil {
		return err
	}
	if pp.LoginUser != "admin" {
		return fmt.Errorf("the phone says this session is user %q; only the admin password can be changed", pp.LoginUser)
	}
	store, err := a.pwStoreFor(t.Label(), f, "admin", f.prompt, cr.Source)
	if err != nil {
		return err
	}

	// The plan.
	how := "typed by you at a prompt (asked twice)"
	if f.generate {
		how = fmt.Sprintf("generated: %d random characters, no look-alikes, never shown", f.length)
	}
	fmt.Fprintf(w, "Password change for %s\n", t.Label())
	fmt.Fprintf(w, "  phone          %s, firmware %s, MAC %s\n", info.Model, info.Firmware, info.MAC)
	fmt.Fprintf(w, "  user           admin (logged in with the current password from %s)\n", cr.Source)
	fmt.Fprintf(w, "  new password   %s\n", how)
	fmt.Fprintf(w, "  kept in        %s\n", store.Name())
	fmt.Fprintf(w, "  checks passed  phone is pinned and answers as a %s, no call active, password page present\n", info.Model)
	fmt.Fprintln(w, "Steps:")
	if store.Persistent() {
		fmt.Fprintf(w, "  1. record the new password as PENDING in %s (the current one stays current)\n", store.Name())
	} else {
		fmt.Fprintln(w, "  1. (nothing to record: you keep the new password yourself)")
	}
	fmt.Fprintln(w, "  2. POST the change to the phone (mod_password, once, never repeated)")
	fmt.Fprintln(w, "  3. log in on a fresh session with the new password to prove it")
	fmt.Fprintln(w, "  4. commit the pending value; if the phone refused, drop it and nothing has changed")
	fmt.Fprintln(w, "Recovery if the phone and the record disagree: ylctl password recover (see docs/password.md).")
	fmt.Fprintln(w, "If the new password is ever lost, the only way back in is a factory reset from the phone's keypad.")
	if f.dry {
		fmt.Fprintln(w, "dry run: only reads were made (a login and GETs). Nothing was changed, nothing was recorded.")
		if a.jsonOut {
			return a.printJSON(map[string]any{"host": host, "mac": info.MAC, "dry_run": true, "kept_in": store.Name(), "checks": "ok"})
		}
		return nil
	}

	// Typed confirmation (R4).
	if !f.understand {
		if !a.env.StdinIsTTY {
			return usageErr("the typed confirmation needs a terminal; from a script pass --yes-i-understand as well")
		}
		last4 := normMAC(info.MAC)[8:]
		fmt.Fprintf(w, "To go ahead, type the phone's address (%s) or the last 4 characters of its MAC (%s): ", t.Label(), last4)
		got, err := a.line()
		if err != nil {
			return errors.New("no confirmation given: nothing was changed")
		}
		if !strings.EqualFold(got, t.Label()) && !strings.EqualFold(got, t.Host) && !strings.EqualFold(got, last4) {
			return errors.New("that is not the phone's address or the last 4 characters of its MAC: nothing was changed")
		}
	}

	// The new password.
	newPW, err := a.newPassword(f, cr.Password, "admin")
	if err != nil {
		return err
	}

	// 1. Record it first.
	fmt.Fprintln(w, "1. recording the new password as pending ...")
	id, err := store.Begin(a.ctx, newPW)
	if err != nil {
		return fmt.Errorf("could not record the new password in %s, so the phone was NOT changed: %w", store.Name(), err)
	}

	// A call may have started while the person was typing.
	if talking, err := c.Talking(a.ctx); err != nil || talking {
		a.dropPending(store, id)
		if err != nil {
			return fmt.Errorf("could not re-check the call state; the phone was not changed: %w", err)
		}
		return errors.New("a call started on the phone; the phone was not changed")
	}

	// 2. Change the phone.
	fmt.Fprintln(w, "2. changing the password on the phone ...")
	outcome, cerr := c.ChangeAdminPassword(a.ctx, cr.Password, newPW)
	switch outcome {
	case yealink.PasswordRejected:
		a.dropPending(store, id)
		return fmt.Errorf("the phone's password was NOT changed and the old one is still current: %w", cerr)
	case yealink.PasswordUnknown:
		fmt.Fprintf(w, "   no clear answer from the phone (%v). Finding out whether it changed ...\n", cerr)
	}

	// 3. Verify on a fresh session.
	fmt.Fprintln(w, "3. logging in on a fresh session with the new password ...")
	verr := a.loginWith(host, "admin", newPW)
	if verr != nil {
		if outcome == yealink.PasswordUnknown && errors.Is(verr, yealink.ErrAuthFailed) {
			// The phone did not take the new password. Is the old one still good?
			if oerr := a.loginWith(host, "admin", cr.Password); oerr == nil {
				a.dropPending(store, id)
				return fmt.Errorf("the phone's password was NOT changed (the old one still works): %v", cerr)
			}
		}
		return a.stateAfterFailedVerify(host, t.Label(), store, outcome, verr)
	}

	// 4. Commit.
	fmt.Fprintln(w, "4. committing ...")
	var last error
	for i := 0; i < 3; i++ {
		if last = store.Commit(a.ctx, id, newPW); last == nil {
			break
		}
		if i < 2 {
			select {
			case <-a.ctx.Done():
			case <-time.After(pwRetryDelay):
			}
		}
	}
	if last != nil {
		fmt.Fprintf(w, "\nThe phone HAS the new password and a fresh login with it works, but %s could not commit it: %v\n", store.Name(), last)
		fmt.Fprintf(w, "The new password is NOT lost: it is still pending there. Finish with:\n  ylctl password recover %s %s\n", host, a.recoverFlags())
		return &exitErr{ExitPartial, errors.New("phone changed and verified; commit not recorded")}
	}
	a.afterSuccessNotes(t.Label(), cr, store)
	if a.jsonOut {
		return a.printJSON(map[string]any{"host": host, "mac": info.MAC, "changed": true, "verified": true, "committed": true, "kept_in": store.Name()})
	}
	fmt.Fprintf(a.out(), "password changed on %s, verified with a fresh login, and recorded in %s\n", t.Label(), store.Name())
	return nil
}

func (a *app) recoverFlags() string {
	if a.mac != "" {
		return "--mac " + a.mac
	}
	return "--keychain"
}

func (a *app) afterSuccessNotes(label string, cr *creds.Credentials, store pwStore) {
	if cr.Source == "env" {
		a.warnf("YLCTL_PASSWORD still holds the OLD password: update or unset it before the next command.")
	}
	if _, isKC := store.(*keychainStore); !isKC {
		o := creds.Options{Host: label, Getenv: a.env.Getenv, Runner: a.env.Runner}
		if _, ok := creds.Get(a.ctx, o, "admin"); ok {
			a.warnf("the keychain entry admin@%s now holds the OLD password: run 'ylctl auth save %s' to update it.", label, label)
		}
	}
}

// newPassword produces and checks the new password.
func (a *app) newPassword(f pwFlags, old, user string) (string, error) {
	if f.generate {
		pw, err := creds.GeneratePassword(f.length)
		if err != nil {
			return "", err
		}
		if err := creds.ValidateGenerated(pw, old, user); err != nil {
			return "", err
		}
		return pw, nil
	}
	p1, err := a.env.ReadPassword("New password: ")
	if err != nil {
		return "", err
	}
	if err := creds.ValidateNewPassword(p1, old, user); err != nil {
		return "", usageErr("%v", err)
	}
	p2, err := a.env.ReadPassword("Repeat the new password: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", usageErr("the two entries differ: nothing was changed")
	}
	return p1, nil
}

// loginWith logs in on a brand new client and session.
func (a *app) loginWith(host, user, pw string) error {
	c, err := a.newClient(host)
	if err != nil {
		return err
	}
	return c.Login(a.ctx, user, pw)
}

// dropPending removes the pending record after the phone was NOT changed.
func (a *app) dropPending(store pwStore, id string) {
	if !store.Persistent() {
		return
	}
	if err := store.Abort(a.ctx, id); err != nil {
		a.warnf("could not drop the pending record in %s (%v). It is harmless: the current password there is still the old one, and the pending one expires in an hour.", store.Name(), err)
	}
}

// stateAfterFailedVerify says exactly where things stand. Nothing is rolled back.
func (a *app) stateAfterFailedVerify(host, label string, store pwStore, outcome yealink.PasswordOutcome, verr error) error {
	w := a.errw()
	fmt.Fprintf(w, "\nCould NOT verify the new password on %s (%v).\n", label, verr)
	fmt.Fprintln(w, "Where things stand:")
	switch outcome {
	case yealink.PasswordChanged:
		fmt.Fprintln(w, "  - the phone said it changed the password, but a fresh login with the new one did not work")
	default:
		fmt.Fprintln(w, "  - the phone did not give a clear answer, and neither the old nor the new password could be confirmed")
	}
	if store.Persistent() {
		fmt.Fprintf(w, "  - %s still holds the OLD password as current and the NEW one as pending. Nothing was rolled back.\n", store.Name())
	} else {
		fmt.Fprintln(w, "  - the new password is the one you typed; the old one is the one you used to log in")
	}
	fmt.Fprintln(w, "What to do:")
	if store.Persistent() {
		fmt.Fprintf(w, "  1. wait a minute (the phone may still be applying it), then run:  ylctl password recover %s %s\n", host, a.recoverFlags())
		fmt.Fprintln(w, "     It tries the pending password, then the old one, and commits or drops the pending one accordingly.")
		fmt.Fprintf(w, "  2. if neither works, the phone may be locked after failed logins: wait, then retry. The pending value stays in %s for recovery.\n", store.Name())
	} else {
		fmt.Fprintln(w, "  1. wait a minute, then try logging in with the new password, and if that fails with the old one")
	}
	fmt.Fprintln(w, "  3. last resort: factory reset from the phone's keypad.")
	return &exitErr{ExitPartial, errors.New("the phone's password state could not be verified")}
}

func (a *app) passwordRecover(host string, f pwFlags) error {
	if a.insecure || a.trustNew {
		return usageErr("--insecure and --trust-new are refused here")
	}
	t, err := a.requirePinned(host)
	if err != nil {
		return err
	}
	if a.mac == "" && !f.keychain {
		return usageErr("say where the pending password is: --mac <MAC> (server vault) or --keychain")
	}
	w := a.errw()
	store, err := a.pwStoreFor(t.Label(), f, "admin", false, "")
	if err != nil {
		return err
	}
	pend, err := store.Pending(a.ctx)
	if err != nil {
		return fmt.Errorf("could not read the pending password from %s: %w", store.Name(), err)
	}
	if pend == nil {
		fmt.Fprintf(w, "Nothing is pending in %s for this phone.\n", store.Name())
		return &exitErr{ExitNoChange, errors.New("nothing to recover")}
	}
	// the current value
	var cur *creds.Credentials
	if a.mac != "" {
		cur, err = a.vaultCreds(a.mac)
	} else {
		cur, err = creds.Resolve(a.ctx, creds.Options{Host: t.Label(), User: "admin", Getenv: a.env.Getenv, Runner: a.env.Runner, Prompt: a.env.ReadPassword})
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "trying the pending password on the phone (attempt 1 of at most 2) ...")
	perr := a.loginWith(host, "admin", pend.Password)
	switch {
	case perr == nil:
		fmt.Fprintln(w, "the phone accepts the pending password: committing ...")
		var last error
		for i := 0; i < 3; i++ {
			if last = store.Commit(a.ctx, pend.ID, pend.Password); last == nil {
				break
			}
			time.Sleep(pwRetryDelay)
		}
		if last != nil {
			return &exitErr{ExitPartial, fmt.Errorf("the phone has the pending password but %s could not commit it: %w", store.Name(), last)}
		}
		fmt.Fprintf(a.out(), "recovered: %s now holds the password the phone has\n", store.Name())
		return nil
	case !errors.Is(perr, yealink.ErrAuthFailed):
		return fmt.Errorf("could not reach the phone to decide (%w). Nothing was changed; try again", perr)
	}
	fmt.Fprintln(w, "the phone refuses the pending password; trying the current one (attempt 2 of 2) ...")
	if cerr := a.loginWith(host, "admin", cur.Password); cerr == nil {
		if err := store.Abort(a.ctx, pend.ID); err != nil {
			return fmt.Errorf("the phone still has the old password, but the pending record could not be dropped: %w", err)
		}
		fmt.Fprintln(a.out(), "the phone still has its old password: the pending change was dropped. Nothing is out of step.")
		return nil
	}
	fmt.Fprintf(w, "Neither the pending nor the current password works on %s.\n", t.Label())
	fmt.Fprintf(w, "Both are still kept in %s; nothing was changed. If the phone locked itself after failed logins, wait and run this again. Last resort: factory reset from the keypad.\n", store.Name())
	return &exitErr{ExitAuth, errors.New("could not log in with either password")}
}
