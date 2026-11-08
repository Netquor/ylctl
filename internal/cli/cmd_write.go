package cli

import (
	"errors"
	"fmt"
	"github.com/Netquor/ylctl/internal/pbx"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) provisionNowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "provision-now <host>", Short: "Trigger 'Auto Provision Now' on the phone", Args: hostArg,
		Long: "Makes the phone fetch its provisioning files from its configured server right away.\nThe phone applies what the server sends, which can change its configuration.",
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.ProvisionNow(a.ctx); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"host": args[0], "provision_now": "ok"})
			}
			fmt.Fprintln(a.out(), "provisioning requested: the phone is fetching its configuration now")
			return nil
		}),
	}
}

func (a *app) rebootCmd() *cobra.Command {
	var yes, force bool
	cmd := &cobra.Command{
		Use: "reboot <host>", Short: "Restart the phone", Args: hostArg,
		Long: "Restarts the phone from its web interface (the same as Settings > Upgrade > Reboot).\nIt refuses while the phone is on a call (--force overrides) and asks first (--yes skips the question).\nThe phone is back in about a minute; 'ylctl status <host>' shows when it has registered again.",
		RunE: run(func(_ *cobra.Command, args []string) error {
			if !yes {
				if !a.confirm("Reboot " + args[0] + "? ") {
					return fmt.Errorf("not rebooted (pass --yes to skip this question)")
				}
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.Reboot(a.ctx, force); err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"host": args[0], "reboot": "requested"})
			}
			fmt.Fprintln(a.out(), "reboot requested: the phone restarts now and is back in about a minute")
			return nil
		}),
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	cmd.Flags().BoolVar(&force, "force", false, "reboot even if a call is in progress")
	return cmd
}

// change is one field edit.
type change struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func (a *app) show(f, v string) string {
	if v == "" {
		return "(empty)"
	}
	return yealink.Display(f, v, a.reveal)
}

func (a *app) printPlan(host string, changes []change, dry bool) {
	title := "changes"
	if dry {
		title = "dry run, would change"
	}
	fmt.Fprintf(a.errw(), "%s on %s:\n", title, host)
	for _, ch := range changes {
		if ch.Before == ch.After {
			fmt.Fprintf(a.errw(), "  %-32s %s (unchanged, rewritten because of --force)\n", ch.Field, a.show(ch.Field, ch.After))
			continue
		}
		fmt.Fprintf(a.errw(), "  %-32s %s -> %s\n", ch.Field, a.show(ch.Field, ch.Before), a.show(ch.Field, ch.After))
	}
}

func validURL(raw string) error {
	if len(raw) > 511 {
		return errors.New("the URL is longer than 511 characters, the phone's limit")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "tftp" && u.Scheme != "ftp") {
		return errors.New("--url must look like https://host/path/")
	}
	if strings.ContainsAny(raw, " \t\r\n&") {
		return errors.New("--url contains characters the phone form cannot carry (space or &)")
	}
	return nil
}

func (a *app) adoptCmd() *cobra.Command {
	var u string
	var fromServer bool
	var disableDHCP, disablePNP, dry, force bool
	cmd := &cobra.Command{
		Use: "adopt <host>", Short: "Point the phone at a provisioning server and fetch now (changes settings)", Args: hostArg,
		Long: "Sets the Auto Provision server URL, optionally switches off DHCP option and PnP provisioning,\nthen triggers 'Auto Provision Now'. Shows a before/after diff. Refuses when nothing would\nchange unless --force. SIP accounts, passwords and transport are never touched.",
		RunE: run(func(_ *cobra.Command, args []string) error {
			if fromServer && u != "" {
				return usageErr("use either --url or --from-server, not both")
			}
			if u == "" && !fromServer {
				return usageErr("adopt needs --url, or --from-server to ask your NQ Phone server for the phone's own URL")
			}
			if u != "" {
				if err := validURL(u); err != nil {
					return usageErr("%v", err)
				}
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if fromServer {
				if u, err = a.urlFromServer(c, dry); err != nil {
					return err
				}
			}
			ap, err := c.Autop(a.ctx)
			if err != nil {
				return err
			}
			want := [][2]string{{yealink.FieldServerURL, u}}
			if disableDHCP {
				want = append(want, [2]string{yealink.FieldEnableDHCP, "0"})
			}
			if disablePNP {
				want = append(want, [2]string{yealink.FieldEnablePNP, "0"})
			}
			return a.apply(c, args[0], ap, want, dry, force, true)
		}),
	}
	cmd.Flags().StringVar(&u, "url", "", "provisioning server URL (contains a token; shown truncated unless --reveal)")
	cmd.Flags().BoolVar(&fromServer, "from-server", false, "ask the linked server for this phone's own URL (the phone must be claimed there); the URL is never shown")
	cmd.Flags().BoolVar(&disableDHCP, "disable-dhcp", false, "also switch off provisioning via DHCP option")
	cmd.Flags().BoolVar(&disablePNP, "disable-pnp", false, "also switch off PnP provisioning")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "show what would change and send nothing")
	cmd.Flags().BoolVar(&force, "force", false, "write even when the values are already set")
	return cmd
}

// apply plans, shows, writes, verifies and optionally provisions.
func (a *app) apply(c *yealink.Client, host string, ap *yealink.Autop, want [][2]string, dry, force, provision bool) error {
	var changes []change
	set := map[string]string{}
	for _, w := range want {
		cur, ok := ap.Get(w[0])
		if !ok {
			return fmt.Errorf("this phone's page has no field %s", w[0])
		}
		if cur != w[1] {
			changes = append(changes, change{w[0], cur, w[1]})
			set[w[0]] = w[1]
		} else if force {
			set[w[0]] = w[1]
		}
	}
	if len(changes) == 0 && !force {
		if a.jsonOut {
			_ = a.printJSON(map[string]any{"host": host, "changed": false, "changes": []change{}})
		}
		return &exitErr{ExitNoChange, errors.New("nothing to change: the phone already has these values (use --force to write anyway)")}
	}
	if len(changes) == 0 {
		for _, w := range want {
			changes = append(changes, change{w[0], w[1], w[1]})
		}
	}
	a.printPlan(host, changes, dry)
	if dry {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(a.errw(), "dry run: would POST q=write with fields %s and the CSRF token", strings.Join(names, ", "))
		if provision {
			fmt.Fprint(a.errw(), ", then POST q=autopnow")
		}
		fmt.Fprintln(a.errw(), ". Nothing was sent.")
		if a.jsonOut {
			return a.printJSON(map[string]any{"host": host, "dry_run": true, "changes": a.maskChanges(changes)})
		}
		return nil
	}
	if _, err := c.WriteAutop(a.ctx, set); err != nil {
		return err
	}
	res := map[string]any{"host": host, "dry_run": false, "changes": a.maskChanges(changes), "written": true}
	var provErr error
	if provision {
		provErr = c.ProvisionNow(a.ctx)
		res["provision_now"] = provErr == nil
	}
	if a.jsonOut {
		if err := a.printJSON(res); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(a.out(), "settings written and verified")
		if provision && provErr == nil {
			fmt.Fprintln(a.out(), "provisioning requested: the phone is fetching its configuration now")
		}
	}
	if provErr != nil {
		return &exitErr{ExitPartial, fmt.Errorf("settings were written, but triggering provisioning failed: %w", provErr)}
	}
	return nil
}

func (a *app) maskChanges(in []change) []change {
	out := make([]change, len(in))
	for i, ch := range in {
		out[i] = change{ch.Field, yealink.Display(ch.Field, ch.Before, a.reveal), yealink.Display(ch.Field, ch.After, a.reveal)}
	}
	return out
}

// autop set
func (a *app) autopSetCmd() *cobra.Command {
	var dry, force bool
	cmd := &cobra.Command{
		Use: "set <host> Field=value...", Short: "Change Auto Provision fields (non-secret, e.g. RepeatMinutes=60)",
		Long: "Field names may be given with or without the AutoProvision prefix. Secret fields (password, AES keys)\nare refused. Shows a before/after diff; use --dry-run first.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return usageErr("autop set needs <host> and at least one Field=value")
			}
			return nil
		},
		RunE: run(func(cmd *cobra.Command, args []string) error {
			var want [][2]string
			for _, kv := range args[1:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || k == "" {
					return usageErr("%q is not Field=value", kv)
				}
				if !strings.HasPrefix(k, "AutoProvision") {
					k = "AutoProvision" + k
				}
				if yealink.IsSecretName(k) {
					return usageErr("refusing to set secret field %s", k)
				}
				want = append(want, [2]string{k, v})
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			ap, err := c.Autop(a.ctx)
			if err != nil {
				return err
			}
			return a.apply(c, args[0], ap, want, dry, force, false)
		}),
	}
	cmd.Flags().BoolVar(&dry, "dry-run", false, "show what would change and send nothing")
	cmd.Flags().BoolVar(&force, "force", false, "write even when the values are already set")
	return cmd
}

func (a *app) authCmd() *cobra.Command {
	auth := &cobra.Command{Use: "auth", Short: "Store or forget a phone password in the OS keychain", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	opts := func(host string) creds.Options {
		return creds.Options{Host: host, Getenv: a.env.Getenv, Runner: a.env.Runner}
	}
	auth.AddCommand(&cobra.Command{
		Use: "save <host>", Short: "Prompt for the password and store it in the keychain (explicit opt-in)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			t, err := yealink.ParseTarget(args[0])
			if err != nil {
				return usageErr("%v", err)
			}
			if a.env.ReadPassword == nil {
				return usageErr("auth save needs a terminal to ask for the password")
			}
			user := a.user
			if user == "" {
				user = "admin"
			}
			pw, err := a.env.ReadPassword(fmt.Sprintf("Password for %s@%s: ", user, t.Label()))
			if err != nil {
				return err
			}
			if pw == "" {
				return usageErr("empty password")
			}
			if err := creds.Save(a.ctx, opts(t.Label()), user, pw); err != nil {
				return err
			}
			fmt.Fprintf(a.errw(), "stored in the keychain as %s@%s\n", user, t.Label())
			return nil
		}),
	}, &cobra.Command{
		Use: "forget <host>", Short: "Remove a stored password from the keychain", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			t, err := yealink.ParseTarget(args[0])
			if err != nil {
				return usageErr("%v", err)
			}
			user := a.user
			if user == "" {
				user = "admin"
			}
			return creds.Forget(a.ctx, opts(t.Label()), user)
		}),
	})
	return auth
}

// urlFromServer asks the linked server for the phone's own provisioning URL. The phone must be claimed
// on the server. A real run issues a NEW URL (the old one stops working); a dry run asks nothing.
func (a *app) urlFromServer(c *yealink.Client, dry bool) (string, error) {
	pb, link, err := a.pbxClient()
	if err != nil {
		return "", err
	}
	st, err := c.Status(a.ctx)
	if err != nil {
		return "", err
	}
	mac := st.Info.MAC
	if mac == "" {
		return "", errors.New("could not read the phone's MAC address")
	}
	dev, err := pb.DeviceByMAC(a.ctx, mac)
	if err != nil {
		return "", fmt.Errorf("could not ask the server about this phone: %w", err)
	}
	switch {
	case dev == nil:
		return "", fmt.Errorf("%s does not know %s yet: claim it first (web UI Provisioning, or 'ylctl recon' to enrol it)", link.Server, mac)
	case dev.Status != "claimed":
		return "", fmt.Errorf("%s is %s on the server: claim it first (give it an extension in the web UI) and run this again", mac, dev.Status)
	}
	if dry {
		return strings.TrimRight(link.Server, "/") + "/webhooks/provision/<new token>/", nil
	}
	issued, err := pb.IssueDeviceURL(a.ctx, dev.ID)
	if err != nil {
		var ae *pbx.APIError
		if errors.As(err, &ae) && ae.Status == 403 {
			return "", errors.New("the server refused: this link may not change phones (a read-only link cannot); link again without read-only")
		}
		return "", fmt.Errorf("could not issue the phone's URL: %w", err)
	}
	if issued.ProvisionURL == "" {
		return "", errors.New("the server did not return a provisioning URL")
	}
	return issued.ProvisionURL, nil
}
