package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/pbx"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) configDir() (string, error) { return yealink.ConfigDir(a.env.Getenv) }

// pbxCreds are the keychain options for the linked server's token.
func (a *app) pbxCreds(server string) creds.Options {
	host := strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://")
	return creds.Options{Host: "pbx:" + host, Getenv: a.env.Getenv, Runner: a.env.Runner}
}

// pbxClient builds a client for the linked server. The token comes from
// $YLCTL_PBX_TOKEN (for scripts) or the OS keychain.
func (a *app) pbxClient() (*pbx.Client, pbx.Link, error) {
	dir, err := a.configDir()
	if err != nil {
		return nil, pbx.Link{}, err
	}
	l, err := pbx.LoadLink(dir)
	if err != nil {
		return nil, pbx.Link{}, err
	}
	if l.Expired(time.Now()) {
		return nil, l, fmt.Errorf("the link to %s expired on %s: run 'ylctl login %s' again", l.Server, l.ExpiresAt, l.Server)
	}
	tok := a.env.Getenv("YLCTL_PBX_TOKEN")
	if tok == "" {
		var ok bool
		if tok, ok = creds.Get(a.ctx, a.pbxCreds(l.Server), "token"); !ok {
			return nil, l, errors.New("the link's token is not in the keychain: run 'ylctl login' again, or set YLCTL_PBX_TOKEN")
		}
	}
	return pbx.New(l.Server, tok), l, nil
}

func (a *app) loginCmd() *cobra.Command {
	var name string
	var allowHTTP bool
	cmd := &cobra.Command{
		Use:   "login <server>",
		Short: "Link this computer to your NQ Phone server (approve it in the browser)",
		Long: "Prints a short code and a web address. Open it signed in as an owner or admin, check that the tool\n" +
			"name and address are yours, choose how long to trust this computer, and approve. The server then hands\n" +
			"this tool its own key, once. It is kept in the OS keychain, and you can pause or revoke it from the\n" +
			"server's 'Linked CLIs' page at any time. With a link, '--mac' fetches a phone's admin password from\n" +
			"the server's vault instead of asking you for it.",
		Args: cobra.ExactArgs(1),
		RunE: run(func(_ *cobra.Command, args []string) error {
			server, err := pbx.NormalizeServer(args[0], allowHTTP)
			if err != nil {
				return usageErr("%v", err)
			}
			dir, err := a.configDir()
			if err != nil {
				return err
			}
			c := pbx.New(server, "")
			host, _ := os.Hostname()
			if name == "" {
				name = "ylctl"
			}
			p, err := c.StartPairing(a.ctx, name, host)
			if err != nil {
				return fmt.Errorf("could not reach %s: %w", server, err)
			}
			w := a.errw()
			fmt.Fprintf(w, "\nLink this computer to %s\n\n", a.color("1;36", server))
			fmt.Fprintf(w, "  1. Open   %s\n", a.color("4;36", p.VerificationURI))
			fmt.Fprintf(w, "  2. Check the code is   %s\n", a.color("1;35", p.UserCode))
			fmt.Fprintf(w, "  3. Choose how long to trust this computer, then approve.\n\n")
			fmt.Fprintf(w, "%s (expires in %d minutes, Ctrl-C to cancel)\n", a.color("2", "Waiting for approval"), p.ExpiresIn/60)
			r, err := c.WaitForApproval(a.ctx, p, nil)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return errors.New("cancelled; nothing was linked")
				}
				return err
			}
			switch r.Status {
			case "approved":
			case "denied":
				return errors.New("the request was refused")
			default:
				return errors.New("the code expired before it was approved; run 'ylctl login' again")
			}
			if err := creds.Save(a.ctx, a.pbxCreds(server), "token", r.Token); err != nil {
				return fmt.Errorf("linked, but the token could not be saved to the keychain (%v): set YLCTL_PBX_TOKEN yourself, or run login on a machine with a keychain", err)
			}
			if err := pbx.SaveLink(dir, pbx.Link{Server: server, KeyName: r.Name, LinkedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: r.ExpiresAt}); err != nil {
				return err
			}
			until := "no expiry"
			if r.ExpiresAt != "" {
				until = r.ExpiresAt
			}
			fmt.Fprintf(a.out(), "%s as %s, trusted until %s\n", a.colorOut("1;32", "Linked"), r.Name, until)
			return nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "name shown on the approval page (default ylctl)")
	cmd.Flags().BoolVar(&allowHTTP, "allow-http", false, "allow plain http on a trusted lab network")
	return cmd
}

func (a *app) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "logout", Short: "Forget the link on this computer", Args: cobra.NoArgs,
		Long: "Removes the saved link and token from this computer. It does not revoke the key on the server:\nuse the server's 'Linked CLIs' page for that.",
		RunE: run(func(*cobra.Command, []string) error {
			dir, err := a.configDir()
			if err != nil {
				return err
			}
			l, lerr := pbx.LoadLink(dir)
			if lerr == nil {
				if err := creds.Forget(a.ctx, a.pbxCreds(l.Server), "token"); err != nil && !errors.Is(err, creds.ErrNoKeychain) {
					a.warnf("could not remove the token from the keychain: %v", err)
				}
			}
			if err := pbx.ForgetLink(dir); err != nil {
				return err
			}
			fmt.Fprintln(a.out(), "Forgot the link on this computer.")
			if lerr == nil {
				fmt.Fprintf(a.out(), "%s\n", a.colorOut("2", "To cut its access completely, revoke "+l.KeyName+" on the server's Linked CLIs page."))
			}
			return nil
		}),
	}
}

func (a *app) whoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use: "whoami", Short: "Show the server this computer is linked to and test the link", Args: cobra.NoArgs,
		RunE: run(func(*cobra.Command, []string) error {
			c, l, err := a.pbxClient()
			if err != nil {
				return err
			}
			st, serr := c.VaultStatus(a.ctx)
			if a.jsonOut {
				return a.printJSON(map[string]any{"server": l.Server, "key": l.KeyName, "linked_at": l.LinkedAt, "expires_at": l.ExpiresAt, "reachable": serr == nil, "vault": st})
			}
			w := a.table()
			fmt.Fprintf(w, "Server\t%s\nKey\t%s\nLinked\t%s\nTrusted until\t%s\n", l.Server, l.KeyName, l.LinkedAt, orDash(l.ExpiresAt, "no expiry"))
			switch {
			case serr == nil:
				vault := "no key configured on the server"
				if ok, _ := st["key_configured"].(bool); ok {
					vault = "ready"
				}
				fmt.Fprintf(w, "Link\t%s\nVault\t%s\n", a.colorOut("1;32", "working"), vault)
			default:
				fmt.Fprintf(w, "Link\t%s\n", a.colorOut("1;31", "not working: "+serr.Error()))
			}
			return w.Flush()
		}),
	}
}

func orDash(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// vaultCreds fetches the web admin login for the phone with this MAC from the linked server.
func (a *app) vaultCreds(mac string) (*creds.Credentials, error) {
	c, l, err := a.pbxClient()
	if err != nil {
		return nil, err
	}
	reason := "ylctl " + subcommandName(os.Args[1:])
	s, err := c.PhoneAdmin(a.ctx, mac, reason)
	if err != nil {
		var ae *pbx.APIError
		if errors.As(err, &ae) {
			switch ae.Status {
			case 404:
				return nil, fmt.Errorf("%s has no stored admin password for that phone (set or generate one on the server first)", l.Server)
			case 401:
				return nil, fmt.Errorf("%s no longer accepts this link (paused, expired or revoked): run 'ylctl login' again", l.Server)
			case 403:
				return nil, fmt.Errorf("%s refused: this link may not read secrets (a read-only link cannot)", l.Server)
			case 503:
				return nil, fmt.Errorf("%s has no vault key configured yet", l.Server)
			}
		}
		return nil, err
	}
	user := s.Username
	if user == "" {
		user = "admin"
	}
	return &creds.Credentials{User: user, Password: s.Secret, Source: "vault"}, nil
}

// subcommandName is the first word of the command line that is not a flag or a flag's value,
// for the vault's access log ("info", "capture follow"...).
func subcommandName(args []string) string {
	takesValue := map[string]bool{"--mac": true, "--user": true, "--timeout": true}
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case takesValue[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			words = append(words, a)
			if len(words) == 2 {
				return strings.Join(words, " ")
			}
		}
	}
	return strings.Join(words, " ")
}
