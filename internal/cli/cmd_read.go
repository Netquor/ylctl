package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the version", Args: cobra.NoArgs,
		RunE: run(func(*cobra.Command, []string) error {
			if a.jsonOut {
				return a.printJSON(map[string]string{"version": Version, "commit": Commit, "date": Date})
			}
			fmt.Fprintf(a.out(), "ylctl %s (commit %s, built %s)\n", Version, Commit, Date)
			fmt.Fprintln(a.out(), a.colorOut("2", credit))
			return nil
		}),
	}
}

func (a *app) infoCmd() *cobra.Command {
	return &cobra.Command{
		Use: "info <host>", Short: "Model, firmware, hardware, MAC, IP and uptime (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			st, err := c.Status(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(st.Info)
			}
			i := st.Info
			w := a.table()
			fmt.Fprintf(w, "Model\t%s\nFirmware\t%s\nHardware\t%s\nMAC\t%s\nIP\t%s\nUptime\t%s\n", i.Model, i.Firmware, i.Hardware, i.MAC, i.IP, i.UptimeText)
			return w.Flush()
		}),
	}
}

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status <host>", Short: "Account registration state and network (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			st, err := c.Status(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(st)
			}
			n := st.Network
			w := a.table()
			fmt.Fprintf(w, "Network\t%s, %s/%s, gateway %s, DNS %s\n", n.WANType, n.IP, n.Mask, n.Gateway, joinNonEmpty(", ", n.DNS1, n.DNS2))
			fmt.Fprintf(w, "VLAN\t%s\nLink\t%s\nUptime\t%s\n\n", n.VLANID, n.LinkStatus, st.Info.UptimeText)
			fmt.Fprintln(w, "ACCOUNT\tREGISTRATION\tCODE")
			for _, ac := range st.Accounts {
				label := ac.Label
				if label == "" {
					label = "-"
				}
				fmt.Fprintf(w, "%d  %s\t%s\t%s\n", ac.Index, label, ac.State.Name, a.colorOut(stateColor(ac.State.Code), strconv.Itoa(ac.State.Code)))
			}
			return w.Flush()
		}),
	}
}

func joinNonEmpty(sep string, s ...string) string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return strings.Join(out, sep)
}

type fieldOut struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (a *app) autopCmd() *cobra.Command {
	autop := &cobra.Command{Use: "autop", Short: "Auto Provision settings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	autop.AddCommand(&cobra.Command{
		Use: "show <host>", Short: "Show the Auto Provision settings, secrets masked (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			ap, err := c.Autop(a.ctx)
			if err != nil {
				return err
			}
			var rows []fieldOut
			for _, f := range ap.Fields {
				rows = append(rows, fieldOut{f.Name, yealink.Display(f.Name, f.Value, a.reveal)})
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"fields": rows})
			}
			w := a.table()
			fmt.Fprintln(w, "FIELD\tVALUE")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\n", strings.TrimPrefix(r.Name, "AutoProvision"), r.Value)
			}
			return w.Flush()
		}),
	})
	autop.AddCommand(a.autopSetCmd())
	return autop
}

func (a *app) accountCmd() *cobra.Command {
	account := &cobra.Command{Use: "account", Short: "SIP account settings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	var n int
	show := &cobra.Command{
		Use: "show <host>", Short: "Show the Register settings of an account, password masked (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			if n < 1 || n > 16 {
				return usageErr("--account must be between 1 and 16")
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			ac, err := c.Account(a.ctx, n)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(ac)
			}
			w := a.table()
			en := "disabled"
			if ac.Enabled {
				en = "enabled"
			}
			fmt.Fprintf(w, "Account\t%d (%s)\nLabel\t%s\nDisplay name\t%s\nRegister name\t%s\nUser name\t%s\nPassword\t%s\n", ac.Number, en, ac.Label, ac.DisplayName, ac.RegisterName, ac.UserName, ac.Password)
			for i, s := range ac.Servers {
				if s.Host == "" {
					continue
				}
				fmt.Fprintf(w, "SIP server %d\t%s:%s %s\n", i+1, s.Host, s.Port, s.Transport)
			}
			ob := "off"
			if ac.Outbound.Enabled {
				ob = "on"
			}
			fmt.Fprintf(w, "Outbound proxy\t%s %s:%s\n", ob, ac.Outbound.Host, ac.Outbound.Port)
			return w.Flush()
		}),
	}
	show.Flags().IntVar(&n, "account", 1, "account number (1-16)")
	account.AddCommand(show)
	return account
}

// stateColor: green when registered, dim when disabled, yellow while working, red otherwise.
func stateColor(code int) string {
	switch code {
	case 2:
		return "1;32"
	case 0:
		return "2"
	case 1:
		return "33"
	}
	return "31"
}
