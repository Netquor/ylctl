package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/discover"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) discoverCmd() *cobra.Command {
	var yes, force, allowPublic bool
	var workers, rate int
	var portsArg string
	cmd := &cobra.Command{
		Use: "discover [cidr]", Short: "Find Yealink phones by probing a network (never logs in)",
		Long: "Probes every address of the range on TCP 443, then 80, and fetches the public login form to\nrecognise a Yealink phone (model and firmware are visible there). No password is ever sent.\nWithout an argument the subnet of your local interface is used. Only private ranges are\nallowed unless --allow-public; ranges larger than /22 need --force. You are asked to confirm\nunless --yes is given.",
		Args: cobra.MaximumNArgs(1),
		RunE: run(func(_ *cobra.Command, args []string) error {
			var prefixes []netip.Prefix
			if len(args) == 1 {
				p, err := discover.ParseRange(args[0], allowPublic, force)
				if err != nil {
					return usageErr("%v", err)
				}
				prefixes = append(prefixes, p)
			} else {
				subs, err := a.localSubnets()
				if err != nil || len(subs) == 0 {
					return usageErr("could not find a local private subnet; give a CIDR such as 192.168.1.0/24")
				}
				for _, s := range subs {
					p, err := discover.ParseRange(s, allowPublic, force)
					if err != nil {
						return usageErr("%v", err)
					}
					prefixes = append(prefixes, p)
				}
			}
			ports, err := parsePorts(portsArg)
			if err != nil {
				return usageErr("%v", err)
			}
			var addrs []netip.Addr
			var names []string
			for _, p := range prefixes {
				addrs = append(addrs, discover.Addresses(p)...)
				names = append(names, p.String())
			}
			if !yes {
				if !a.env.StdinIsTTY {
					return usageErr("discover sends probes to %d addresses; run it on a terminal to confirm, or pass --yes", len(addrs))
				}
				if !a.confirm(fmt.Sprintf("Probe %d addresses in %s on TCP ports %s? Only a GET of the login page is sent, no login.", len(addrs), strings.Join(names, ", "), portsArg)) {
					return &exitErr{ExitError, errors.New("not confirmed, nothing was sent")}
				}
			}
			fmt.Fprintf(a.errw(), "scanning %d addresses in %s (%d workers, %d probes/s)...\n", len(addrs), strings.Join(names, ", "), workers, rate)
			res, err := discover.Scan(a.ctx, addrs, discover.Config{Ports: ports, Workers: workers, Rate: rate, Timeout: minDur(a.timeout, 3*time.Second)})
			if err != nil {
				return err
			}
			if a.jsonOut {
				if res == nil {
					res = []yealink.ProbeResult{}
				}
				return a.printJSON(map[string]any{"ranges": names, "probed": len(addrs), "phones": res})
			}
			if len(res) == 0 {
				fmt.Fprintln(a.out(), "no Yealink phones found")
				return nil
			}
			w := a.table()
			fmt.Fprintln(w, "ADDRESS\tMODEL\tFIRMWARE\tPORT\tCERT SHA-256")
			for _, r := range res {
				fp := r.CertSHA256
				if len(fp) > 16 {
					fp = fp[:16] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d/%s\t%s\n", r.IP, r.Model, r.Firmware, r.Port, r.Scheme, fp)
			}
			return w.Flush()
		}),
	}
	f := cmd.Flags()
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	f.BoolVar(&force, "force", false, "allow ranges larger than /22")
	f.BoolVar(&allowPublic, "allow-public", false, "allow non-private ranges (only scan networks you are allowed to scan)")
	f.IntVar(&workers, "workers", 32, "parallel probes")
	f.IntVar(&rate, "rate", 100, "maximum probes per second")
	f.StringVar(&portsArg, "ports", "443,80", "TCP ports to try, in order")
	return cmd
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func (a *app) localSubnets() ([]string, error) {
	if a.env.Subnets != nil {
		return a.env.Subnets()
	}
	ps, err := discover.LocalSubnets()
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out, err
}
