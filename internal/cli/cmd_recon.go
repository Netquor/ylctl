package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/discover"
	"github.com/Netquor/ylctl/internal/pbx"
	"github.com/Netquor/ylctl/internal/recon"
	"github.com/Netquor/ylctl/internal/yealink"
)

type reconOpts struct {
	super, yes, noPrompt, register, keepDHCP, force bool
	tftp, noTFTP, dhcpURL                           bool
	enrollURL                                       string
}

func (a *app) reconCmd() *cobra.Command {
	var o reconOpts
	cmd := &cobra.Command{
		Use:   "recon [subnet...]",
		Short: "Find the phones on your network, see which are registered, and bring them under management",
		Long: "Scans the subnets you confirm (the tool guesses yours), logs in to each phone it finds to read its\n" +
			"state, and sorts them: managed by your NQ Phone server, registered somewhere else, not registered, or\n" +
			"not reachable with any password it has. It then offers to bring the unmanaged ones in (A for all, or\n" +
			"space and the arrow keys to choose): each phone is pointed at your server's enrollment link and asked\n" +
			"to fetch its configuration, and you finish in the web UI (extensions, groups, policies, users).\n\n" +
			"A phone that answers but refuses every password gets a plan: a zero-touch attempt when your network\n" +
			"hands phones the enrollment URL or the PBX's TFTP server by DHCP, with a check-back in 10 minutes, then factory reset steps for its\n" +
			"vendor, and 'wait for me' so the tool keeps going with the other phones while you reset it.\n\n" +
			"Subnets: give them as arguments (192.168.0.0/24 10.1.0.0/24), or answer the prompt: Enter accepts the\n" +
			"guess, a full range replaces it, '/23' only changes the mask. --super scans very fast (more parallel\n" +
			"probes: use it on a network you own). Only a GET of each login page is sent while scanning.",
		RunE: run(func(_ *cobra.Command, args []string) error { return a.recon(args, o) }),
	}
	f := cmd.Flags()
	f.BoolVar(&o.super, "super", false, "scan and check phones with many parallel workers (fast; for networks you own)")
	f.BoolVar(&o.yes, "yes", false, "accept the guessed subnets and the default answers; do not ask")
	f.BoolVar(&o.noPrompt, "no-prompt", false, "only report; never ask or change anything (also the default off a terminal)")
	f.BoolVar(&o.register, "auto-register-discovered", false, "bring every unmanaged phone that accepts our login under management without asking which")
	f.BoolVar(&o.keepDHCP, "keep-dhcp-provisioning", false, "when registering, leave the phone's DHCP-option and PnP provisioning switches alone")
	f.BoolVar(&o.force, "force", false, "allow ranges larger than /22")
	f.BoolVar(&o.tftp, "tftp", false, "state that this network serves the PBX's TFTP server to phones (DHCP option 66); remembered")
	f.BoolVar(&o.noTFTP, "no-tftp", false, "state that this network does not serve TFTP to phones; remembered")
	f.BoolVar(&o.dhcpURL, "dhcp-url", false, "state that DHCP on this network hands phones the server's enrollment URL (option 66 = https://...); remembered")
	f.StringVar(&o.enrollURL, "enroll-url", "", "the server's enrollment link (default: $YLCTL_ENROLL_URL, the saved one, or make one)")
	return cmd
}

// line reads one line from stdin after printing a prompt on stderr.
func (a *app) askLine(prompt string) string {
	if a.rd == nil {
		a.rd = bufio.NewReader(a.env.Stdin)
	}
	fmt.Fprint(a.errw(), prompt)
	s, _ := a.rd.ReadString('\n')
	return strings.TrimSpace(s)
}

// yn asks a yes/no question; def is the answer for just pressing Enter.
func (a *app) yn(q string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	switch strings.ToLower(a.askLine(q + " " + hint + " ")) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

func (a *app) recon(args []string, o reconOpts) error {
	interactive := a.env.StdinIsTTY && !o.noPrompt
	if len(args) == 0 && !interactive && !o.yes {
		return usageErr("recon needs subnets (192.168.0.0/24) when it cannot ask you; or pass --yes to scan the guessed ones")
	}
	dir, err := a.configDir()
	if err != nil {
		return err
	}
	set := recon.Load(dir)
	switch {
	case o.dhcpURL:
		set.SetZeroTouch(recon.ZTDHCPURL)
	case o.tftp:
		set.SetZeroTouch(recon.ZTTFTP)
	case o.noTFTP:
		set.SetZeroTouch(recon.ZTNone)
	}

	// ---- 1. which subnets ----
	var guesses []netip.Prefix
	if subs, err := a.localSubnets(); err == nil {
		for _, s := range subs {
			if p, err := netip.ParsePrefix(s); err == nil {
				guesses = append(guesses, p)
			}
		}
	}
	if len(guesses) == 0 {
		for _, s := range set.Subnets {
			if p, err := netip.ParsePrefix(s); err == nil {
				guesses = append(guesses, p)
			}
		}
	}
	var prefixes []netip.Prefix
	if len(args) > 0 {
		prefixes, err = recon.ParseSubnets(guesses, strings.Join(args, " "))
		if err != nil {
			return usageErr("%v", err)
		}
	} else {
		prefixes = guesses
		if interactive && !o.yes {
			for {
				if len(prefixes) == 0 {
					prefixes = nil
				}
				q := "No subnet could be guessed. Type a range like 192.168.0.0/24: "
				if len(guesses) > 0 {
					q = fmt.Sprintf("Scan %s ?\n  Enter to continue, or type a full range (192.168.5.0/24), or just /CIDR (like /23) to correct the mask; several are fine: ", recon.Describe(guesses))
				}
				in := a.askLine(q)
				p, err := recon.ParseSubnets(guesses, in)
				if err != nil || len(p) == 0 {
					a.warnf("%v", err)
					continue
				}
				prefixes = p
				break
			}
		}
	}
	var addrs []netip.Addr
	for i, p := range prefixes {
		q, err := discover.ParseRange(p.String(), false, o.force)
		if err != nil {
			return usageErr("%v", err)
		}
		prefixes[i] = q
		addrs = append(addrs, discover.Addresses(q)...)
	}
	if len(addrs) == 0 {
		return usageErr("nothing to scan")
	}
	set.Subnets = nil
	for _, p := range prefixes {
		set.Subnets = append(set.Subnets, p.String())
	}
	_ = recon.Save(dir, set)

	// ---- 2. scan ----
	cfg := discover.Config{Ports: []int{443, 80}, Workers: 64, Rate: 500, Timeout: 3 * time.Second}
	assessWorkers := 8
	if o.super {
		cfg = discover.Config{Ports: []int{443, 80}, Workers: 512, Rate: 8000, Timeout: 2 * time.Second}
		assessWorkers = 64
	}
	fmt.Fprintf(a.errw(), "%s %d addresses in %s%s\n", a.color("1;36", "Scanning"), len(addrs), recon.Describe(prefixes), map[bool]string{true: a.color("1;35", "  (super)"), false: ""}[o.super])
	t0 := time.Now()
	// First pass: a SIP OPTIONS ping to UDP 5060. A phone answers in ~25 ms with its model and firmware,
	// no login, so a whole network is checked in about a second.
	rate := 2000
	if o.super {
		rate = 4000
	}
	if v, err := strconv.Atoi(a.env.Getenv("YLCTL_SIP_RATE")); err == nil && v > 0 { // tuning knob
		rate = v
	}
	hits, _ := discover.SIPSweep(a.ctx, addrs, 5060, 1800*time.Millisecond, rate)
	var yl []discover.SIPHit
	var other []string
	for _, h := range hits {
		if h.Model != "" {
			yl = append(yl, h)
		} else if h.UserAgent != "" {
			other = append(other, h.IP+" "+h.UserAgent)
		}
	}
	fmt.Fprintf(a.errw(), "%s %d Yealink phone(s) answered the SIP ping in %s\n", a.color("1;32", "Ping:"), len(yl), time.Since(t0).Round(100*time.Millisecond))
	if len(other) > 0 {
		sort.Strings(other)
		if len(other) > 5 {
			other = append(other[:5], fmt.Sprintf("... and %d more", len(other)-5))
		}
		fmt.Fprintf(a.errw(), "%s\n", a.color("2", "Also answered SIP, not Yealink (not handled yet): "+strings.Join(other, "; ")))
	}
	var found []yealink.ProbeResult
	if o.super {
		// only look at the web interface of phones that answered
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 32)
		for _, h := range yl {
			wg.Add(1)
			sem <- struct{}{}
			go func(h discover.SIPHit) {
				defer wg.Done()
				defer func() { <-sem }()
				r, _ := yealink.Probe(a.ctx, h.IP, cfg.Ports, cfg.Timeout)
				if r == nil {
					r = &yealink.ProbeResult{IP: h.IP, Port: 443, Scheme: "https", Model: h.Model, Firmware: h.Firmware}
				}
				mu.Lock()
				found = append(found, *r)
				mu.Unlock()
			}(h)
		}
		wg.Wait()
	} else {
		var err error
		found, err = discover.Scan(a.ctx, addrs, cfg)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		have := map[string]bool{}
		for _, f := range found {
			have[f.IP] = true
		}
		for _, h := range yl { // answered the ping but not the web probe: keep it, assess will say what is wrong
			if !have[h.IP] {
				found = append(found, yealink.ProbeResult{IP: h.IP, Port: 443, Scheme: "https", Model: h.Model, Firmware: h.Firmware})
			}
		}
	}
	// A fast sweep can miss a phone that is slow to answer. The ARP table lists every host that answered
	// the sweep at the network level: look again, patiently, at those that were not recognised.
	arp := map[string]string{}
	if a.env.Runner != nil {
		if out, err := a.env.Runner.Run(a.ctx, "", "arp", "-an"); err == nil {
			arp = recon.ParseARP(out)
		}
	}
	have := map[string]bool{}
	for _, f := range found {
		have[f.IP] = true
	}
	var again []netip.Addr
	for ip := range arp {
		ad, err := netip.ParseAddr(ip)
		if err != nil || have[ip] {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(ad) {
				again = append(again, ad)
				break
			}
		}
	}
	if len(again) > 0 && a.ctx.Err() == nil {
		more, _ := discover.Scan(a.ctx, again, discover.Config{Ports: []int{443, 80}, Workers: 16, Rate: 50, Timeout: 5 * time.Second})
		found = append(found, more...)
	}
	if o.super && len(found) < len(addrs) {
		fmt.Fprintln(a.errw(), a.color("2", "(--super trades completeness for speed: a slow phone on a routed subnet can be missed; run once without it to be sure)"))
	}
	fmt.Fprintf(a.errw(), "%s %d phone(s) in %s\n", a.color("1;32", "Found"), len(found), time.Since(t0).Round(100*time.Millisecond))
	if len(found) == 0 {
		fmt.Fprintln(a.errw(), "No Yealink phones answered. Check the subnet, that the phones are powered and on this network, or try --super for a faster, wider sweep.")
		return nil
	}

	// ---- 3. what we know ----
	var pb *pbx.Client
	var link pbx.Link
	if c, l, err := a.pbxClient(); err == nil {
		pb, link = c, l
	} else if !errors.Is(err, pbx.ErrNotLinked) {
		a.warnf("%v", err)
	}
	known := map[string]string{}
	if pb != nil {
		ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
		if ds, err := pb.Devices(ctx); err == nil {
			for _, d := range ds {
				known[recon.NormMAC(d.MAC)] = d.Status
			}
		} else {
			a.warnf("could not read the server's device list: %v", err)
		}
		cancel()
	} else {
		fmt.Fprintln(a.errw(), a.color("2", "Not linked to a server (ylctl login): phones can be listed, not registered by name."))
	}
	allowDefault := a.tryDefault
	trust := a.trustNew || o.yes
	if interactive && !o.yes {
		if !allowDefault {
			allowDefault = a.yn("Also try the factory login admin/admin once on phones that refuse the stored password?", false)
		}
		if !trust {
			trust = a.yn(fmt.Sprintf("Remember (pin) the certificates of the %d phone(s) found, so a later change is refused?", len(found)), true)
		}
	}

	// ---- 4. look at each phone ----
	fmt.Fprintf(a.errw(), "%s each phone (one login attempt per password, never repeated)\n", a.color("1;36", "Checking"))
	phones := a.assessAll(a.ctx, found, arp, pb, link, known, allowDefault, trust, assessWorkers)
	sort.Slice(phones, func(i, j int) bool { return ipLess(phones[i].IP, phones[j].IP) })
	a.printRecon(phones)
	if a.jsonOut {
		return a.printJSON(reconJSON(phones))
	}

	// ---- 5. bring unmanaged phones in ----
	var targets []*reconPhone
	for _, p := range phones {
		if p.client != nil && (p.State == stRegistered || p.State == stUnregistered) {
			targets = append(targets, p)
		}
	}
	registered := 0
	if len(targets) > 0 && (o.register || interactive) {
		chosen := targets
		if !o.register {
			items := make([]string, len(targets))
			for i, p := range targets {
				items[i] = fmt.Sprintf("%-15s %-8s %-18s %s", p.IP, p.Model, recon.Colon(p.MAC), a.stateText(p))
			}
			idx, ok := a.pick(fmt.Sprintf("Bring these %d phone(s) under management?", len(targets)), items)
			if !ok || len(idx) == 0 {
				fmt.Fprintln(a.errw(), "Nothing selected; leaving them as they are.")
				chosen = nil
			} else {
				chosen = nil
				for _, i := range idx {
					chosen = append(chosen, targets[i])
				}
			}
		}
		if len(chosen) > 0 {
			registered = a.reconBringIn(chosen, pb, link, &set, dir, o)
		}
	} else if len(targets) > 0 {
		fmt.Fprintf(a.errw(), "\n%d phone(s) are not under management. Run again on a terminal to choose, or pass --auto-register-discovered.\n", len(targets))
	}

	// ---- 6. phones we could not log in to ----
	var stuck []*reconPhone
	for _, p := range phones {
		if p.State == stNoAuth || p.State == stLocked {
			stuck = append(stuck, p)
		}
	}
	if len(stuck) > 0 {
		if interactive && !o.yes {
			a.reconStuck(stuck, pb, link, &set, dir, o, allowDefault, trust)
		} else {
			a.printStuckHints(stuck)
		}
	}

	// ---- 7. what next ----
	if pb != nil && (registered > 0) {
		fmt.Fprintf(a.errw(), "\n%s Finish in the web UI: %s/provisioning  (give each phone an extension, put it in groups and policies, link it to a person).\n", a.color("1;32", "Next:"), link.Server)
	}
	return nil
}

func ipLess(a, b string) bool {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x.Less(y)
}

func (a *app) stateText(p *reconPhone) string {
	switch p.State {
	case stManaged:
		return "managed"
	case stRegistered:
		if p.RegHere {
			return "registered to your PBX, not provisioned by it: " + strings.Join(p.Registered, ", ")
		}
		return "registered elsewhere: " + strings.Join(p.Registered, ", ")
	case stUnregistered:
		return "not registered"
	case stNoAuth:
		return "password not accepted"
	case stLocked:
		return "login locked"
	}
	return p.State
}

func (a *app) stateColor(p *reconPhone) string {
	switch p.State {
	case stManaged:
		return "1;32"
	case stRegistered:
		return "33"
	case stUnregistered:
		return "1;33"
	}
	return "1;31"
}

func (a *app) printRecon(phones []*reconPhone) {
	counts := map[string]int{}
	w := a.table()
	fmt.Fprintln(w, "\nADDRESS\tMAC\tMODEL\tSERVER\tSTATE")
	for _, p := range phones {
		counts[p.State]++
		mac := "-"
		if p.MAC != "" {
			mac = recon.Colon(p.MAC)
		}
		srv := p.Known
		if srv == "" {
			srv = "-"
		} else {
			srv = "known: " + srv
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.IP, mac, p.label(), srv, a.colorOut(a.stateColor(p), a.stateText(p)))
	}
	_ = w.Flush()
	fmt.Fprintf(a.out(), "\n%d phone(s): %d managed, %d registered but not managed, %d not registered, %d need a password or reset\n",
		len(phones), counts[stManaged], counts[stRegistered], counts[stUnregistered], counts[stNoAuth]+counts[stLocked]+counts[stError])
}

type reconJSONPhone struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac,omitempty"`
	Model      string   `json:"model"`
	Firmware   string   `json:"firmware"`
	State      string   `json:"state"`
	Detail     string   `json:"detail,omitempty"`
	Registered []string `json:"registered,omitempty"`
	Server     string   `json:"server_knows,omitempty"`
}

func reconJSON(phones []*reconPhone) []reconJSONPhone {
	out := make([]reconJSONPhone, len(phones))
	for i, p := range phones {
		out[i] = reconJSONPhone{p.IP, p.MAC, p.Model, p.Firmware, p.State, p.Detail, p.Registered, p.Known}
	}
	return out
}

func (a *app) printStuckHints(stuck []*reconPhone) {
	fmt.Fprintf(a.errw(), "\n%d phone(s) answer but could not be logged in to:\n", len(stuck))
	for _, p := range stuck {
		fmt.Fprintf(a.errw(), "  %s  %s  %s\n", p.IP, p.label(), p.Detail)
	}
	fmt.Fprintln(a.errw(), "Run recon on a terminal for a plan for each (zero-touch attempt, factory reset steps, wait for you).")
}

// pick shows a multi-select list. It returns the chosen indexes and false if cancelled.
func (a *app) pick(title string, items []string) ([]int, bool) {
	fd := int(os.Stdin.Fd())
	if !a.env.StdinIsTTY {
		return nil, false
	}
	st, err := term.MakeRaw(fd)
	if err != nil {
		return nil, false
	}
	defer term.Restore(fd, st)
	p := recon.NewPicker(items)
	col := func(code, s string) string { return a.colorOut(code, s) }
	draw := func(first bool) {
		if !first {
			fmt.Fprintf(a.errw(), "\x1b[%dA\x1b[J", len(items)+2)
		}
		fmt.Fprint(a.errw(), strings.ReplaceAll(p.Render(title, col), "\n", "\r\n"))
	}
	draw(true)
	buf := make([]byte, 8)
	for !p.Done {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return nil, false
		}
		p.Key(buf[:n])
		draw(false)
	}
	fmt.Fprint(a.errw(), "\r\n")
	if p.Canceled {
		return nil, false
	}
	return p.Chosen(), true
}

// enrollURL finds or makes the server's enrollment link.
func (a *app) enrollURL(pb *pbx.Client, link pbx.Link, flagURL string, interactive bool) (string, error) {
	if flagURL != "" {
		return flagURL, nil
	}
	if v := a.env.Getenv("YLCTL_ENROLL_URL"); v != "" {
		return v, nil
	}
	if pb == nil {
		return "", errors.New("not linked to a server and no enrollment link given: run 'ylctl login <server>' or pass --enroll-url")
	}
	kc := a.pbxCreds(link.Server)
	kc.Host = "pbx-enroll:" + strings.TrimPrefix(strings.TrimPrefix(link.Server, "https://"), "http://")
	if u, ok := creds.Get(a.ctx, kc, "url"); ok {
		return u, nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()
	st, err := pb.ProvisioningSettings(ctx)
	if err != nil {
		return "", fmt.Errorf("could not read the server's provisioning settings: %w", err)
	}
	if !interactive {
		return "", errors.New("no saved enrollment link; run on a terminal to make one, or pass --enroll-url")
	}
	q := "Enrollment is off on the server. Make an enrollment link now?"
	if st.EnrollmentOn {
		q = "The server has an enrollment link, but this computer does not hold it. Making a new one STOPS the old link working. Make a new one?"
	}
	if !a.yn(q, !st.EnrollmentOn) {
		return "", errors.New("no enrollment link; pass --enroll-url or try again")
	}
	e, err := pb.NewEnrollment(ctx)
	if err != nil {
		return "", fmt.Errorf("could not make an enrollment link: %w", err)
	}
	if err := creds.Save(a.ctx, kc, "url", e.URL); err != nil {
		a.warnf("made the link but could not keep it in the keychain (%v); pass it next time with --enroll-url or $YLCTL_ENROLL_URL", err)
	}
	return e.URL, nil
}

// reconBringIn registers the chosen phones and checks that the server saw them. It returns how many were registered.
func (a *app) reconBringIn(chosen []*reconPhone, pb *pbx.Client, link pbx.Link, set *recon.Settings, dir string, o reconOpts) int {
	// A phone the server has already claimed needs its OWN URL (the enrollment link only records phones and
	// always answers 404). Any other phone is enrolled with the enrollment link and claimed afterwards.
	var own, enrol []*reconPhone
	for _, p := range chosen {
		if p.Known == "claimed" && pb != nil {
			own = append(own, p)
		} else {
			enrol = append(enrol, p)
		}
	}
	url := ""
	if len(enrol) > 0 {
		var err error
		if url, err = a.enrollURL(pb, link, o.enrollURL, a.env.StdinIsTTY && !o.yes); err != nil {
			a.warnf("%v", err)
			enrol = nil
		}
	}
	fmt.Fprintf(a.errw(), "\n%s\n", a.color("1;36", "Plan"))
	dh := map[bool]string{true: "", false: " and switch off DHCP/PnP provisioning"}[o.keepDHCP]
	for _, p := range own {
		fmt.Fprintf(a.errw(), "  %-15s %s: issue its own private URL on the server (a new one; never shown) and write it to the phone%s, then Auto Provision Now\n", p.IP, p.label(), dh)
	}
	for _, p := range enrol {
		fmt.Fprintf(a.errw(), "  %-15s %s: set the Auto Provision URL to the server's enrollment link%s, then Auto Provision Now (claim it on the server afterwards, then run recon again to give it its own URL)\n", p.IP, p.label(), dh)
	}
	chosen = append(append([]*reconPhone(nil), own...), enrol...)
	if len(chosen) == 0 {
		return 0
	}
	if !o.register && !o.yes && !a.yn(fmt.Sprintf("Apply to %d phone(s)? SIP accounts and passwords are not touched.", len(chosen)), true) {
		fmt.Fprintln(a.errw(), "Not applied.")
		return 0
	}
	ok := 0
	var done []*reconPhone
	for _, p := range chosen {
		ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
		target := url
		var err error
		if p.Known == "claimed" && pb != nil {
			var dev *pbx.Device
			if dev, err = pb.DeviceByMAC(ctx, p.MAC); err == nil && dev != nil {
				var issued pbx.Device
				if issued, err = pb.IssueDeviceURL(ctx, dev.ID); err == nil {
					target = issued.ProvisionURL
				}
			} else if err == nil {
				err = errors.New("the server no longer knows this phone")
			}
		}
		if err == nil {
			err = a.reconRegisterPhone(ctx, p, target, o.keepDHCP)
		}
		cancel()
		if err != nil {
			fmt.Fprintf(a.errw(), "  %s  %s %v\n", p.IP, a.color("1;31", "failed:"), shortErr(err))
			continue
		}
		fmt.Fprintf(a.errw(), "  %s  %s\n", p.IP, a.color("1;32", "asked to fetch its configuration"))
		ok++
		done = append(done, p)
	}
	if pb != nil && len(done) > 0 {
		fmt.Fprintln(a.errw(), a.color("2", "Waiting up to 90 seconds for the server to see them..."))
		a.waitServerSees(pb, done, 90*time.Second)
	}
	return ok
}

// waitServerSees polls the server's device list until every phone's MAC is there or the time is up.
func (a *app) waitServerSees(pb *pbx.Client, ps []*reconPhone, max time.Duration) {
	deadline := time.Now().Add(max)
	seen := map[string]bool{}
	for time.Now().Before(deadline) && len(seen) < len(ps) {
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		ds, err := pb.Devices(ctx)
		cancel()
		if err != nil {
			continue
		}
		for _, d := range ds {
			m := recon.NormMAC(d.MAC)
			for _, p := range ps {
				if p.MAC == m && !seen[m] {
					seen[m] = true
					fmt.Fprintf(a.errw(), "  %s  %s (%s)\n", p.IP, a.color("1;32", "the server has it"), d.Status)
				}
			}
		}
	}
	for _, p := range ps {
		if !seen[p.MAC] {
			fmt.Fprintf(a.errw(), "  %s  %s\n", p.IP, a.color("33", "not seen by the server yet; it may need another minute (check the web UI, Provisioning > Unclaimed)"))
		}
	}
}
