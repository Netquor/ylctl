package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Netquor/ylctl/internal/pbx"
	"github.com/Netquor/ylctl/internal/recon"
	"github.com/Netquor/ylctl/internal/yealink"
)

const (
	tftpCheckBack = 10 * time.Minute
	resetGiveUp   = 20 * time.Minute
	tickEvery     = 5 * time.Second
)

type waiter struct {
	p        *reconPhone
	kind     string // "reset" or "tftp"
	started  time.Time
	deadline time.Time
	lastSeen time.Time // last time we looked (tftp: every 20 s)
	down     bool      // the phone went offline (restarting)
	tries    int
	lastTry  time.Time
	finished bool
}

type reconEvent struct {
	p    *reconPhone
	text string
	good bool
	// retry asks the main loop to offer the reset plan again (the zero-touch check-back found nothing)
	retry bool
}

// reconStuck walks the phones we could not log in to: zero-touch first when the network has TFTP,
// then factory reset steps, and "wait for me" so the others keep going.
func (a *app) reconStuck(stuck []*reconPhone, pb *pbx.Client, link pbx.Link, set *recon.Settings, dir string, o reconOpts, allowDefault, trust bool) {
	events := make(chan reconEvent, 64)
	var mu sync.Mutex
	var waiters []*waiter
	var retry []*reconPhone
	enroll := ""
	enrollTried := false
	needEnroll := func() string {
		if !enrollTried {
			enrollTried = true
			if u, err := a.enrollURL(pb, link, o.enrollURL, true); err == nil {
				enroll = u
			} else {
				a.warnf("%v (a recovered phone will be logged in to and reported, not registered)", err)
			}
		}
		return enroll
	}

	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(tickEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			mu.Lock()
			ws := append([]*waiter(nil), waiters...)
			mu.Unlock()
			for _, w := range ws {
				if !w.finished {
					a.tickWaiter(ctx, w, events, pb, link, enroll, o, trust)
				}
			}
		}
	}()
	drain := func() {
		for {
			select {
			case e := <-events:
				mark, col := "·", "33"
				if e.good {
					mark, col = "✔", "1;32"
				}
				fmt.Fprintf(a.errw(), "%s %s  %s\n", a.color(col, mark), e.p.IP, e.text)
				if e.retry {
					mu.Lock()
					retry = append(retry, e.p)
					mu.Unlock()
				}
			default:
				return
			}
		}
	}
	active := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, w := range waiters {
			if !w.finished {
				n++
			}
		}
		return n
	}
	addWaiter := func(w *waiter) {
		mu.Lock()
		waiters = append(waiters, w)
		mu.Unlock()
	}

	fmt.Fprintf(a.errw(), "\n%s %d phone(s) answer but would not let us in.\n", a.color("1;33", "Needs attention:"), len(stuck))
	offer := func(p *reconPhone, allowTFTP bool) {
		drain()
		fmt.Fprintf(a.errw(), "\n%s  %s  %s\n", a.color("1;36", p.IP), p.label(), p.Detail)
		if allowTFTP {
			fmt.Fprintf(a.errw(), "  [t] zero-touch: power-cycle it; %s, and I check back in 10 minutes\n", ztWords(set.ZeroTouch()))
		}
		fmt.Fprintln(a.errw(), "  [r] factory reset steps for this phone")
		fmt.Fprintln(a.errw(), "  [w] wait for me: I am resetting it now, carry on with the others and watch for it")
		fmt.Fprintln(a.errw(), "  [s] skip it")
		for {
			switch strings.ToLower(a.askLine("  choose: ")) {
			case "t":
				if !allowTFTP {
					continue
				}
				if set.ZeroTouch() == recon.ZTUnknown {
					fmt.Fprintln(a.errw(), "  What does DHCP on this network hand to phones?")
					fmt.Fprintln(a.errw(), "    [u] the server's enrollment URL (option 66 = https://server/.../<token>/)")
					fmt.Fprintln(a.errw(), "    [t] the PBX's TFTP server (option 66 = tftp://server)")
					fmt.Fprintln(a.errw(), "    [n] neither / not sure")
					switch strings.ToLower(a.askLine("  choose: ")) {
					case "u":
						set.SetZeroTouch(recon.ZTDHCPURL)
					case "t":
						set.SetZeroTouch(recon.ZTTFTP)
					default:
						set.SetZeroTouch(recon.ZTNone)
					}
					_ = recon.Save(dir, *set)
				}
				if set.ZeroTouch() == recon.ZTNone || set.ZeroTouch() == recon.ZTUnknown {
					fmt.Fprintln(a.errw(), "  No zero-touch path is set up on this network. Choose r or w.")
					continue
				}
				if pb == nil {
					fmt.Fprintln(a.errw(), "  I can only check back if this computer is linked to the server (ylctl login). Choose r or w.")
					continue
				}
				if p.MAC == "" {
					p.MAC = recon.NormMAC(a.askLine("  MAC address of this phone (on the label on its back): "))
					if p.MAC == "" {
						fmt.Fprintln(a.errw(), "  That is not a MAC address.")
						continue
					}
				}
				fmt.Fprintf(a.errw(), "  Power-cycle %s now (unplug and replug it). I will check back for up to 10 minutes.\n", p.IP)
				addWaiter(&waiter{p: p, kind: "tftp", started: time.Now(), deadline: time.Now().Add(tftpCheckBack)})
				return
			case "r":
				a.printGuide(p)
				if a.yn("  Wait for you while you reset it?", true) {
					needEnroll()
					addWaiter(&waiter{p: p, kind: "reset", started: time.Now(), deadline: time.Now().Add(resetGiveUp)})
					fmt.Fprintf(a.errw(), "  Okay. I am watching %s; when it comes back with the factory login I will continue with it.\n", p.IP)
				}
				return
			case "w":
				needEnroll()
				a.printGuide(p)
				addWaiter(&waiter{p: p, kind: "reset", started: time.Now(), deadline: time.Now().Add(resetGiveUp)})
				fmt.Fprintf(a.errw(), "  Okay. I am watching %s.\n", p.IP)
				return
			case "s", "":
				return
			}
		}
	}

	for _, p := range stuck {
		offer(p, true)
	}
	// ---- wait for the ones in progress ----
	waitAll := func() {
		last := time.Now()
		for active() > 0 {
			select {
			case <-a.ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			drain()
			if time.Since(last) > 30*time.Second {
				last = time.Now()
				mu.Lock()
				var parts []string
				for _, w := range waiters {
					if !w.finished {
						parts = append(parts, fmt.Sprintf("%s (%s, %s left)", w.p.IP, map[string]string{"reset": "reset", "tftp": "zero-touch"}[w.kind], time.Until(w.deadline).Round(time.Second)))
					}
				}
				mu.Unlock()
				fmt.Fprintf(a.errw(), "%s waiting for %s  (Ctrl-C stops waiting)\n", a.color("2", "…"), strings.Join(parts, ", "))
			}
		}
		drain()
	}
	if active() > 0 {
		fmt.Fprintf(a.errw(), "\n%s\n", a.color("2", "Watching the phones above. Ctrl-C stops waiting; anything finished is kept."))
	}
	waitAll()
	// ---- zero-touch found nothing: offer the reset plan ----
	mu.Lock()
	again := retry
	retry = nil
	mu.Unlock()
	if len(again) > 0 && a.ctx.Err() == nil {
		fmt.Fprintf(a.errw(), "\n%s these phones did not appear on the server within 10 minutes. Factory reset is next.\n", a.color("1;33", "Zero-touch did not work:"))
		for _, p := range again {
			offer(p, false)
		}
		waitAll()
	}
}

func (a *app) printGuide(p *reconPhone) {
	g := recon.GuideFor(p.Vendor)
	fmt.Fprintf(a.errw(), "  %s (reported by the maker's guides; the key combination can differ by model)\n", a.color("1;35", "Factory reset, "+g.Vendor+":"))
	for i, s := range g.Steps {
		fmt.Fprintf(a.errw(), "    %d. %s\n", i+1, s)
	}
}

// tickWaiter advances one waiter by one step.
func (a *app) tickWaiter(ctx context.Context, w *waiter, ev chan<- reconEvent, pb *pbx.Client, link pbx.Link, enroll string, o reconOpts, trust bool) {
	now := time.Now()
	send := func(text string, good, retry bool) {
		select {
		case ev <- reconEvent{w.p, text, good, retry}:
		default:
		}
	}
	switch w.kind {
	case "tftp":
		if now.After(w.deadline) {
			w.finished = true
			send("not seen by the server in 10 minutes", false, true)
			return
		}
		if now.Sub(w.lastSeen) < 20*time.Second {
			return
		}
		w.lastSeen = now
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		ds, err := pb.Devices(c)
		cancel()
		if err != nil {
			return
		}
		for _, d := range ds {
			if recon.NormMAC(d.MAC) == w.p.MAC {
				w.finished = true
				send(fmt.Sprintf("the server has it now (%s). Finish in the web UI: %s/provisioning", d.Status, link.Server), true, false)
				return
			}
		}
	case "reset":
		if now.After(w.deadline) {
			w.finished = true
			send("gave up waiting (20 minutes). Run recon again once it has been reset.", false, false)
			return
		}
		pr, err := yealink.Probe(ctx, w.p.IP, []int{443, 80}, 1500*time.Millisecond)
		if err != nil || pr == nil {
			if !w.down {
				w.down = true
				send("went offline (restarting). I will look again when it is back.", false, false)
			}
			return
		}
		// It is up. Only try the factory login after we saw it restart (or 2 minutes passed), a few times, spaced out.
		if !w.down && now.Sub(w.started) < 2*time.Minute {
			return
		}
		if w.tries >= 3 || now.Sub(w.lastTry) < 15*time.Second {
			if w.tries >= 3 {
				w.finished = true
				send("is back but does not accept the factory login admin/admin. Was it reset? Check the steps and run recon again.", false, false)
			}
			return
		}
		w.tries++
		w.lastTry = now
		pins, _ := a.pinStore()
		c, err := yealink.New(fmt.Sprintf("%s://%s:%d", pr.Scheme, pr.IP, pr.Port), yealink.Options{Timeout: a.timeout, Pins: pins, TrustNew: trust, Insecure: a.insecure})
		if err != nil {
			return
		}
		if err := c.Login(ctx, "admin", "admin"); err != nil {
			return
		}
		w.finished = true
		send("accepts the factory login again.", true, false)
		if enroll == "" {
			send("no enrollment link available, so I left it as it is. Run recon again.", false, false)
			return
		}
		p := a.assess(ctx, *pr, w.p.MAC, pb, link, map[string]string{}, true, trust)
		if p.client == nil {
			return
		}
		if err := a.reconRegisterPhone(ctx, p, enroll, o.keepDHCP); err != nil {
			send("recovered, but registering it failed: "+shortErr(err), false, false)
			return
		}
		send("registered: it was asked to fetch its configuration from the server. Finish in the web UI: "+link.Server+"/provisioning", true, false)
	}
}

// ztWords says how a phone gets its first configuration in the stated mode.
func ztWords(z recon.ZeroTouch) string {
	switch z {
	case recon.ZTDHCPURL:
		return "it boots, DHCP hands it the enrollment URL, and it appears on the server as unclaimed"
	case recon.ZTTFTP:
		return "it fetches its setup from the PBX over TFTP"
	}
	return "it tries to fetch its setup (I will ask once what DHCP hands out here and remember it)"
}
