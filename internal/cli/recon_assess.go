package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Netquor/ylctl/internal/creds"
	"github.com/Netquor/ylctl/internal/pbx"
	"github.com/Netquor/ylctl/internal/recon"
	"github.com/Netquor/ylctl/internal/yealink"
)

// Phone states recon reports.
const (
	stManaged      = "managed"      // provisioning points at the server and it knows the phone
	stRegistered   = "registered"   // SIP registered somewhere, but not managed by the server
	stUnregistered = "unregistered" // reachable and logged in, no account registered
	stNoAuth       = "no-auth"      // answers, but no password we have works
	stLocked       = "locked"       // the phone locked its web login
	stError        = "error"
)

type reconPhone struct {
	IP, URL         string
	Model, Firmware string
	MAC             string // 12 hex, from the phone or the ARP table
	State           string
	Detail          string
	Registered      []string
	ServerURL       string
	Known           string // what the server says about this MAC: "", unclaimed, claimed
	RegHere         bool   // every registered account points at the linked server
	Vendor          string
	client          *yealink.Client
}

func (p *reconPhone) label() string {
	m := p.Model
	if p.Firmware != "" {
		m += " " + p.Firmware
	}
	return strings.TrimSpace(m)
}

type credTry struct{ user, pass, source string }

// candidates are the logins to try on one phone, best first. Each is tried once: a phone locks its web login after a few failures.
func (a *app) reconCandidates(ip, mac string, pb *pbx.Client, allowDefault bool) []credTry {
	var out []credTry
	seen := map[string]bool{}
	add := func(u, p, src string) {
		if p != "" && !seen[u+"\x00"+p] {
			seen[u+"\x00"+p] = true
			out = append(out, credTry{u, p, src})
		}
	}
	if pb != nil && mac != "" {
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		if s, err := pb.PhoneAdmin(ctx, mac, "ylctl recon"); err == nil {
			u := s.Username
			if u == "" {
				u = "admin"
			}
			add(u, s.Secret, "vault")
		}
		cancel()
	}
	if cr, err := creds.Resolve(a.ctx, creds.Options{Host: ip, User: a.user, Getenv: a.env.Getenv, Runner: a.env.Runner}); err == nil {
		add(cr.User, cr.Password, cr.Source)
	}
	if allowDefault {
		add("admin", "admin", "default")
	}
	return out
}

// assess logs in to one phone (once per candidate) and reads its state.
func (a *app) assess(ctx context.Context, pr yealink.ProbeResult, arpMAC string, pb *pbx.Client, link pbx.Link, known map[string]string, allowDefault, trust bool) *reconPhone {
	p := &reconPhone{IP: pr.IP, Model: pr.Model, Firmware: pr.Firmware, MAC: arpMAC, Vendor: "yealink"}
	target := fmt.Sprintf("%s://%s:%d", pr.Scheme, pr.IP, pr.Port)
	pins, err := a.pinStore()
	if err != nil {
		p.State, p.Detail = stError, err.Error()
		return p
	}
	c, err := yealink.New(target, yealink.Options{Timeout: a.timeout, Pins: pins, TrustNew: trust, Insecure: a.insecure})
	if err != nil {
		p.State, p.Detail = stError, err.Error()
		return p
	}
	cands := a.reconCandidates(pr.IP, arpMAC, pb, allowDefault)
	if len(cands) == 0 {
		p.State, p.Detail = stNoAuth, "no password to try (store one with 'ylctl auth save', link the server, or allow the factory default)"
		return p
	}
	var logged bool
	var lastErr error
	for _, cd := range cands {
		err := c.Login(ctx, cd.user, cd.pass)
		if err == nil {
			logged = true
			p.Detail = "login: " + cd.source
			break
		}
		lastErr = err
		if errors.Is(err, yealink.ErrLocked) {
			p.State, p.Detail = stLocked, "the phone locked its web login; wait a few minutes or reset it"
			return p
		}
		if !errors.Is(err, yealink.ErrAuthFailed) {
			p.State, p.Detail = stError, shortErr(err)
			return p
		}
	}
	if !logged {
		p.State = stNoAuth
		p.Detail = fmt.Sprintf("answers, but %d password(s) tried were refused", len(cands))
		_ = lastErr
		return p
	}
	p.client = c
	if st, err := c.Status(ctx); err == nil {
		if m := recon.NormMAC(st.Info.MAC); m != "" {
			p.MAC = m
		}
		if st.Info.Model != "" {
			p.Model = st.Info.Model
		}
		for _, ac := range st.Accounts {
			if ac.State.Code == 2 {
				p.Registered = append(p.Registered, ac.Label)
			}
		}
	}
	if ap, err := c.Autop(ctx); err == nil {
		p.ServerURL, _ = ap.Get(yealink.FieldServerURL)
	}
	p.Known = known[p.MAC]
	host := strings.TrimPrefix(strings.TrimPrefix(link.Server, "https://"), "http://")
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if len(p.Registered) > 0 && host != "" {
		p.RegHere = true
		for _, r := range p.Registered {
			if !strings.Contains(r, host) {
				p.RegHere = false
			}
		}
	}
	switch {
	case link.Server != "" && strings.Contains(p.ServerURL, host) && strings.Contains(p.ServerURL, "/webhooks/provision") && p.Known == "claimed":
		p.State = stManaged
	case len(p.Registered) > 0:
		p.State = stRegistered
	default:
		p.State = stUnregistered
	}
	return p
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		s = s[:90] + "..."
	}
	return s
}

// assessAll runs assess on every probe result with a worker pool.
func (a *app) assessAll(ctx context.Context, found []yealink.ProbeResult, arp map[string]string, pb *pbx.Client, link pbx.Link, known map[string]string, allowDefault, trust bool, workers int) []*reconPhone {
	out := make([]*reconPhone, len(found))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range found {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = a.assess(ctx, found[i], arp[found[i].IP], pb, link, known, allowDefault, trust)
		}(i)
	}
	wg.Wait()
	return out
}

// register points one logged-in phone at the enrollment link and asks it to fetch now.
func (a *app) reconRegisterPhone(ctx context.Context, p *reconPhone, enrollURL string, keepDHCP bool) error {
	if p.client == nil {
		return errors.New("not logged in to this phone")
	}
	ap, err := p.client.Autop(ctx)
	if err != nil {
		return err
	}
	set := map[string]string{yealink.FieldServerURL: enrollURL}
	if !keepDHCP {
		if _, ok := ap.Get(yealink.FieldEnableDHCP); ok {
			set[yealink.FieldEnableDHCP] = "0"
		}
		if _, ok := ap.Get(yealink.FieldEnablePNP); ok {
			set[yealink.FieldEnablePNP] = "0"
		}
	}
	if _, err := p.client.WriteAutop(ctx, set); err != nil {
		return err
	}
	if err := p.client.ProvisionNow(ctx); err != nil {
		return fmt.Errorf("settings written, but 'provision now' failed: %w", err)
	}
	return nil
}
