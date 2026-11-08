package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/syslog"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) logsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "logs",
		Short: "Phone logs: show the syslog settings, follow the log live, restore settings",
		Long: "'follow' points the phone's remote syslog at this computer, prints what arrives, and puts the\n" +
			"phone's previous syslog settings back when you quit (Ctrl-C, time limit or error). The previous\n" +
			"values are saved first in your ylctl config folder; 'logs restore' puts them back if a run was\n" +
			"killed. Only the syslog fields are ever changed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(a.logsShowCmd(), a.logsRestoreCmd(), a.logsFollowCmd())
	return c
}

var transportNames = map[string]string{"0": "UDP", "1": "TCP", "2": "TLS"}
var levelNames = []string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}

func describeSyslog(s yealink.Syslog) string {
	on := "off"
	if s["SyslogSwitch"] == "1" {
		on = "on"
	}
	lv := s["SyslogLevel"]
	if n, err := strconv.Atoi(lv); err == nil && n >= 0 && n < len(levelNames) {
		lv = fmt.Sprintf("%d (%s)", n, levelNames[n])
	}
	return fmt.Sprintf("syslog %s, server %q port %s, transport %s, level %s, facility %s, prepend MAC %s",
		on, s["SyslogServerName"], s["SyslogServerPort"], transportNames[s["SyslogTransportType"]], lv, s["SyslogFacility"], s["SyslogPrependMac"])
}

func (a *app) logsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <host>", Short: "The phone's remote syslog settings (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			s, err := c.Syslog(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(s)
			}
			fmt.Fprintln(a.out(), describeSyslog(s))
			return nil
		}),
	}
}

// ---- restore file ----

type restoreFile struct {
	Host     string            `json:"host"`
	Saved    string            `json:"saved"`
	Previous map[string]string `json:"previous"`
}

func (a *app) restorePath(host string) (string, error) {
	d, err := yealink.ConfigDir(a.env.Getenv)
	if err != nil {
		return "", err
	}
	safe := regexp.MustCompile(`[^A-Za-z0-9_.-]`).ReplaceAllString(host, "_")
	return filepath.Join(d, "syslog-restore-"+safe+".json"), nil
}

func saveRestore(path string, r restoreFile) error {
	b, _ := json.MarshalIndent(r, "", " ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *app) logsRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use: "restore <host>", Short: "Put back the syslog settings saved before a 'logs follow' run", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			return a.doRestore(c, args[0])
		}),
	}
}

func (a *app) doRestore(c *yealink.Client, host string) error {
	path, err := a.restorePath(c.Target().Label())
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(a.out(), "nothing to restore: no saved syslog settings for this phone")
		return nil
	}
	if err != nil {
		return err
	}
	var r restoreFile
	if err := json.Unmarshal(b, &r); err != nil || len(r.Previous) == 0 {
		return fmt.Errorf("the restore file %s is unreadable; fix or delete it", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cur, err := c.Syslog(ctx)
	if err != nil {
		return err
	}
	diff := map[string]string{}
	for k, v := range r.Previous {
		if cur[k] != v {
			diff[k] = v
		}
	}
	if len(diff) > 0 {
		if err := c.WriteSyslog(ctx, diff); err != nil {
			return fmt.Errorf("could not restore (the saved values stay in %s): %w", path, err)
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Fprintf(a.out(), "%s %s\n", a.colorOut("1;32", "restored:"), describeSyslog(r.Previous))
	return nil
}

// ---- follow ----

type logsOpts struct {
	listen   string
	ip       string
	port     int
	level    int
	grep     string
	duration time.Duration
	dryRun   bool
	format   string
}

func (a *app) logsFollowCmd() *cobra.Command {
	var o logsOpts
	cmd := &cobra.Command{
		Use:   "follow <host>",
		Short: "Send the phone's syslog to this computer and print it live",
		Long: "Changes ONLY the phone's syslog fields (switch, server, port, transport, level), prints what arrives\n" +
			"from that phone, and restores the previous values on exit. Use --dry-run to see the change first.\n" +
			"Level 6 (info) includes the SIP signalling the phone sends and receives, readable even when the\n" +
			"phone uses TLS. Your computer's firewall may ask to allow incoming UDP.\n\n" +
			"Formats: text (default) or --json (one object per line).",
		Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			if a.jsonOut {
				o.format = "json"
			}
			if o.level < 0 || o.level > 7 {
				return usageErr("--level must be 0 to 7")
			}
			if o.port < 1 || o.port > 65535 {
				return usageErr("--port must be 1 to 65535")
			}
			if o.duration <= 0 {
				return usageErr("--duration must be positive")
			}
			var re *regexp.Regexp
			if o.grep != "" {
				var err error
				if re, err = regexp.Compile(o.grep); err != nil {
					return usageErr("--grep: %v", err)
				}
			}
			return a.logsFollow(args[0], o, re)
		}),
	}
	f := cmd.Flags()
	f.IntVar(&o.port, "port", 5514, "UDP port to listen on and to give the phone")
	f.StringVar(&o.ip, "ip", "", "this computer's address as the phone should reach it (default: detected)")
	f.IntVar(&o.level, "level", 6, "syslog level the phone sends, 0 emergency to 7 debug (6 = info, includes SIP)")
	f.StringVar(&o.grep, "grep", "", "only lines matching this regular expression")
	f.DurationVar(&o.duration, "duration", 10*time.Minute, "stop after this long")
	f.BoolVar(&o.dryRun, "dry-run", false, "show the change and exit without changing the phone")
	f.StringVar(&o.format, "format", "text", "text or json")
	return cmd
}

func localIPToward(host string) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, "9"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	ip, _, err := net.SplitHostPort(conn.LocalAddr().String())
	return ip, err
}

func (a *app) logsFollow(host string, o logsOpts, re *regexp.Regexp) error {
	c, _, err := a.connect(host)
	if err != nil {
		return err
	}
	label := c.Target().Label()
	phoneIP := label
	if h, _, err := net.SplitHostPort(label); err == nil {
		phoneIP = h
	}
	myIP := o.ip
	if myIP == "" {
		if myIP, err = localIPToward(phoneIP); err != nil {
			return fmt.Errorf("could not work out this computer's address; use --ip: %w", err)
		}
	}
	cur, err := c.Syslog(a.ctx)
	if err != nil {
		return err
	}
	rpath, err := a.restorePath(label)
	if err != nil {
		return err
	}
	// A restore file from an earlier run holds the real original values: keep it.
	prev := cur
	if b, rerr := os.ReadFile(rpath); rerr == nil {
		var r restoreFile
		if json.Unmarshal(b, &r) == nil && len(r.Previous) > 0 {
			prev = r.Previous
			a.warnf("an earlier run did not restore this phone; the saved original values are kept (%s)", rpath)
		}
	}
	want := map[string]string{
		"SyslogSwitch": "1", "SyslogServerName": myIP, "SyslogServerPort": strconv.Itoa(o.port),
		"SyslogTransportType": "0", "SyslogLevel": strconv.Itoa(o.level),
	}
	change := map[string]string{}
	for k, v := range want {
		if cur[k] != v {
			change[k] = v
		}
	}
	keys := make([]string, 0, len(change))
	for k := range change {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(a.errw(), "phone now:   %s\n", describeSyslog(cur))
	for _, k := range keys {
		fmt.Fprintf(a.errw(), "  change %-20s %q -> %q\n", k, cur[k], change[k])
	}
	if o.dryRun {
		fmt.Fprintln(a.errw(), "dry run: nothing was changed")
		return nil
	}

	// Listen first, so nothing is lost and a port clash is found before touching the phone.
	ctx, cancel := context.WithTimeout(a.ctx, o.duration)
	defer cancel()
	msgs := make(chan syslog.Message, 256)
	_, serve, err := syslog.Listen(ctx, ":"+strconv.Itoa(o.port), phoneIP, msgs)
	if err != nil {
		return fmt.Errorf("cannot listen on UDP port %d: %w", o.port, err)
	}

	if len(change) > 0 {
		if err := saveRestore(rpath, restoreFile{Host: label, Saved: time.Now().UTC().Format(time.RFC3339), Previous: prev}); err != nil {
			return fmt.Errorf("could not save the restore file, so I will not change the phone: %w", err)
		}
		restored := false
		restore := func() {
			if restored {
				return
			}
			restored = true
			if err := a.doRestore(c, host); err != nil {
				fmt.Fprintf(a.errw(), "%s could not restore the phone's syslog settings: %v\nRun: ylctl logs restore %s\n", a.color("1;31", "WARNING:"), err, host)
			}
		}
		defer restore()
		if err := c.WriteSyslog(ctx, change); err != nil {
			restore()
			return err
		}
		defer func() { fmt.Fprintln(a.errw(), "restoring the phone's previous syslog settings") }()
	}
	keyCh, endKeys := a.liveKeys()
	defer endKeys()
	fmt.Fprintln(a.errw(), a.color("1;32", "listening")+fmt.Sprintf(" on UDP %d for %s (limit %s)", o.port, phoneIP, o.duration))
	if keyCh != nil {
		a.showKeyHelp()
	}
	sv := &saver{a: a, kind: "logs", host: label}
	defer sv.close()

	srvErr := make(chan error, 1)
	go func() { srvErr <- serve() }()
	for {
		select {
		case k, ok := <-keyCh:
			if !ok {
				keyCh = nil
				continue
			}
			switch k {
			case 'q', 'Q', 3, 4:
				cancel()
			case 's', 'S':
				sv.toggle(nil)
			case 'c', 'C':
				a.clearScreen()
			case '?', 'h':
				a.showKeyHelp()
			}
		case m := <-msgs:
			if re != nil && !re.MatchString(m.Raw) {
				continue
			}
			if sv.file != nil {
				fmt.Fprintln(sv.file, plainLog(m, o.format))
				sv.count++
			}
			a.printLog(m, o.format)
		case err := <-srvErr:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *app) printLog(m syslog.Message, format string) {
	if format == "json" {
		b, _ := json.Marshal(map[string]any{
			"time": m.Received.UTC().Format(time.RFC3339Nano), "from": m.From, "severity": m.SeverityName(),
			"facility": m.Facility, "host": m.Host, "tag": m.Tag, "module": m.Module, "text": m.Text,
		})
		fmt.Fprintf(a.out(), "%s\n", b)
		return
	}
	col := map[string]string{"emerg": "1;31", "alert": "1;31", "crit": "1;31", "error": "31", "warn": "33", "notice": "36", "debug": "2"}[m.SeverityName()]
	sev := fmt.Sprintf("%-6s", m.SeverityName())
	if col != "" {
		sev = a.colorOut(col, sev)
	}
	tag := m.Tag
	if tag != "" {
		tag += ": "
	}
	// Color the whole line by its module or tag; errors stay red so they stand out.
	text := m.Text
	body := tag + text
	switch m.SeverityName() {
	case "emerg", "alert", "crit", "error":
		body = a.colorOut("31", body)
	default:
		if k := m.Key(); k != "" {
			body = a.colorOut(tagColor(k), body)
		}
	}
	fmt.Fprintf(a.out(), "%s %s %s\n", a.colorOut("2", m.Received.Format("15:04:05.000")), sev, body)
}

func (a *app) colorOut(code, s string) string {
	f, ok := a.env.Stdout.(*os.File)
	if !ok || a.noColor || a.env.Getenv("NO_COLOR") != "" || !isTTY(f) {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// plainLog is the uncolored line that goes into a saved file.
func plainLog(m syslog.Message, format string) string {
	if format == "json" {
		b, _ := json.Marshal(map[string]any{
			"time": m.Received.UTC().Format(time.RFC3339Nano), "from": m.From, "severity": m.SeverityName(),
			"facility": m.Facility, "host": m.Host, "tag": m.Tag, "module": m.Module, "text": m.Text,
		})
		return string(b)
	}
	tag := m.Tag
	if tag != "" {
		tag += ": "
	}
	return fmt.Sprintf("%s %-6s %s%s", m.Received.Format("15:04:05.000"), m.SeverityName(), tag, m.Text)
}

var tagPalette = []string{"36", "35", "33", "34", "96", "95", "93", "94", "92", "32"}

// tagColor gives every module or tag a stable color. SIP is always bright green.
func tagColor(key string) string {
	switch strings.ToUpper(key) {
	case "SIP":
		return "1;32"
	case "SYS":
		return "2;37"
	}
	h := fnv.New32a()
	h.Write([]byte(strings.ToUpper(key)))
	return tagPalette[int(h.Sum32())%len(tagPalette)]
}
