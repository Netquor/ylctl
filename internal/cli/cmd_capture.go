package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/pcap"
)

func (a *app) captureCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "capture",
		Short: "Packet capture on the phone: status, stop, and a live follow",
		Long: "The phone's Diagnostics page can capture the packets it sends and receives and stream them as a\n" +
			"pcap download. 'follow' reads that stream while it is still arriving and prints each packet\n" +
			"(or SIP message) as it happens. SIP over TLS (port 5061) is encrypted: you will see the TLS\n" +
			"records but not the messages. For readable SIP from a TLS phone use 'ylctl logs follow'.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(a.captureStatusCmd(), a.captureStopCmd(), a.captureFollowCmd())
	return c
}

func (a *app) captureStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status <host>", Short: "Is a capture running on the phone? (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			on, err := c.CaptureStatus(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]bool{"running": on})
			}
			if on {
				fmt.Fprintln(a.out(), a.colorOut("1;33", "capture is running"))
			} else {
				fmt.Fprintln(a.out(), a.colorOut("2", "no capture running"))
			}
			return nil
		}),
	}
}

func (a *app) captureStopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stop <host>", Short: "Stop a capture that is running on the phone", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.StopCapture(a.ctx); err != nil {
				return err
			}
			on, err := c.CaptureStatus(a.ctx)
			if err != nil {
				return err
			}
			if on {
				return fmt.Errorf("the phone still reports a running capture")
			}
			fmt.Fprintln(a.out(), a.colorOut("1;32", "capture stopped"))
			return nil
		}),
	}
}

type captureOpts struct {
	format   string
	outFile  string
	filter   string
	ip       string
	port     int
	callID   string
	duration time.Duration
	maxBytes int64
	force    bool
}

func (a *app) captureFollowCmd() *cobra.Command {
	var o captureOpts
	cmd := &cobra.Command{
		Use:   "follow <host>",
		Short: "Start a capture and print packets live (stops the capture when you quit)",
		Long: "Starts a capture on the phone (refuses if one is already running, unless --force) and decodes the\n" +
			"stream as it arrives. Always stops the capture on exit, on Ctrl-C and when a limit is reached.\n\n" +
			"Formats:\n" +
			"  summary  one line per packet (default)\n" +
			"  sip      each SIP message in full (plain SIP only; TLS is not decrypted)\n" +
			"  json     one JSON object per line, for scripts and AI assistants (also: --json)\n" +
			"  pcap     raw pcap bytes on stdout: ylctl capture follow HOST --format pcap | wireshark -k -i -\n\n" +
			"Filters: --filter sip|tcp|udp|tls|dns|arp, --ip ADDRESS, --port N, --call-id ID.\n" +
			"Limits: --duration (default 5m) and --max-bytes (default 20 MiB) protect the phone.",
		Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			if a.jsonOut {
				o.format = "json"
			}
			switch o.format {
			case "summary", "sip", "json", "pcap":
			default:
				return usageErr("--format must be summary, sip, json or pcap")
			}
			if o.duration <= 0 || o.maxBytes <= 0 {
				return usageErr("--duration and --max-bytes must be positive")
			}
			return a.captureFollow(args[0], o)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&o.format, "format", "summary", "summary, sip, json or pcap")
	f.StringVar(&o.outFile, "out", "", "also save the raw pcap to this file")
	f.StringVar(&o.filter, "filter", "", "only show: sip, tcp, udp, tls, dns, arp, icmp")
	f.StringVar(&o.ip, "ip", "", "only packets from or to this address")
	f.IntVar(&o.port, "port", 0, "only packets from or to this port")
	f.StringVar(&o.callID, "call-id", "", "only SIP messages with this Call-ID")
	f.DurationVar(&o.duration, "duration", 5*time.Minute, "stop after this long")
	f.Int64Var(&o.maxBytes, "max-bytes", 20<<20, "stop after this many bytes of capture")
	f.BoolVar(&o.force, "force", false, "stop a capture that is already running and start a new one")
	return cmd
}

func (a *app) captureFollow(host string, o captureOpts) error {
	c, _, err := a.connect(host)
	if err != nil {
		return err
	}
	on, err := c.CaptureStatus(a.ctx)
	if err != nil {
		return err
	}
	if on {
		if !o.force {
			return fmt.Errorf("a capture is already running on the phone (someone may be using it); use 'capture stop' or --force")
		}
		if err := c.StopCapture(a.ctx); err != nil {
			return err
		}
	}

	var file *os.File
	if o.outFile != "" {
		file, err = os.OpenFile(o.outFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return usageErr("--out: %v", err)
		}
		defer file.Close()
	}

	ctx, cancel := context.WithTimeout(a.ctx, o.duration)
	defer cancel()
	cs, err := c.OpenCapture(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.errw(), a.color("1;32", "capturing")+fmt.Sprintf(" on %s (limit %s or %d bytes; Ctrl-C stops it)", c.Target().Label(), o.duration, o.maxBytes))

	// Whatever happens next, stop the capture on the phone.
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cs.Body.Close()
		sctx, scancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer scancel()
		if err := c.StopCapture(sctx); err != nil {
			fmt.Fprintf(a.errw(), "%s could not stop the capture on the phone: %v\nRun: ylctl capture stop %s\n", a.color("1;31", "WARNING:"), err, host)
			return
		}
		if on, err := c.CaptureStatus(sctx); err == nil && on {
			fmt.Fprintf(a.errw(), "%s the phone still reports a running capture. Run: ylctl capture stop %s\n", a.color("1;31", "WARNING:"), host)
		}
	}
	defer stop()

	reason, err := a.pumpCapture(ctx, cancel, cs.Body, o, file, c.Target().Label())
	stop()
	fmt.Fprintln(a.errw(), a.color("1;36", "capture ended")+": "+reason)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

// pumpCapture reads the stream and prints packets until a limit, the end of the stream or cancellation.
func (a *app) pumpCapture(ctx context.Context, cancel context.CancelFunc, body io.Reader, o captureOpts, file *os.File, label string) (string, error) {
	type chunk struct {
		b   []byte
		err error
	}
	ch := make(chan chunk, 4)
	go func() {
		defer close(ch)
		buf := make([]byte, 32<<10)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				ch <- chunk{b: append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				ch <- chunk{err: err}
				return
			}
		}
	}()

	pr := &printer{a: a, o: o}
	var parser pcap.Parser
	var total int64
	keys, endKeys := a.liveKeys()
	defer endKeys()
	if keys != nil {
		a.showKeyHelp()
	}
	sv := &saver{a: a, kind: "capture", host: label}
	defer sv.close()
	var pw *pcap.Writer
	for {
		select {
		case k, ok := <-keys:
			if !ok {
				keys = nil
				continue
			}
			switch k {
			case 'q', 'Q', 3, 4:
				cancel()
			case 's', 'S':
				pw = nil
				sv.toggle(func(f *os.File) error {
					hdr, ok := parser.Header()
					if !ok {
						return errors.New("no packets yet; try again in a moment")
					}
					pw = pcap.NewWriter(f, hdr.LinkType, hdr.SnapLen)
					return pw.WriteHeader()
				})
			case 'c', 'C':
				a.clearScreen()
			case '?', 'h':
				a.showKeyHelp()
			}
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Sprintf("duration limit %s reached", o.duration), nil
			}
			return "interrupted", nil
		case c, ok := <-ch:
			if !ok {
				return "stream closed", nil
			}
			if c.err != nil {
				if errors.Is(c.err, io.EOF) {
					return "the phone ended the stream", parser.Finish()
				}
				if ctx.Err() != nil {
					return "interrupted", nil
				}
				return "read error", c.err
			}
			total += int64(len(c.b))
			if file != nil {
				if _, err := file.Write(c.b); err != nil {
					return "write error", err
				}
			}
			if o.format == "pcap" {
				if _, err := a.out().Write(c.b); err != nil {
					return "output closed", nil
				}
			}
			pk, err := parser.Feed(c.b)
			if o.format != "pcap" {
				hdr, _ := parser.Header()
				for _, p := range pk {
					if sv.file != nil && pw != nil {
						if pw.WritePacket(p) == nil {
							sv.count++
						}
					}
					pr.packet(hdr.LinkType, p)
				}
			}
			if err != nil {
				return "bad capture data", err
			}
			if total >= o.maxBytes {
				return fmt.Sprintf("size limit %d bytes reached", o.maxBytes), nil
			}
		}
	}
}

type printer struct {
	a    *app
	o    captureOpts
	sip  pcap.SIPStream
	last time.Time
}

type jsonPacket struct {
	Time    string   `json:"time"`
	Src     string   `json:"src,omitempty"`
	Dst     string   `json:"dst,omitempty"`
	SrcPort int      `json:"src_port,omitempty"`
	DstPort int      `json:"dst_port,omitempty"`
	Proto   string   `json:"proto"`
	Len     int      `json:"len"`
	Info    string   `json:"info,omitempty"`
	TLS     bool     `json:"tls,omitempty"`
	SIP     *jsonSIP `json:"sip,omitempty"`
}

type jsonSIP struct {
	First  string `json:"first"`
	CallID string `json:"call_id,omitempty"`
	CSeq   string `json:"cseq,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Text   string `json:"text,omitempty"`
}

func (p *printer) match(f pcap.Frame, msgs []*pcap.SIPMessage) bool {
	o := p.o
	if o.ip != "" && f.Src != o.ip && f.Dst != o.ip {
		return false
	}
	if o.port != 0 && f.SrcPort != o.port && f.DstPort != o.port {
		return false
	}
	switch strings.ToLower(o.filter) {
	case "":
	case "sip":
		if f.SIP == nil && len(msgs) == 0 {
			return false
		}
	case "tcp", "udp", "arp", "icmp":
		if !strings.EqualFold(f.Proto, o.filter) && !(o.filter == "icmp" && strings.HasPrefix(f.Proto, "ICMP")) {
			return false
		}
	case "tls":
		if !f.TLS {
			return false
		}
	case "dns":
		if !strings.Contains(f.Info, "DNS") {
			return false
		}
	default:
		return false
	}
	return true
}

func (p *printer) packet(link uint32, pk pcap.Packet) {
	f := pcap.Decode(link, pk)
	var msgs []*pcap.SIPMessage
	if f.SIP != nil {
		msgs = []*pcap.SIPMessage{f.SIP}
	} else if f.Proto == "TCP" && len(f.Payload) > 0 && !f.TLS {
		flow := fmt.Sprintf("%s:%d>%s:%d", f.Src, f.SrcPort, f.Dst, f.DstPort)
		msgs = p.sip.Feed(flow, f.Payload)
		if len(msgs) > 0 {
			f.Info = joinNonEmpty(" ", f.Info, msgs[0].Summary())
		}
	}
	if !p.match(f, msgs) {
		return
	}
	if p.o.callID != "" {
		ok := false
		for _, m := range msgs {
			ok = ok || m.CallID == p.o.callID
		}
		if !ok {
			return
		}
	}
	ts := f.Time.Format("15:04:05.000")
	switch p.o.format {
	case "json":
		j := jsonPacket{Time: f.Time.UTC().Format(time.RFC3339Nano), Src: f.Src, Dst: f.Dst, SrcPort: f.SrcPort, DstPort: f.DstPort,
			Proto: f.Proto, Len: f.Len, Info: f.Info, TLS: f.TLS}
		if len(msgs) > 0 {
			m := msgs[0]
			j.SIP = &jsonSIP{First: m.First, CallID: m.CallID, CSeq: m.CSeq, From: m.From, To: m.To, Text: string(m.Raw)}
		}
		b, _ := json.Marshal(j)
		fmt.Fprintf(p.a.out(), "%s\n", b)
	case "sip":
		for _, m := range msgs {
			fmt.Fprintf(p.a.out(), "%s\n%s\n", p.a.colorOut("1;32", fmt.Sprintf("---- %s  %s:%d -> %s:%d  %s", ts, f.Src, f.SrcPort, f.Dst, f.DstPort, f.Proto)),
				strings.ReplaceAll(strings.TrimRight(string(m.Raw), "\r\n"), "\r\n", "\n"))
		}
	default:
		src, dst := f.Src, f.Dst
		if f.SrcPort != 0 {
			src = fmt.Sprintf("%s:%d", f.Src, f.SrcPort)
			dst = fmt.Sprintf("%s:%d", f.Dst, f.DstPort)
		}
		proto := p.a.colorOut(protoColor(f), fmt.Sprintf("%-5s", f.Proto))
		info := f.Info
		if f.SIP != nil || len(msgs) > 0 {
			info = p.a.colorOut("1;32", info)
		} else if f.TLS {
			info = p.a.colorOut("35", info)
		}
		fmt.Fprintf(p.a.out(), "%s %s %-22s -> %-22s %4d  %s\n", p.a.colorOut("2", ts), proto, src, dst, f.Len, info)
	}
}

func protoColor(f pcap.Frame) string {
	switch {
	case f.SIP != nil:
		return "1;32"
	case f.TLS:
		return "35"
	case f.Proto == "TCP":
		return "36"
	case f.Proto == "UDP":
		return "34"
	case f.Proto == "ARP" || strings.HasPrefix(f.Proto, "ICMP"):
		return "33"
	}
	return "2"
}
