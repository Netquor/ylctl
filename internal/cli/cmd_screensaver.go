package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/dob"
)

func (a *app) screensaverCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "screensaver",
		Short: "Phone screensaver: build the XML file, show or set the phone's XML screensaver, reset it",
		Long: "Yealink phones load their screensaver from an XML file (Settings > Preference > XML Screensaver URL). The file\n" +
			"uses Yealink's screensaver schema (YealinkIPPhoneCustomScreenSaver: clock, status icons, text lines, and on\n" +
			"color phones an image), NOT the XML Browser objects such as ImageScreen or TextScreen, which the phone rejects\n" +
			"there with 'load browser url error'. 'build --text ...' makes that file. 'set' and 'reset' change only the\n" +
			"screensaver fields on the Preference page and keep the old values so 'reset' puts them back.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(a.ssBuildCmd(), a.ssShowCmd(), a.ssSetCmd(), a.ssResetCmd())
	return c
}

var reSize = regexp.MustCompile(`^(\d{1,4})x(\d{1,4})$`)

func (a *app) ssBuildCmd() *cobra.Command {
	var img, out, size, colorURL, crop string
	var texts []string
	var clock, icons, contrast bool
	var sharpen, gamma float64
	var dither, pool string
	var cut float64
	var bold int
	var levels int
	var invert, darkBG, fullscreen, quiet bool
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Make the screensaver XML: --text/--clock/--status-icons (all models), or an experimental image",
		Long: "Mono (default): converts --image (a png, jpg or gif file or https URL) to a gray image no larger than --size\n" +
			"(default 192x64, the T41S screen), keeps its proportions, and writes the XML with the picture inline as\n" +
			"hexadecimal characters. A terminal preview shows what it will look like. Which end of the scale the phone treats\n" +
			"as dark is not documented: try --invert if the phone shows a negative. White logos on a transparent background\n" +
			"need --dark-bg so they show against black.\n\n" +
			"Color: with --color-url the XML just points the phone at an image URL it can download.",
		Args: cobra.NoArgs,
		RunE: run(func(*cobra.Command, []string) error {
			if len(texts) > 0 || clock || icons {
				x, err := dob.CustomXML(dob.CustomOptions{Lines: texts, Clock: clock, StatusIcons: icons, ImageURL: colorURL})
				if err != nil {
					return usageErr("%v", err)
				}
				return a.writeXML(out, x)
			}
			if colorURL != "" {
				x, err := dob.ColorXML(colorURL)
				if err != nil {
					return usageErr("%v", err)
				}
				return a.writeXML(out, x)
			}
			if img == "" {
				return usageErr("give --image (a logo file or URL), or --color-url for a color phone")
			}
			m := reSize.FindStringSubmatch(size)
			if m == nil {
				return usageErr("--size is WIDTHxHEIGHT, like 192x64")
			}
			w, _ := strconv.Atoi(m[1])
			h, _ := strconv.Atoi(m[2])
			src, err := loadImage(a, img)
			if err != nil {
				return err
			}
			if crop != "" {
				if src, err = cropPercent(src, crop); err != nil {
					return usageErr("%v", err)
				}
			}
			conv, err := dob.Convert(src, dob.Options{Width: w, Height: h, Levels: levels, Invert: invert, Dark: darkBG, Sharpen: sharpen, Gamma: gamma, Contrast: contrast, Dither: dither, Pool: pool, Cut: cut, Bold: bold})
			if err != nil {
				return usageErr("%v", err)
			}
			if !quiet {
				fmt.Fprintln(a.errw(), a.color("2", "preview (filled = bright on the phone, empty = dark):"))
				fmt.Fprint(a.errw(), conv.Preview())
			}
			return a.writeXML(out, dob.MonoXML(conv, fullscreen))
		}),
	}
	f := cmd.Flags()
	f.Float64Var(&sharpen, "sharpen", 0, "sharpen after scaling (0 off; 0.5 to 2 helps small pictures)")
	f.Float64Var(&gamma, "gamma", 1, "brightness curve (above 1 darker midtones, below 1 lighter)")
	f.BoolVar(&contrast, "contrast", false, "stretch the brightness range to use the whole scale")
	f.StringVar(&pool, "pool", "", "how to shrink: average (default) or max (keeps thin strokes solid)")
	f.Float64Var(&cut, "cut", 0, "with --levels 2: brightness 0..1 at which a pixel lights (low values like 0.25 fill in thin strokes)")
	f.IntVar(&bold, "bold", 0, "thicken lit areas by this many pixels")
	f.StringVar(&dither, "dither", "", "turn grays into fine dots: fs, atkinson or bayer (best with --levels 2 or 4)")
	f.StringArrayVar(&texts, "text", nil, "a line of text to show (repeat for more lines); works on every model, verified on a T41S")
	f.BoolVar(&clock, "clock", false, "show the time and date")
	f.BoolVar(&icons, "status-icons", false, "show the status icons")
	f.StringVar(&crop, "crop", "", "keep only this part of the picture, as percentages LEFT,TOP,RIGHT,BOTTOM (for example 17,5,83,72)")
	f.StringVar(&img, "image", "", "logo file or https URL (png, jpg, gif)")
	f.StringVar(&out, "out", "", "write the XML here (default: standard output)")
	f.StringVar(&size, "size", "192x64", "picture size in pixels, no larger than the phone's screen")
	f.IntVar(&levels, "levels", 16, "gray levels: 2, 4 or 16")
	f.BoolVar(&invert, "invert", false, "swap dark and bright")
	f.BoolVar(&darkBG, "dark-bg", false, "lay transparency over black (for white logos)")
	f.BoolVar(&fullscreen, "fullscreen", true, "ask the phone to use the whole screen")
	f.StringVar(&colorURL, "color-url", "", "make the XML for a color phone: the image URL it should download")
	f.BoolVar(&quiet, "no-preview", false, "do not draw the preview")
	return cmd
}

func (a *app) writeXML(out, xml string) error {
	if out == "" {
		_, err := io.WriteString(a.out(), xml)
		return err
	}
	if err := os.WriteFile(out, []byte(xml), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(a.errw(), "%s %s (%d bytes)\n", a.color("1;32", "wrote"), out, len(xml))
	return nil
}

func loadImage(a *app, src string) (image.Image, error) {
	var r io.ReadCloser
	if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
		cl := &http.Client{Timeout: 20 * time.Second}
		resp, err := cl.Get(src)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("%s answered %d", src, resp.StatusCode)
		}
		r = http.MaxBytesReader(nil, resp.Body, 8<<20)
	} else {
		f, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		r = f
	}
	defer r.Close()
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("could not read %s as a png, jpg or gif (an SVG must be rendered to a png first): %w", src, err)
	}
	return img, nil
}

func (a *app) ssShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <host>", Short: "The phone's screensaver settings (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			s, err := c.Screensaver(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(s)
			}
			wait := s.WaitSeconds
			if n, err := strconv.Atoi(wait); err == nil {
				wait = waitText(n)
			}
			w := a.table()
			fmt.Fprintf(w, "Wait time\t%s\nXML URL\t%s\n", wait, orDash(s.XMLURL, "(none)"))
			if s.HasType {
				fmt.Fprintf(w, "Type\t%s (0 default, 1 pictures, 2 server XML)\n", s.Type)
			} else {
				fmt.Fprintln(w, "Type\tnot offered on this model: the XML URL is the screensaver")
			}
			return w.Flush()
		}),
	}
}

func waitText(sec int) string {
	switch {
	case sec == 0:
		return "Off"
	case sec < 60:
		return fmt.Sprintf("%d s", sec)
	case sec < 3600:
		return fmt.Sprintf("%d min", sec/60)
	}
	return fmt.Sprintf("%d h", sec/3600)
}

func parseWait(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	m := map[string]int{"off": 0, "0": 0, "15s": 15, "30s": 30, "1m": 60, "2m": 120, "5m": 300, "10m": 600,
		"30m": 1800, "30min": 1800, "1h": 3600, "2h": 7200, "4h": 14400, "6h": 21600, "8h": 28800, "12h": 43200}
	if v, ok := m[s]; ok {
		return strconv.Itoa(v), nil
	}
	return "", fmt.Errorf("use off, 15s, 30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 6h, 8h or 12h")
}

type ssRestore struct {
	Host     string            `json:"host"`
	Saved    string            `json:"saved"`
	Previous map[string]string `json:"previous"`
}

func (a *app) ssRestorePath(label string) (string, error) {
	d, err := a.configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "screensaver-restore-"+safeName(label)+".json"), nil
}

func (a *app) ssSetCmd() *cobra.Command {
	var u, wait string
	var typ2, dry bool
	cmd := &cobra.Command{
		Use: "set <host>", Short: "Point the phone's screensaver at an XML URL (changes settings; reset puts them back)", Args: hostArg,
		Long: "Sets the XML Browser URL and, optionally, the wait time (the phone's menu goes down to 15s: off, 15s, 30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 6h, 8h, 12h).\n" +
			"The previous values are saved first; 'ylctl screensaver reset <host>' restores them. On color phones that have a\n" +
			"screensaver type, --type-xml selects 'server XML'.",
		RunE: run(func(_ *cobra.Command, args []string) error {
			if u == "" && wait == "" && !typ2 {
				return usageErr("nothing to set: give --url and/or --wait")
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			cur, err := c.Screensaver(a.ctx)
			if err != nil {
				return err
			}
			want := map[string]string{}
			if u != "" {
				want["XmlScreenSaverURL"] = u
			}
			if wait != "" {
				w, err := parseWait(wait)
				if err != nil {
					return usageErr("%v", err)
				}
				want["ScreenSaverWaitTime"] = w
			}
			if typ2 {
				if !cur.HasType {
					return usageErr("this phone has no screensaver type (the XML URL is the screensaver); leave out --type-xml")
				}
				want["ScreenSaverType"] = "2"
			}
			have := map[string]string{"XmlScreenSaverURL": cur.XMLURL, "ScreenSaverWaitTime": cur.WaitSeconds, "ScreenSaverType": cur.Type}
			change := map[string]string{}
			for k, v := range want {
				if have[k] != v {
					change[k] = v
					fmt.Fprintf(a.errw(), "  change %-20s %q -> %q\n", k, have[k], v)
				}
			}
			if len(change) == 0 {
				fmt.Fprintln(a.out(), "nothing to change: the phone already has these values")
				return nil
			}
			if dry {
				fmt.Fprintln(a.errw(), "dry run: nothing was changed")
				return nil
			}
			label := c.Target().Label()
			rp, err := a.ssRestorePath(label)
			if err != nil {
				return err
			}
			if _, statErr := os.Stat(rp); errors.Is(statErr, os.ErrNotExist) { // keep the ORIGINAL values across several sets
				prev := map[string]string{}
				for k := range change {
					prev[k] = have[k]
				}
				b, _ := json.MarshalIndent(ssRestore{Host: label, Saved: time.Now().UTC().Format(time.RFC3339), Previous: prev}, "", " ")
				if err := os.WriteFile(rp, b, 0o600); err != nil {
					return fmt.Errorf("could not save the previous values, so I will not change the phone: %w", err)
				}
			} else {
				// merge: add any field not saved before
				b, _ := os.ReadFile(rp)
				var r ssRestore
				if json.Unmarshal(b, &r) == nil {
					for k := range change {
						if _, ok := r.Previous[k]; !ok {
							r.Previous[k] = have[k]
						}
					}
					nb, _ := json.MarshalIndent(r, "", " ")
					_ = os.WriteFile(rp, nb, 0o600)
				}
			}
			if err := c.WriteScreensaver(a.ctx, change); err != nil {
				return err
			}
			fmt.Fprintf(a.out(), "%s. Previous values saved; undo with: ylctl screensaver reset %s\n", a.colorOut("1;32", "Screensaver set"), args[0])
			if _, ok := change["XmlScreenSaverURL"]; ok {
				fmt.Fprintln(a.out(), a.colorOut("2", "The phone shows it after the wait time of idle (set with --wait; the shortest is 15 seconds)."))
			}
			return nil
		}),
	}
	cmd.Flags().StringVar(&u, "url", "", "the XML address the phone downloads (https://...)")
	cmd.Flags().StringVar(&wait, "wait", "", "idle time before the screensaver: off, 15s, 30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 6h, 8h, 12h")
	cmd.Flags().BoolVar(&typ2, "type-xml", false, "on phones with a screensaver type, choose 'server XML'")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "show the change and send nothing")
	return cmd
}

func (a *app) ssResetCmd() *cobra.Command {
	return &cobra.Command{
		Use: "reset <host>", Short: "Put back the screensaver settings saved before 'screensaver set'", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			rp, err := a.ssRestorePath(c.Target().Label())
			if err != nil {
				return err
			}
			b, err := os.ReadFile(rp)
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(a.out(), "nothing to restore: no saved screensaver settings for this phone")
				return nil
			}
			if err != nil {
				return err
			}
			var r ssRestore
			if err := json.Unmarshal(b, &r); err != nil || len(r.Previous) == 0 {
				return fmt.Errorf("the restore file %s is unreadable; fix or delete it", rp)
			}
			if err := c.WriteScreensaver(a.ctx, r.Previous); err != nil {
				return fmt.Errorf("could not restore (the saved values stay in %s): %w", rp, err)
			}
			_ = os.Remove(rp)
			fmt.Fprintf(a.out(), "%s\n", a.colorOut("1;32", "restored the previous screensaver settings"))
			return nil
		}),
	}
}
