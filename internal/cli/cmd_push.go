package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/dob"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) pushCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "push",
		Short: "Push an XML screen to a phone right now (shows at once and wakes the phone), for previews",
		Long: "A pushed XML object is drawn by the phone immediately and wakes it, which makes it a quick way to preview a\n" +
			"design. The phone only accepts a push from the addresses in its Push XML Server list, which is blank (refuse\n" +
			"all) by default: 'allow' adds this computer, 'reset' puts the old value back.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(a.pushAllowCmd(), a.pushShowCmd(), a.pushSendCmd(), a.pushResetCmd())
	return c
}

type pushRestore struct {
	Host  string `json:"host"`
	Saved string `json:"saved"`
	Prev  string `json:"previous"`
}

func (a *app) pushRestorePath(label string) (string, error) {
	d, err := a.configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "push-restore-"+safeName(label)+".json"), nil
}

func (a *app) pushAllowCmd() *cobra.Command {
	var ip string
	cmd := &cobra.Command{
		Use: "allow <host>", Short: "Let this computer push XML to the phone (changes the phone's Push XML Server list)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if ip == "" {
				if ip, err = yealink.LocalIPToward(c.Target().Host); err != nil {
					return fmt.Errorf("could not work out this computer's address; pass --ip: %w", err)
				}
			}
			cur, err := c.PushServer(a.ctx)
			if err != nil {
				return err
			}
			if cur == ip {
				fmt.Fprintln(a.out(), "nothing to change: the phone already accepts pushes from", ip)
				return nil
			}
			rp, err := a.pushRestorePath(c.Target().Label())
			if err != nil {
				return err
			}
			if _, e := os.Stat(rp); errors.Is(e, os.ErrNotExist) {
				b, _ := json.MarshalIndent(pushRestore{Host: c.Target().Label(), Saved: time.Now().UTC().Format(time.RFC3339), Prev: cur}, "", " ")
				if err := os.WriteFile(rp, b, 0o600); err != nil {
					return fmt.Errorf("could not save the previous value, so I will not change the phone: %w", err)
				}
			}
			fmt.Fprintf(a.errw(), "  change PushXMLServerIP %q -> %q\n", cur, ip)
			if err := c.WritePushServer(a.ctx, ip); err != nil {
				return err
			}
			fmt.Fprintf(a.out(), "%s. Undo with: ylctl push reset %s\n", a.colorOut("1;32", "Push allowed from "+ip), args[0])
			return nil
		}),
	}
	cmd.Flags().StringVar(&ip, "ip", "", "the address allowed to push (default: this computer's address toward the phone)")
	return cmd
}

func (a *app) pushShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <host>", Short: "Which addresses the phone accepts pushed XML from (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			v, err := c.PushServer(a.ctx)
			if err != nil {
				return err
			}
			if v == "" {
				v = "(blank: the phone refuses every push)"
			}
			fmt.Fprintln(a.out(), "Push XML Server:", v)
			return nil
		}),
	}
}

func (a *app) pushResetCmd() *cobra.Command {
	return &cobra.Command{
		Use: "reset <host>", Short: "Put back the Push XML Server value saved before 'push allow'", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			rp, err := a.pushRestorePath(c.Target().Label())
			if err != nil {
				return err
			}
			b, err := os.ReadFile(rp)
			if err != nil {
				return fmt.Errorf("nothing saved for %s: 'push allow' was not used from this computer", args[0])
			}
			var r pushRestore
			if json.Unmarshal(b, &r) != nil {
				return errors.New("the saved file is unreadable: " + rp)
			}
			if err := c.WritePushServer(a.ctx, r.Prev); err != nil {
				return err
			}
			_ = os.Remove(rp)
			fmt.Fprintf(a.out(), "%s (the Push XML Server is back to %q)\n", a.colorOut("1;32", "Restored"), r.Prev)
			return nil
		}),
	}
}

func (a *app) pushSendCmd() *cobra.Command {
	var file, img, size, crop string
	var texts []string
	var levels int
	var invert, dark, contrast bool
	var sharpen, gamma float64
	var dither, pool string
	var cut float64
	var bold int
	cmd := &cobra.Command{
		Use: "send <host>", Short: "Push an XML file, a few lines of text, or an image (as a hex picture) to the phone", Args: hostArg,
		Long: "Sends one XML object to the phone, which draws it at once.\n" +
			"  --file x.xml     any XML Browser object (ImageScreen, TextScreen, ...), sent as is\n" +
			"  --text LINE ...  a TextScreen with a title and these lines\n" +
			"  --image logo.png a picture converted to the phone's hex image (--size, --levels, --invert, --dark-bg)\n" +
			"The phone must allow this computer first: 'ylctl push allow <host>'. The screen stays until a key is pressed\n" +
			"(Timeout 0).",
		RunE: run(func(_ *cobra.Command, args []string) error {
			var x string
			switch {
			case file != "":
				b, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				x = string(b)
			case img != "":
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
				conv, err := dob.Convert(src, dob.Options{Width: w, Height: h, Levels: levels, Invert: invert, Dark: dark, Sharpen: sharpen, Gamma: gamma, Contrast: contrast, Dither: dither, Pool: pool, Cut: cut, Bold: bold})
				if err != nil {
					return usageErr("%v", err)
				}
				x = dob.MonoXML(conv, true)
			case len(texts) > 0:
				var sb strings.Builder
				sb.WriteString("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<YealinkIPPhoneTextScreen Beep=\"no\" Timeout=\"0\" LockIn=\"no\">\n")
				sb.WriteString("  <Title wrap=\"no\">" + xmlEsc(texts[0]) + "</Title>\n  <Text>" + xmlEsc(strings.Join(texts[1:], "\n")) + "</Text>\n</YealinkIPPhoneTextScreen>\n")
				x = sb.String()
			default:
				return usageErr("give --file, --text or --image")
			}
			host := strings.TrimPrefix(strings.TrimPrefix(args[0], "https://"), "http://")
			if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
				host = host[:i]
			}
			if err := yealink.PushXML(a.ctx, host, x); err != nil {
				return err
			}
			fmt.Fprintln(a.out(), "pushed: the phone shows it now")
			return nil
		}),
	}
	f := cmd.Flags()
	f.StringVar(&file, "file", "", "an XML file to push")
	f.StringArrayVar(&texts, "text", nil, "TextScreen: the first is the title, the rest are lines")
	f.StringVar(&img, "image", "", "logo file or https URL to convert and push as an ImageScreen")
	f.StringVar(&size, "size", "192x64", "picture size in pixels")
	f.StringVar(&crop, "crop", "", "keep only this part of the picture, as percentages LEFT,TOP,RIGHT,BOTTOM (for example 17,5,83,72)")
	f.IntVar(&levels, "levels", 16, "gray levels: 2, 4 or 16")
	f.BoolVar(&invert, "invert", false, "swap dark and bright")
	f.Float64Var(&sharpen, "sharpen", 0, "sharpen after scaling (0 off; 0.5 to 2 helps small pictures)")
	f.Float64Var(&gamma, "gamma", 1, "brightness curve (above 1 darker midtones, below 1 lighter)")
	f.BoolVar(&contrast, "contrast", false, "stretch the brightness range to use the whole scale")
	f.StringVar(&pool, "pool", "", "how to shrink: average (default) or max (keeps thin strokes solid)")
	f.Float64Var(&cut, "cut", 0, "with --levels 2: brightness 0..1 at which a pixel lights (low values like 0.25 fill in thin strokes)")
	f.IntVar(&bold, "bold", 0, "thicken lit areas by this many pixels")
	f.StringVar(&dither, "dither", "", "turn grays into fine dots: fs, atkinson or bayer (best with --levels 2 or 4)")
	f.BoolVar(&dark, "dark-bg", false, "lay transparency over black (for white logos)")
	return cmd
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;").Replace(s)
}

// cropPercent keeps the rectangle given as "LEFT,TOP,RIGHT,BOTTOM" percentages of the picture.
func cropPercent(src image.Image, spec string) (image.Image, error) {
	p := strings.Split(spec, ",")
	if len(p) != 4 {
		return nil, errors.New("--crop is LEFT,TOP,RIGHT,BOTTOM in percent, like 17,5,83,72")
	}
	var v [4]int
	for i := range p {
		n, err := strconv.Atoi(strings.TrimSpace(p[i]))
		if err != nil || n < 0 || n > 100 {
			return nil, errors.New("--crop values are whole percentages from 0 to 100")
		}
		v[i] = n
	}
	if v[0] >= v[2] || v[1] >= v[3] {
		return nil, errors.New("--crop: RIGHT must be greater than LEFT and BOTTOM greater than TOP")
	}
	b := src.Bounds()
	r := image.Rect(b.Min.X+b.Dx()*v[0]/100, b.Min.Y+b.Dy()*v[1]/100, b.Min.X+b.Dx()*v[2]/100, b.Min.Y+b.Dy()*v[3]/100)
	sub, ok := src.(interface {
		SubImage(image.Rectangle) image.Image
	})
	if !ok {
		return nil, errors.New("this picture type cannot be cropped")
	}
	return sub.SubImage(r), nil
}
