package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/dob"
	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) logoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "logo",
		Short: "The phone's LCD logo (monochrome models): build the .dob file, upload it, switch it on, delete it",
		Long: "Yealink's own logo route for monochrome phones (T41S, T42S/G, T41P: at most 192x64, 2 gray levels): a .dob file\n" +
			"uploaded to the phone (Features > General Information > LCD Logo) and shown on the idle screen alternately\n" +
			"with the normal idle screen. The byte layout of .dob is documented only by an open-source converter for older\n" +
			"phones; whether the T41S wants dark as the high value is tried on the phone (--white-high).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(a.logoShowCmd(), a.logoSetCmd(), a.logoModeCmd(), a.logoDeleteCmd())
	return c
}

func (a *app) logoShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <host>", Short: "The LCD logo mode (read-only)", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			m, err := c.Logo(a.ctx)
			if err != nil {
				return err
			}
			name := map[yealink.LogoMode]string{yealink.LogoOff: "off", yealink.LogoSystem: "system logo", yealink.LogoCustom: "custom logo"}[m]
			if name == "" {
				name = "unknown (" + string(m) + ")"
			}
			fmt.Fprintln(a.out(), "LCD logo:", name)
			return nil
		}),
	}
}

func (a *app) logoModeCmd() *cobra.Command {
	return &cobra.Command{
		Use: "mode <host> <off|system|custom>", Short: "Choose which logo the phone shows", Args: cobra.ExactArgs(2),
		RunE: run(func(_ *cobra.Command, args []string) error {
			m := map[string]yealink.LogoMode{"off": yealink.LogoOff, "system": yealink.LogoSystem, "custom": yealink.LogoCustom}[args[1]]
			if m == "" {
				return usageErr("the mode is off, system or custom")
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.SetLogoMode(a.ctx, m); err != nil {
				return err
			}
			fmt.Fprintln(a.out(), "LCD logo mode set to", args[1])
			return nil
		}),
	}
}

func (a *app) logoDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use: "delete <host>", Short: "Delete the uploaded custom logo and switch the logo off", Args: hostArg,
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.DeleteLogo(a.ctx); err != nil {
				return err
			}
			_ = c.SetLogoMode(a.ctx, yealink.LogoOff)
			fmt.Fprintln(a.out(), "custom logo deleted")
			return nil
		}),
	}
}

func (a *app) logoSetCmd() *cobra.Command {
	var img, size, crop, dither, pool, outFile string
	var levels, bold int
	var invert, whiteHigh, contrast, noMode bool
	var sharpen, gamma, cut float64
	cmd := &cobra.Command{
		Use: "set <host>", Short: "Convert a picture to .dob, upload it and switch the custom logo on (changes settings)", Args: hostArg,
		Long: "Converts --image to a .dob (default 192x64, 2 levels), uploads it to the phone and sets the LCD logo mode to\n" +
			"custom. With --out the file is also written to disk. Use 'ylctl logo mode <host> off' or 'logo delete' to undo.\n" +
			"If the picture comes out as a negative, repeat with --white-high.",
		RunE: run(func(_ *cobra.Command, args []string) error {
			if img == "" {
				return usageErr("give --image (a logo file or URL)")
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
			conv, err := dob.Convert(src, dob.Options{Width: w, Height: h, Levels: levels, Invert: invert, Dark: true, Sharpen: sharpen, Gamma: gamma, Contrast: contrast, Dither: dither, Pool: pool, Cut: cut, Bold: bold})
			if err != nil {
				return usageErr("%v", err)
			}
			data, err := conv.DOB(!whiteHigh)
			if err != nil {
				return usageErr("%v", err)
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, data, 0o644); err != nil {
					return err
				}
			}
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			if err := c.UploadLogo(a.ctx, data); err != nil {
				return err
			}
			if !noMode {
				if err := c.SetLogoMode(a.ctx, yealink.LogoCustom); err != nil {
					return err
				}
			}
			fmt.Fprintf(a.out(), "%s (%d bytes, %dx%d). The phone shows it on the idle screen alternately with the normal one.\n", a.colorOut("1;32", "Logo uploaded"), len(data), w, h)
			return nil
		}),
	}
	f := cmd.Flags()
	f.StringVar(&img, "image", "", "logo file or https URL (png, jpg, gif); white logos on transparent are laid over black")
	f.StringVar(&size, "size", "192x64", "picture size in pixels (at most 192x64 on a T41S)")
	f.StringVar(&crop, "crop", "", "keep only this part of the picture, as percentages LEFT,TOP,RIGHT,BOTTOM")
	f.IntVar(&levels, "levels", 2, "gray levels: 2, 4 or 16 (the T41S takes 2)")
	f.BoolVar(&invert, "invert", false, "swap dark and bright in the picture")
	f.BoolVar(&whiteHigh, "white-high", false, "write bright as the high value (the opposite of the older-phone layout); try this if the logo is a negative")
	f.StringVar(&outFile, "out", "", "also write the .dob file here")
	f.BoolVar(&noMode, "no-mode", false, "upload only; do not switch the logo mode")
	f.Float64Var(&sharpen, "sharpen", 0, "sharpen after scaling")
	f.Float64Var(&gamma, "gamma", 1, "brightness curve")
	f.BoolVar(&contrast, "contrast", false, "stretch the brightness range")
	f.StringVar(&dither, "dither", "", "fs, atkinson or bayer")
	f.StringVar(&pool, "pool", "", "average (default) or max")
	f.Float64Var(&cut, "cut", 0, "with --levels 2: brightness at which a pixel lights")
	f.IntVar(&bold, "bold", 0, "thicken lit areas by this many pixels")
	return cmd
}
