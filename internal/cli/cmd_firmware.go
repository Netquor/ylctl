package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netquor/ylctl/internal/yealink"
)

func (a *app) firmwareCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "firmware",
		Short: "Phone firmware: show the running version, or upgrade from a .rom file",
		Long:  "Firmware works the way the phone's own Upgrade page does: the version is read from the page, and an upgrade uploads a .rom file through it.\nThe phone reboots itself when the new firmware is in. 'upgrade' waits until the phone answers with the new version.",
	}
	c.AddCommand(a.firmwareStatusCmd(), a.firmwareUpgradeCmd())
	return c
}

func (a *app) firmwareStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status <host>", Short: "Running firmware version and model (read-only)", Args: hostArg,
		Example: "  ylctl firmware status 192.168.1.50",
		RunE: run(func(_ *cobra.Command, args []string) error {
			c, _, err := a.connect(args[0])
			if err != nil {
				return err
			}
			st, err := c.CurrentFirmware(a.ctx)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(st)
			}
			w := a.table()
			fmt.Fprintf(w, "Model\t%s\nFirmware\t%s\n", st.Model, st.Version)
			return w.Flush()
		}),
	}
}

func (a *app) firmwareUpgradeCmd() *cobra.Command {
	var yes, dry bool
	var wait time.Duration
	cmd := &cobra.Command{
		Use: "upgrade <host> <file.rom>", Short: "Upgrade the phone from a .rom file (reboots the phone)", Args: cobra.ExactArgs(2),
		Long: "Uploads a .rom file to the phone, the way its Upgrade page does, then waits for the phone to come back on the new version.\n" +
			"The file's header is checked first. The phone itself refuses a file with the same version as its own (-7) or an older one (-16).\n" +
			"The phone reboots during the upgrade and is unreachable for a few minutes. Do not unplug it.\n" +
			"It asks first (--yes skips the question). --dry-run shows what would happen and sends nothing.",
		Example: "  ylctl firmware upgrade 192.168.1.50 ~/Downloads/T4XS-66.86.0.180.rom --dry-run\n" +
			"  ylctl firmware upgrade 192.168.1.50 ~/Downloads/T4XS-66.86.0.180.rom --yes",
		RunE: run(func(_ *cobra.Command, args []string) error {
			host, path := args[0], args[1]
			rom, hdr, err := yealink.ReadROM(path)
			if err != nil {
				return err
			}
			c, _, err := a.connect(host)
			if err != nil {
				return err
			}
			now, err := c.CurrentFirmware(a.ctx)
			if err != nil {
				return err
			}
			if now.Version == hdr.Version {
				return fmt.Errorf("the phone is already on %s; nothing to do", hdr.Version)
			}
			plan := map[string]any{
				"host": host, "file": filepath.Base(path), "file_bytes": hdr.Size, "sha256": hdr.SHA256,
				"from_version": now.Version, "to_version": hdr.Version, "rom_model": hdr.Model, "phone_model": now.Model,
			}
			if dry {
				if a.jsonOut {
					return a.printJSON(map[string]any{"dry_run": true, "plan": plan})
				}
				fmt.Fprintf(a.out(), "dry run: nothing sent\n  phone      %s, firmware %s\n  file       %s (%d bytes, sha256 %s)\n  header     model %s, version %s\n  would go   %s -> %s\n",
					now.Model, now.Version, filepath.Base(path), hdr.Size, hdr.SHA256, hdr.Model, hdr.Version, now.Version, hdr.Version)
				return nil
			}
			if !yes {
				if !a.confirm(fmt.Sprintf("Upgrade %s from %s to %s and reboot it? ", host, now.Version, hdr.Version)) {
					return fmt.Errorf("not upgraded (pass --yes to skip this question)")
				}
			}
			if !a.jsonOut {
				fmt.Fprintf(a.errw(), "uploading %s (%d bytes) to %s ...\n", filepath.Base(path), hdr.Size, host)
			}
			if _, err := c.UploadFirmware(a.ctx, rom, filepath.Base(path)); err != nil {
				return err
			}
			if !a.jsonOut {
				fmt.Fprintf(a.errw(), "upload accepted; waiting up to %s for %s ...\n", wait, hdr.Version)
			}
			done, err := c.WaitFirmware(a.ctx, hdr.Version, wait)
			if err != nil {
				return err
			}
			if a.jsonOut {
				return a.printJSON(map[string]any{"host": host, "from_version": now.Version, "version": done.Version, "upgraded": true})
			}
			fmt.Fprintf(a.out(), "upgraded: %s is now on %s\n", host, done.Version)
			return nil
		}),
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "show the plan and send nothing")
	cmd.Flags().DurationVar(&wait, "wait", 10*time.Minute, "how long to wait for the phone to come back on the new version")
	return cmd
}
