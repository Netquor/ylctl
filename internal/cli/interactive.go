package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// isInteractive is true only when a person is at a terminal (not in pipes, scripts or tests).
func (a *app) isInteractive() bool {
	out, ok := a.env.Stdout.(*os.File)
	return ok && a.env.StdinIsTTY && isTTY(out)
}

type guidePage struct {
	key   byte
	title string
	body  string
}

var guidePages = []guidePage{
	{'h', "Commands", `
  Find and look (read-only)
    discover <network>      find phones on a network, never logs in
    info <host>             model, firmware, MAC, uptime
    status <host>           registration state and network
    autop show <host>       auto-provision settings
    account show <host>     SIP account settings

  Change something (shows a before/after and asks first)
    provision-now <host>    make the phone fetch its config now
    adopt <host>            point the phone at your provisioning server
    autop set <host>        change one auto-provision setting
    firmware upgrade <host> <file.rom>   upload a .rom and reboot the phone into it (asks first)
    reboot <host>           restart the phone (asks first)
    password set <host>     change the web admin password (typed confirmation; keeps the vault in step)
    password recover <host> finish or undo an interrupted password change

  Find and bring in
    recon [subnet...]       scan, list phones and their state, bring unmanaged ones under management

  Watch live
    capture follow <host>   packets as they happen (status, stop)
    logs follow <host>      the phone's own log, live (show, restore)

  Setup
    auth save|forget        keep a phone password in the OS keychain
    login <server>          link this computer to your NQ Phone server (approve in the browser)
    whoami | logout         check or forget that link
    --mac <MAC>             use the phone's admin password from the server's vault
`},
	{'e', "Examples", `
  ylctl recon                                        (guesses your subnet; Enter, or type 10.1.0.0/24 or /23)
  ylctl recon --super 192.168.0.0/24 10.20.30.0/24  (several networks, fast)
  ylctl discover 192.168.0.0/24
  ylctl --try-default info 10.20.30.204
  ylctl status 10.20.30.211

  ylctl logs follow 10.20.30.211 --grep 'REGISTER|INVITE'
  ylctl logs follow 10.20.30.211 --json            (for scripts and AI)
  ylctl capture follow 10.20.30.211 --filter tls
  ylctl capture follow 10.20.30.211 --format pcap | wireshark -k -i -

  ylctl login https://pbx.example.com               (approve the code in your browser)
  ylctl --mac 80:5e:c0:00:00:0a info 10.20.30.211   (password comes from the vault)

  ylctl --mac 80:5e:c0:00:00:0a password set 10.20.30.211 --generate --dry-run
  ylctl adopt 10.20.30.211 --dry-run               (shows the change, sends nothing)
  ylctl provision-now 10.20.30.211

  Add --json to most commands for machine-readable output.
`},
	{'s', "Safety", `
  Passwords come from $YLCTL_PASSWORD, the OS keychain or a prompt, never from a flag.
  --try-default tries admin/admin once; it warns when that works. Change that password.

  Read-only:      discover, info, status, autop show, account show, logs show, capture status
  Changes phone:  adopt, autop set, provision-now, reboot, firmware upgrade, password set, logs follow (temporary), capture follow (temporary)

  logs follow saves the phone's old syslog settings first and puts them back when you quit.
  If a run is killed:  ylctl logs restore <host>
  capture follow always stops the capture on exit.  If it cannot:  ylctl capture stop <host>

  Not built on purpose (see the roadmap): factory reset.
`},
	{'a', "About", `
  ylctl talks to the web interface of Yealink desk phones on your own network.
  It is not affiliated with Yealink.

  ` + credit + `
`},
}

// interactive shows the banner and a key menu. It returns when the user quits.
func (a *app) interactive() error {
	in := os.Stdin
	st, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return nil
	}
	defer term.Restore(int(in.Fd()), st)
	// The guide lives on the alternate screen: quitting restores the terminal as it was.
	fmt.Fprint(a.out(), altOn)
	defer fmt.Fprint(a.out(), altOff)

	put := func(s string) { fmt.Fprint(a.out(), strings.ReplaceAll(s, "\n", "\r\n")) }
	clear := func() { put("\x1b[2J\x1b[H") }
	menu := func() {
		clear()
		a.bannerTo(put)
		put(a.colorOut("1;36", "  [h]") + " commands   " + a.colorOut("1;36", "[e]") + " examples   " +
			a.colorOut("1;36", "[s]") + " safety   " + a.colorOut("1;36", "[a]") + " about   " +
			a.colorOut("1;36", "[q]") + " quit\n\n  press a key: ")
	}
	menu()
	buf := make([]byte, 8)
	for {
		n, err := in.Read(buf)
		if err != nil || n == 0 {
			return nil
		}
		k := buf[0]
		if k >= 'A' && k <= 'Z' {
			k += 'a' - 'A'
		}
		switch {
		case k == 'q' || k == 3 || k == 4 || (k == 27 && n == 1):
			put("\n")
			return nil
		case k == '?' || k == '/':
			k = 'h'
			fallthrough
		default:
			for _, p := range guidePages {
				if p.key == k {
					clear()
					put(a.colorOut("1;35", "  "+p.title) + "\n")
					put(p.body)
					put(a.colorOut("2", "\n  any key: back to the menu   q: quit") + " ")
					n2, _ := in.Read(buf)
					if n2 > 0 && (buf[0] == 'q' || buf[0] == 'Q' || buf[0] == 3) {
						put("\n")
						return nil
					}
					menu()
				}
			}
		}
	}
}
