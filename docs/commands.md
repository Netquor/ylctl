# ylctl command reference

`ylctl [global flags] <command> [args]`. Data goes to stdout, messages, diffs and warnings to stderr. Exit codes are listed in the [README](../README.md#exit-codes).

## Global flags

| flag | meaning |
|---|---|
| `--user NAME` | web user (default `admin`, or `$YLCTL_USER`) |
| `--json` | JSON output on stdout |
| `--timeout DURATION` | per request, default `10s` |
| `--trust-new` | pin the certificate of a phone seen for the first time without asking |
| `--insecure` | skip TLS verification entirely (escape hatch, not recorded) |
| `--try-default` | use the factory login `admin`/`admin` once instead of a stored password |
| `--reveal` | print provisioning URLs in full (they contain a token) |
| `--no-color` | no color (also `NO_COLOR`) |

Environment: `YLCTL_PASSWORD`, `YLCTL_USER`, `YLCTL_CONFIG_DIR` (default `$XDG_CONFIG_HOME/ylctl` or `~/.config/ylctl`).

`<host>` is `10.0.0.5`, `10.0.0.5:8443`, `https://10.0.0.5` or `[fe80::1]:443`. Credentials inside a host are refused.

## version

`ylctl version` prints version, commit and build date (`--json` for an object).

## discover

`ylctl discover [cidr] [--yes] [--force] [--allow-public] [--workers 32] [--rate 100] [--ports 443,80]`

Probes every address (network and broadcast excluded) on the ports, then fetches `/servlet?m=mod_listener&p=login&q=loginForm` and recognises a Yealink phone from the page.
No credentials are ever sent. Without a CIDR the private IPv4 subnets of your up interfaces are used. Private ranges only (`--allow-public` overrides), ranges larger than /22 need `--force`,
and you are asked to confirm on a terminal unless `--yes` (without a terminal and without `--yes` it exits 2).
Output columns: address, model, firmware, port/scheme, certificate fingerprint prefix. JSON: `{"ranges":[...],"probed":N,"phones":[{"ip","port","scheme","model","firmware","cert_sha256"}]}`.

## info

`ylctl info <host>`: model, firmware, hardware, MAC, IP, uptime. Read-only. JSON fields: `model firmware hardware mac ip uptime_seconds uptime`.

## status

`ylctl status <host>`: WAN type, IP/mask/gateway/DNS, VLAN, link speed, uptime and one row per account with the registration state and the raw phone code.
JSON: `{"info":{...},"network":{...},"accounts":[{"index","account","state":{"code","state","observed_live"}}]}`.
State codes: see [protocol.md](protocol.md#account-status-codes). Read-only.

## autop show

`ylctl autop show <host>`: every `AutoProvision*` field of Settings > Auto Provision (PNP, DHCP option, server URL, user, password, AES keys, power on, repeat, weekly, flexible).
Secrets are `********`; the server URL is truncated unless `--reveal`. Read-only.

## account show

`ylctl account show <host> [--account N]` (1 to 16, default 1): enabled, label, display name, register name, user name, password (masked), SIP servers with port and transport (UDP, TCP, TLS, DNS-NAPTR), outbound proxy. Read-only.

## provision-now

`ylctl provision-now <host>`: POST `q=autopnow`. The phone fetches its provisioning files immediately. Whether it did can be seen on the provisioning server; the phone's own status page does not report it.

## adopt

`ylctl adopt <host> --url URL [--disable-dhcp] [--disable-pnp] [--dry-run] [--force]`

1. logs in and reads Auto Provision;
2. computes the changes: `AutoProvisionServerURL`, and with the flags `AutoProvisionEnableDHCPOption=0` and `AutoProvisionEnablePNP=0` (only if currently on);
3. shows a before/after diff on stderr; `--dry-run` stops here (exit 0, nothing sent);
4. if nothing would change it exits **6** without sending anything, unless `--force`, which rewrites the given values;
5. writes the changed fields, re-reads the page and checks every value (a mismatch is an error);
6. triggers provision-now. If that fails after a successful write: exit **7**.

SIP accounts, passwords, server host and transport are never touched. The URL is an argument and therefore visible to other users of the same machine in `ps`; use it on a machine you trust.

## autop set

`ylctl autop set <host> Field=value... [--dry-run] [--force]`: change non-secret Auto Provision fields, e.g. `RepeatMinutes=61` (prefix `AutoProvision` optional).
Same diff, dry-run, verify and exit 6 behaviour as `adopt`, but it does **not** trigger provisioning. Secret fields (`Password`, `AESKey16`, `AESKey16MAC`) are refused with exit 2.

## auth

`ylctl auth save <host> [--user NAME]` prompts for the password (terminal needed) and stores it in the macOS keychain (`security`) or Linux secret service (`secret-tool`) as `<user>@<host>`;
the password is passed to the helper on stdin, never as an argument. `ylctl auth forget <host>` removes it. Nothing else ever writes to the keychain.

## password

`ylctl password set <host> (--generate | --prompt) [--mac MAC | --keychain] [--length 20] [--dry-run] [--yes] [--yes-i-understand]`
`ylctl password recover <host> (--mac MAC | --keychain)`

Changes the web admin password and keeps the server vault (or the keychain) in step, in an order that cannot lose it: pending record first, then the phone, then a fresh-session login with the new password, then commit. Never takes the new password from the command line, never prints a password.
Full design, safeguards, failure states and the live test checklist: [password.md](password.md).

## firmware

`ylctl firmware` reads and upgrades the phone's firmware. It uses the phone's own Upgrade page, so it needs the same login as the other commands.

### firmware status

`ylctl firmware status <host>`: running firmware version and model. Read-only.

```sh
ylctl firmware status 192.168.1.50
```

### firmware upgrade

`ylctl firmware upgrade <host> <file.rom> [--dry-run] [--yes] [--wait 10m]`

1. reads the `.rom` header (model, version, size, SHA-256) and checks it is a Yealink image;
2. reads the phone's current version. The same version is refused;
3. shows the plan. `--dry-run` stops here and sends nothing;
4. asks first (`--yes` skips the question; without a terminal and without `--yes` it does not run);
5. uploads the file the way the phone's Upgrade page does, then waits up to `--wait` for the phone to answer with the new version.

The phone reboots itself while it flashes and is unreachable for a few minutes. Do not unplug it. A dropped connection during the upload does not mean it failed: check the version with `firmware status` before you retry.

```sh
ylctl firmware upgrade 192.168.1.50 ~/Downloads/T4XS-66.86.0.180.rom --dry-run
ylctl firmware upgrade 192.168.1.50 ~/Downloads/T4XS-66.86.0.180.rom --yes
```

## login, logout, whoami

These link this computer to your NQ Phone server.

- `ylctl login <server> [--name NAME] [--allow-http]`: links this computer to the server. You approve it in your browser; `--name` sets the name shown on that approval page (default `ylctl`). `--allow-http` is for a trusted lab network only.
- `ylctl whoami`: shows the linked server and tests the link.
- `ylctl logout`: forgets the link on this computer.

```sh
ylctl login https://pbx.example.com --name "ops laptop"
ylctl whoami
ylctl logout
```

## reboot

`ylctl reboot <host> [--yes] [--force]`: restarts the phone from its web interface. It refuses while the phone is on a call (`--force` overrides) and asks first (`--yes` skips the question).

```sh
ylctl reboot 192.168.1.50 --yes
```

## recon

`ylctl recon [subnet...] [--super] [--yes] [--no-prompt] [--enroll-url URL] [--auto-register-discovered] [--tftp | --no-tftp] [--dhcp-url] [--keep-dhcp-provisioning] [--force]`

Finds phones on the subnets you name (or a guessed local subnet), shows which are registered, and offers to bring unmanaged ones under management. `--no-prompt` only reports and changes nothing. `--super` uses many parallel workers, for networks you own. Ranges larger than /22 need `--force`.

```sh
ylctl recon 192.168.1.0/24 --no-prompt
```

## capture

Packet capture on the phone's Diagnostics page. The phone captures; `ylctl` decodes the stream.

### capture status

`ylctl capture status <host>`: is a capture running? Read-only.

### capture stop

`ylctl capture stop <host>`: stops a capture left running on the phone.

### capture follow

`ylctl capture follow <host> [--format summary|sip|json|pcap] [--filter sip|tcp|udp|tls|dns|arp|icmp] [--ip ADDR] [--port N] [--call-id ID] [--duration 5m] [--max-bytes 20971520] [--out FILE] [--force]`

Starts a capture and prints packets as they arrive. It always stops the capture on exit, on Ctrl-C and when a limit is reached. Refuses if a capture is already running unless `--force`.

```sh
ylctl capture follow 192.168.1.50 --filter sip
ylctl capture follow 192.168.1.50 --format pcap | wireshark -k -i -
```

## logs

The phone's remote syslog, sent to this computer.

### logs show

`ylctl logs show <host>`: the phone's remote syslog settings. Read-only.

### logs follow

`ylctl logs follow <host> [--port 5514] [--ip ADDR] [--level 6] [--grep REGEX] [--duration 10m] [--format text|json] [--dry-run]`

Points the phone's syslog at this computer, prints what arrives, and puts the phone's old settings back when you quit. `--dry-run` shows the change and exits without changing the phone.

```sh
ylctl logs follow 192.168.1.50 --grep 'REGISTER|INVITE'
ylctl logs follow 192.168.1.50 --format json
```

### logs restore

`ylctl logs restore <host>`: puts back the syslog settings saved before a `logs follow` run. Use it if a run was killed.

## push

Pushes XML to the phone, which draws it at once. Useful for previews.

### push show

`ylctl push show <host>`: which addresses the phone accepts pushed XML from. Read-only.

### push allow

`ylctl push allow <host> [--ip ADDR]`: adds this computer to the phone's Push XML Server list. The old value is saved so `push reset` can restore it.

### push send

`ylctl push send <host> [--file FILE.xml] [--text "Title" --text "line"] [--image PICTURE] [--size 192x64] [--crop L,T,R,B] [--levels 2|4|16] [--invert] [--dither fs|atkinson|bayer]`

Sends one XML object: an XML file, a text screen (the first `--text` is the title), or a picture converted to a hex image.

```sh
ylctl push send 192.168.1.50 --text "Hello" --text "from ylctl"
ylctl push send 192.168.1.50 --image logo.png --levels 2
```

### push reset

`ylctl push reset <host>`: puts back the Push XML Server value saved before `push allow`.

## logo

The LCD logo on monochrome models (T41S, T42S/G, T41P). A picture is converted to Yealink's `.dob` format.

### logo show

`ylctl logo show <host>`: the current logo mode. Read-only.

### logo set

`ylctl logo set <host> --image PICTURE [--size 192x64] [--levels 2] [--crop L,T,R,B] [--invert] [--white-high] [--dither fs|atkinson|bayer] [--out FILE.dob] [--no-mode]`

Converts the picture, uploads it and switches the custom logo on. `--no-mode` uploads without changing the mode.

```sh
ylctl logo set 192.168.1.50 --image logo.png
```

### logo mode

`ylctl logo mode <host> off|system|custom`: chooses which logo the phone shows.

### logo delete

`ylctl logo delete <host>`: deletes the uploaded custom logo and switches the logo off.

## screensaver

Yealink phones load their screensaver from an XML file at a URL.

### screensaver show

`ylctl screensaver show <host>`: the phone's screensaver settings. Read-only.

### screensaver build

`ylctl screensaver build [--text LINE]... [--clock] [--status-icons] [--image PICTURE] [--crop L,T,R,B] [--size WxH] [--levels N] [--out FILE.xml]`

Writes the screensaver XML file (to standard output unless `--out`). It does not contact a phone.

```sh
ylctl screensaver build --text "Netquor" --clock --out screensaver.xml
```

### screensaver set

`ylctl screensaver set <host> --url https://... [--wait 5m] [--type-xml] [--dry-run]`: points the phone's screensaver at an XML URL. `--wait` sets the idle time before it starts. `--dry-run` shows the change and sends nothing. `screensaver reset` puts the saved settings back.

### screensaver reset

`ylctl screensaver reset <host>`: puts back the screensaver settings saved before `screensaver set`.

## completion

`ylctl completion bash|zsh|fish|powershell`.

## Help and the terminal

On a terminal, `ylctl --help` and `ylctl <command> --help` open on the terminal's alternate screen, like `man` or `less`. Closing it restores the screen exactly as it was, so only the command you typed remains. Keys: `↑/↓` or `j/k` scroll, `space`/`b` page, `g`/`G` top and end, `q` (or Esc, Ctrl-C) closes, `p` closes and keeps the text in your scrollback. The interactive guide (`ylctl` with no arguments) does the same. Piped or scripted help, `TERM=dumb`, and `YLCTL_NO_VIEWER=1` print plainly instead.
