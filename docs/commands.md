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

## completion

`ylctl completion bash|zsh|fish|powershell`.

## Help and the terminal

On a terminal, `ylctl --help` and `ylctl <command> --help` open on the terminal's alternate screen, like `man` or `less`. Closing it restores the screen exactly as it was, so only the command you typed remains. Keys: `↑/↓` or `j/k` scroll, `space`/`b` page, `g`/`G` top and end, `q` (or Esc, Ctrl-C) closes, `p` closes and keeps the text in your scrollback. The interactive guide (`ylctl` with no arguments) does the same. Piped or scripted help, `TERM=dumb`, and `YLCTL_NO_VIEWER=1` print plainly instead.
