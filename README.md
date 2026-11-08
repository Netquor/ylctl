# ylctl

```text
    .--------------------------.
   /  .--------------------.    \
  |   | ylctl         [ok] |  ==|             _      _   _
  |   | > discover  capture|    |       _   _| | ___| |_| |
  |   | > logs      status |    |      | | | | |/ __| __| |
  |   '--------------------'    |      | |_| | | (__| |_| |
  |    (o)(o)(o)(o)   [ ^ ]     |       \__, |_|\___|\__|_|
  |    [1][2][3]    <( OK )>    |       |___/
  |    [4][5][6]      [ v ]     |
  |    [7][8][9]                |      drive Yealink phones from a terminal
  |    [*][0][#]   (( ))(( ))   |      by Jay Peters @ Netquor Technologies  -  www.netquor.com
   \____________________________/
```

[![tests](https://github.com/Netquor/ylctl/actions/workflows/ci.yml/badge.svg)](https://github.com/Netquor/ylctl/actions/workflows/ci.yml)
[![latest release](https://img.shields.io/github/v/release/Netquor/ylctl?sort=semver)](https://github.com/Netquor/ylctl/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/Netquor/ylctl)](go.mod)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-blue)](https://github.com/Netquor/ylctl/releases/latest)
[![license](https://img.shields.io/github/license/Netquor/ylctl)](LICENSE)

A command-line tool for admins to diagnose and bring up Yealink desk phones from a laptop **inside the same network**.
It finds phones, reads their state, points them at a provisioning server and triggers a fetch. It is not affiliated with Yealink.

> Status: **0.x, first Go build**. Verified on two lab T41S phones (firmware 66.85.0.79 and 66.86.0.15), see [docs/live-test.md](docs/live-test.md).
> Everything is reverse-engineered from the phones' own web interface, so it can change between firmware versions. Test on a spare phone first.

## Install

```sh
go install github.com/Netquor/ylctl/cmd/ylctl@latest      # needs Go 1.22 or newer
```

or download an archive for macOS, Linux or Windows (amd64 and arm64) from the [Releases page](https://github.com/Netquor/ylctl/releases/latest) and check it against `checksums.txt`:

```sh
gh release download --repo Netquor/ylctl --pattern 'ylctl_*_darwin_arm64.tar.gz'   # or any file from the release
shasum -a 256 -c checksums.txt --ignore-missing                                    # Windows: Get-FileHash
```

Build from a clone: `make build` writes `dist/ylctl`.

## Cutting a release

`scripts/release.sh vX.Y.Z` runs the checks, builds macOS, Windows and Linux packages (amd64 and arm64) with the version stamped in, writes `checksums.txt`, tags the commit and publishes the GitHub release with `gh`. It needs a clean `main` and an authenticated `gh`. Add `--draft` to review the release before anyone can see it.

## Usage

```sh
ylctl discover                          # probe your local subnet (asks first); or: ylctl discover 192.168.1.0/24
ylctl info 192.168.1.50                 # model, firmware, hardware, MAC, IP, uptime
ylctl status 192.168.1.50               # registration state per account, network
ylctl autop show 192.168.1.50           # provisioning settings, secrets masked
ylctl account show 192.168.1.50         # SIP account 1: server, port, transport (password masked)
ylctl provision-now 192.168.1.50        # "Auto Provision Now"
ylctl firmware status 192.168.1.50      # running firmware version and model
ylctl firmware upgrade 192.168.1.50 ~/Downloads/T4XS-66.86.0.180.rom --dry-run   # check the plan, send nothing
ylctl reboot 192.168.1.50               # restart the phone (asks first)
ylctl adopt 192.168.1.50 --url https://pbx.example.net/webhooks/provision/TOKEN/ --disable-dhcp --disable-pnp --dry-run
ylctl autop set 192.168.1.50 RepeatMinutes=61 --dry-run
ylctl --json status 192.168.1.50        # JSON for scripts
ylctl completion zsh                    # shell completions (bash, zsh, fish, powershell)
```

Full reference: [docs/commands.md](docs/commands.md).

### Passwords

The phone's web password is **never** a flag or argument. In this order:

1. `YLCTL_PASSWORD` (and `YLCTL_USER`, or `--user`; default user `admin`). Environment variables are visible to your own processes, so prefer the keychain for daily use.
2. The OS keychain, when the helper exists: macOS `security`, Linux `secret-tool`. Nothing is stored unless you run `ylctl auth save <host>` yourself.
3. A prompt without echo, when stdin is a terminal.

The factory login `admin` / `admin` is tried **only** with `--try-default`, once, and a success prints
`warning: default password in use ... Change it.` Wrong passwords are never retried: a phone can lock its web login after a few failures
(the tool stops at the first `lock` and exits 5).

### Certificates

Phones use a self-signed certificate. ylctl uses trust on first use: the SHA-256 fingerprint is stored in
`~/.config/ylctl/known_phones.json` (mode 0600, override with `YLCTL_CONFIG_DIR`). On a terminal you are asked to confirm a new fingerprint;
in scripts pass `--trust-new`. **A changed fingerprint is always a hard error.** `--insecure` skips checks entirely and is an explicit escape hatch.

## Safety rails

* `discover` probes only private ranges (RFC 1918, loopback, link-local) unless `--allow-public`, refuses ranges larger than /22 unless `--force`,
  asks for consent unless `--yes`, runs at most 32 workers and 100 probes per second by default, and **never logs in**: it only fetches the public login form.
* Writes (`adopt`, `autop set`) read the current value first, show a before/after diff, support `--dry-run`, refuse when nothing would change unless `--force` (exit 6),
  write only the named non-secret `AutoProvision*` fields, and re-read the page to verify.
* Secrets never appear in output, logs or errors. Values of fields matching `pass|pwd|aes|secret|key|token` print as `********`. The provisioning URL contains a token and prints truncated unless `--reveal`.
* No factory reset or config import exists in this version. `ylctl firmware upgrade` reflashes the phone: it checks the file header and the version, shows the plan, and asks first (`--dry-run` sends nothing).
* No telemetry, no self-update. The only network traffic goes to the hosts you name or scan.

## What it does to the phone

| command | effect on the phone |
|---|---|
| `discover` | read-only: TCP connect and one GET of the public login page per address |
| `info`, `status`, `autop show`, `account show` | read-only (logs in; the phone records a web session) |
| `provision-now` | the phone fetches its provisioning files now and applies what the server sends, which may change its configuration |
| `password set` / `password recover` | **changes the web admin password**, keeping the vault or keychain in step; typed confirmation, see [docs/password.md](docs/password.md) |
| `adopt` | **changes settings**: server URL, optionally DHCP-option and PnP switches, then the same fetch as `provision-now` |
| `autop set` | **changes settings**: the named Auto Provision fields only |
| `auth save` / `auth forget` | changes your keychain only |

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | error (including untrusted or changed TLS certificate, rejected write) |
| 2 | usage error (bad arguments, unsafe range, missing consent or password) |
| 3 | unreachable (connection refused, timeout) |
| 4 | authentication failed |
| 5 | web login is locked |
| 6 | changed nothing (`adopt`, `autop set`: the phone already had the values) |
| 7 | partial: settings were written but triggering provisioning failed |

## How it works

See [docs/protocol.md](docs/protocol.md): hybrid RSA+AES login, the status-first quirk, page loads, the CSRF token, the settings write, account state codes and the discovery fingerprint.
`prototype/` keeps the original Python proof of concept.

## Development

```sh
make test     # go test -race ./...
make lint     # go vet, gofmt check, golangci-lint if installed
```

Tests run against `internal/fakephone`, an `httptest` server that really decrypts the login and serves sanitized pages captured from real phones. See [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
