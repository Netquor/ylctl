# ylctl

A command-line tool for admins to diagnose and bring up Yealink desk phones from a laptop **inside the same network**.

> Status: **early prototype** (a Python proof of concept of the phone's web protocol is in `prototype/`; the Go CLI is planned).
> Tested so far on T41S firmware 66.83 to 66.86. Everything here is reverse-engineered from the phones' own web UI, so it can change between firmware versions.

## Planned commands

| command | what it does | safe? |
|---|---|---|
| `ylctl discover` | find Yealink phones on the LAN (OUI 80:5e:c0 and others), with consent and rate limits | read-only |
| `ylctl info <host>` | model, firmware, hardware, MAC, IP, uptime | read-only |
| `ylctl status <host>` | account registration state, network | read-only |
| `ylctl autop show <host>` | provisioning settings (secrets masked) | read-only |
| `ylctl provision-now <host>` | trigger "Autoprovision Now" | safe |
| `ylctl adopt <host> --url ...` | set the provisioning server URL and trigger it | changes settings |
| `ylctl reboot`, `ylctl reset`, `ylctl config export/import`, `ylctl screenshot` | later stages; destructive ones need `--yes` | varies |

Credentials come from the environment or the OS keychain, never from the command line.

## How the web login works

See [docs/protocol.md](docs/protocol.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
