# Security

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a vulnerability" (Security advisories) on the Netquor/ylctl repository, not in a public issue.
Include the version (`ylctl version`), what you did and what happened. We aim to reply within a week and to coordinate disclosure with you.

**Never include phone passwords, provisioning tokens or full provisioning URLs in a report or an issue.** Mask them (`<token>`).

## What ylctl protects, and what it does not

* Passwords are read from the environment, the OS keychain or a prompt, never from a flag. They are sent only to the phone you name, encrypted with the phone's own RSA/AES scheme inside a TLS session. They are not logged and not printed; secret-looking fields are masked in all output.
* TLS uses trust on first use with a pinned SHA-256 fingerprint in `known_phones.json` (mode 0600). A changed fingerprint is a hard error. `--insecure` disables checking and is only an escape hatch.
* The phone's web interface itself is old and uses a weak scheme (1024-bit RSA, `JSESSIONID`, DHE/RSA suites). Do not expose it to untrusted networks. Change the factory `admin` / `admin` password; `ylctl --try-default` warns when it still works.
* A provisioning URL contains a token that grants access to a phone's configuration. `ylctl adopt --url` takes it as an argument, which other users of the same machine can see in the process list; use it on a machine you trust. Output truncates the token unless `--reveal`.
* `discover` sends only TCP connects and one GET of the public login page, only into private ranges unless you pass `--allow-public`. Scan networks you are allowed to scan.

## Supported versions

0.x: only the latest release is supported.
