# Live verification on the lab phones

Date: 2026-11-07. Tool: the `ylctl` built from this branch. Run from a laptop on <lab-net-2>.0/24.

**Consent:** the owner of both phones explicitly allowed them as test subjects ("they are not important and are older and for testing anyway"), including the scans of <lab-net-3>/24 and <lab-net-1>.0/24 and writes to phone B.
Both have the factory web login admin / admin, which is public knowledge and used here with `--try-default` or `YLCTL_PASSWORD=admin`.

| | phone A | phone B |
|---|---|---|
| address | <phone-A-ip> | <phone-B-ip> |
| model, firmware | T41S, 66.86.0.15 | T41S, 66.85.0.79 |
| MAC | 80:5E:C0:00:00:0A | 80:5E:C0:00:00:0B |
| account | 1002, registered (TLS, port 5061) | 1004, registered (TLS, port 5061) |
| Auto Provision at start | PnP on, DHCP option on, server URL empty | PnP off, DHCP option off, server URL set (token), power on, repeat every 60 min |

Rules followed: reads first; writes only on phone B; no reboot, factory reset, firmware change, password change or config import; account credentials, SIP server and transport never touched; every changed value was read first and restored.

## Exploration before the CLI existed

1. Read the phone JavaScript through an authenticated session (`commonjs.js`: `doSubmit`, `YLForm.submit`, `getKeyAndValue`, `Ajax.post`) to learn the write: POST `q=write` with only the changed fields plus `token`.
2. First login attempt on phone A with the Python prototype answered `{"authstatus":"error","errorno":"-3"}`, which looks like a wrong password. It was not: the prototype emitted RSA hex without its leading zero (one in eight logins). One later attempt with the Go tool succeeded on phone A with admin/admin. That was the only retry on A; there was one failed attempt on phone B (same cause) with no lockout. Lesson recorded in protocol.md; prototype fixed.
3. Write response on phone B: setting `AutoProvisionServerURL` to its current value returned `<div id="_RES_INFO_"></div>` (empty) and the value was unchanged. A wrong or missing token returned **HTTP 403** (also for `autopnow`).
4. Go's TLS client could not connect at all (`tls: handshake failure`): phone B offers only DHE-RSA and RSA key exchange suites. Fixed by offering the RSA suites explicitly.

## What the final run showed

Checked against the phone's own pages (read through the web session before the CLI work): phone B shows PNP off, DHCP option off, repeat 60, label 1004, display name "Test Phone 2", server <your-netquor-pbx> port 5061, Transport select 2 (TLS); phone A shows PNP on, DHCP option on, empty URL, label 1002, same server, port 5061, TLS. The CLI output below matches.

* `discover` on both /24 ranges found exactly one phone each, nobody else.
* `info`, `status`, `autop show`, `account show` worked on both. Status code 2 = registered on both, accounts 2 to 6 disabled (code 0).
* `provision-now` returned ok on both; afterwards both stayed registered and uptime kept counting (no reboot). **The PBX is not visible from here**, so whether the fetch reached it is unverified from this side; the first exploration (earlier session) saw two fetches on the server after a manual `autopnow` on phone B.
* `adopt --dry-run` on both: diff shown, nothing sent. Against phone A the diff showed URL empty -> set, DHCP option 1 -> 0, PnP 1 -> 0.
* `adopt` without `--force` on phone B with its current URL exited 6 (nothing to change).
* One real `adopt --force` on phone B with its current URL: write ok and verified, provisioning requested, DHCP/PnP untouched, URL byte-identical afterwards.
* `autop set RepeatMinutes=61` then `=60` on phone B: written, verified by re-read, restored; final value 60.
* Nothing was left changed. Phone A was never written to.

Surprises: TLS cipher suites (above), the prototype's RSA padding bug, HTTP 403 for a bad token, empty write answer, uptime in seconds, the 66.86 network "cache config" banner (not relevant for Auto Provision pages), and that the model is only on the login page / status as `g_phonetype` (there is no label for it).

## Raw log (sanitized)

Provisioning tokens replaced by `<token>` or `xxxx...`. Commands run with `YLCTL_CONFIG_DIR=/tmp/ylctl-lab-cfg2` (a fresh pin store), `YLCTL_PASSWORD=admin` except where `--try-default` is shown.

```
### discover
$ ylctl discover --yes <lab-net-3>/24
scanning 254 addresses in <lab-net-3>/24 (32 workers, 100 probes/s)...
ADDRESS        MODEL  FIRMWARE    PORT       CERT SHA-256
<phone-A-ip>  T41S   66.86.0.15  443/https  <cert-sha256>
[exit 0]

$ ylctl discover --yes <lab-net-1>.0/24
scanning 254 addresses in <lab-net-1>.0/24 (32 workers, 100 probes/s)...
ADDRESS        MODEL  FIRMWARE    PORT       CERT SHA-256
<phone-B-ip>  T41S   66.85.0.79  443/https  <cert-sha256>
[exit 0]

### first contact, no flag: TOFU refuses
$ ylctl info <phone-B-ip>
ylctl: Get "https://<phone-B-ip>:443/servlet?m=mod_listener&p=login&q=loginForm": TLS certificate of <phone-B-ip>:443 is not trusted yet (sha256 <cert-sha256>); verify it, then re-run with --trust-new
[exit 1]

### default password, one attempt, warning
$ ylctl --trust-new --try-default info <phone-B-ip>
warning: default password in use on <phone-B-ip>: the factory login admin/admin worked. Change it.
Model     T41S
Firmware  66.85.0.79
Hardware  68.0.0.0.0.0.0
MAC       80:5E:C0:00:00:0B
IP        <phone-B-ip>
Uptime    0 days 01:25
[exit 0]

$ ylctl --trust-new --try-default info <phone-A-ip>
warning: default password in use on <phone-A-ip>: the factory login admin/admin worked. Change it.
Model     T41S
Firmware  66.86.0.15
Hardware  68.0.0.0.0.0.0
MAC       80:5E:C0:00:00:0A
IP        <phone-A-ip>
Uptime    0 days 01:16
[exit 0]

### phone <phone-B-ip>
$ ylctl info <phone-B-ip>
Model     T41S
Firmware  66.85.0.79
Hardware  68.0.0.0.0.0.0
MAC       80:5E:C0:00:00:0B
IP        <phone-B-ip>
Uptime    0 days 01:25
[exit 0]

$ ylctl status <phone-B-ip>
Network  DHCP, <phone-B-ip>/255.255.255.0, gateway <lab-gateway>, DNS 1.1.1.1, 1.0.0.1
VLAN     0
Link     100Mbps Full Duplex
Uptime   0 days 01:25

ACCOUNT                           REGISTRATION  CODE
1  1004@<your-netquor-pbx>  registered    2
2  -                              disabled      0
3  -                              disabled      0
4  -                              disabled      0
5  -                              disabled      0
6  -                              disabled      0
[exit 0]

$ ylctl autop show <phone-B-ip>
FIELD                  VALUE
EnablePNP              0
EnableDHCPOption       0
OptionType             
OptionTypeIPv6         
ServerURL              https://<your-netquor-pbx>/webhooks/provision/xxxx.../
User                   
Password               ********
AESKey16               ********
AESKey16MAC            ********
PowerOn                1
Repeat                 1
RepeatMinutes          60
EnableWeekly           0
WeeklyUpgradeInterval  0
InactivityTimeExpire   0
WeeklyBeginTime        00:00
WeeklyEndTime          00:00
WeeklyMask             0123456
FlexibleSwitch         0
FlexibleInterval       30
FlexibleBeginTime      02:00
FlexibleEndTime        
[exit 0]

$ ylctl account show <phone-B-ip>
Account         1 (enabled)
Label           1004
Display name    Test Phone 2
Register name   1004
User name       1004
Password        ********
SIP server 1    <your-netquor-pbx>:5061 TLS
Outbound proxy  off :5060
[exit 0]

$ ylctl provision-now <phone-B-ip>
provisioning requested: the phone is fetching its configuration now
[exit 0]

### phone <phone-A-ip>
$ ylctl info <phone-A-ip>
Model     T41S
Firmware  66.86.0.15
Hardware  68.0.0.0.0.0.0
MAC       80:5E:C0:00:00:0A
IP        <phone-A-ip>
Uptime    0 days 01:16
[exit 0]

$ ylctl status <phone-A-ip>
Network  DHCP, <phone-A-ip>/255.255.255.0, gateway <lab-gateway-A>, DNS 1.1.1.1, 1.0.0.1
VLAN     0
Link     100Mbps Full Duplex
Uptime   0 days 01:17

ACCOUNT                           REGISTRATION  CODE
1  1002@<your-netquor-pbx>  registered    2
2  -                              disabled      0
3  -                              disabled      0
4  -                              disabled      0
5  -                              disabled      0
6  -                              disabled      0
[exit 0]

$ ylctl autop show <phone-A-ip>
FIELD                  VALUE
EnablePNP              1
EnableDHCPOption       1
OptionType             
OptionTypeIPv6         
ServerURL              
User                   
Password               ********
AESKey16               ********
AESKey16MAC            ********
PowerOn                1
Repeat                 1
RepeatMinutes          60
EnableWeekly           0
WeeklyUpgradeInterval  0
InactivityTimeExpire   0
WeeklyBeginTime        00:00
WeeklyEndTime          00:00
WeeklyMask             0123456
FlexibleSwitch         0
FlexibleInterval       30
FlexibleBeginTime      02:00
FlexibleEndTime        
[exit 0]

$ ylctl account show <phone-A-ip>
Account         1 (enabled)
Label           1002
Display name    1002
Register name   1002
User name       1002
Password        ********
SIP server 1    <your-netquor-pbx>:5061 TLS
Outbound proxy  off :5060
[exit 0]

$ ylctl provision-now <phone-A-ip>
provisioning requested: the phone is fetching its configuration now
[exit 0]

### adopt dry runs
$ ylctl adopt <phone-B-ip> --url https://<your-netquor-pbx>/webhooks/provision/<token>/ --dry-run
ylctl: nothing to change: the phone already has these values (use --force to write anyway)
[exit 6]

$ ylctl adopt <phone-B-ip> --url https://<your-netquor-pbx>/webhooks/provision/<token>/ --force --dry-run
dry run, would change on <phone-B-ip>:
  AutoProvisionServerURL           https://<your-netquor-pbx>/webhooks/provision/xxxx.../ (unchanged, rewritten because of --force)
dry run: would POST q=write with fields AutoProvisionServerURL and the CSRF token, then POST q=autopnow. Nothing was sent.
[exit 0]

$ ylctl adopt <phone-A-ip> --url https://<your-netquor-pbx>/webhooks/provision/<token>/ --disable-dhcp --disable-pnp --dry-run
dry run, would change on <phone-A-ip>:
  AutoProvisionServerURL           (empty) -> https://<your-netquor-pbx>/webhooks/provision/xxxx.../
  AutoProvisionEnableDHCPOption    1 -> 0
  AutoProvisionEnablePNP           1 -> 0
dry run: would POST q=write with fields AutoProvisionEnableDHCPOption, AutoProvisionEnablePNP, AutoProvisionServerURL and the CSRF token, then POST q=autopnow. Nothing was sent.
[exit 0]

### adopt on B: same URL, unchanged without --force
$ ylctl adopt <phone-B-ip> --url https://<your-netquor-pbx>/webhooks/provision/<token>/
ylctl: nothing to change: the phone already has these values (use --force to write anyway)
[exit 6]

### adopt on B: --force rewrites the current URL, DHCP/PnP untouched
$ ylctl adopt <phone-B-ip> --url https://<your-netquor-pbx>/webhooks/provision/<token>/ --force
changes on <phone-B-ip>:
  AutoProvisionServerURL           https://<your-netquor-pbx>/webhooks/provision/xxxx.../ (unchanged, rewritten because of --force)
settings written and verified
provisioning requested: the phone is fetching its configuration now
[exit 0]

### RepeatMinutes 60 -> 61 -> 60 on B
$ ylctl autop set <phone-B-ip> RepeatMinutes=61 --dry-run
dry run, would change on <phone-B-ip>:
  AutoProvisionRepeatMinutes       60 -> 61
dry run: would POST q=write with fields AutoProvisionRepeatMinutes and the CSRF token. Nothing was sent.
[exit 0]

$ ylctl autop set <phone-B-ip> RepeatMinutes=61
changes on <phone-B-ip>:
  AutoProvisionRepeatMinutes       60 -> 61
settings written and verified
[exit 0]

$ ylctl autop show <phone-B-ip>
FIELD                  VALUE
EnablePNP              0
EnableDHCPOption       0
OptionType             
OptionTypeIPv6         
ServerURL              https://<your-netquor-pbx>/webhooks/provision/xxxx.../
User                   
Password               ********
AESKey16               ********
AESKey16MAC            ********
PowerOn                1
Repeat                 1
RepeatMinutes          61
EnableWeekly           0
WeeklyUpgradeInterval  0
InactivityTimeExpire   0
WeeklyBeginTime        00:00
WeeklyEndTime          00:00
WeeklyMask             0123456
FlexibleSwitch         0
FlexibleInterval       30
FlexibleBeginTime      02:00
FlexibleEndTime        
[exit 0]

$ ylctl autop set <phone-B-ip> RepeatMinutes=60
changes on <phone-B-ip>:
  AutoProvisionRepeatMinutes       61 -> 60
settings written and verified
[exit 0]

$ ylctl autop show <phone-B-ip>
FIELD                  VALUE
EnablePNP              0
EnableDHCPOption       0
OptionType             
OptionTypeIPv6         
ServerURL              https://<your-netquor-pbx>/webhooks/provision/xxxx.../
User                   
Password               ********
AESKey16               ********
AESKey16MAC            ********
PowerOn                1
Repeat                 1
RepeatMinutes          60
EnableWeekly           0
WeeklyUpgradeInterval  0
InactivityTimeExpire   0
WeeklyBeginTime        00:00
WeeklyEndTime          00:00
WeeklyMask             0123456
FlexibleSwitch         0
FlexibleInterval       30
FlexibleBeginTime      02:00
FlexibleEndTime        
[exit 0]

server URL byte-identical after all writes
```
