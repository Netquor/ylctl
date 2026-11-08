# ylctl recon

Find the phones on your network, see which are working and managed, and bring the rest in.

```sh
ylctl recon                          # guesses your subnet; Enter accepts, or type a range
ylctl recon <lab-net-3>/24 <lab-net-1>.0/24
ylctl recon --super ...              # many parallel probes: fast, can miss a slow phone on a routed subnet
ylctl recon --no-prompt --json       # report only, for scripts
ylctl recon --auto-register-discovered   # register every unmanaged phone that accepts our login
```

## The flow

1. **Subnets.** The tool guesses the subnets of your interfaces. At the prompt: Enter keeps the guess; a full range (`192.168.5.0/24`) replaces it; a bare `/23` only changes the mask of the guess; several can be typed together. Private ranges only; larger than /22 needs `--force`.
2. **Scan.** Only a GET of each login page is sent. Hosts that answered at the network level (ARP) but were not recognised get a second, patient look.
3. **Check each phone.** One login attempt per password, never repeated (phones lock after a few failures). Passwords tried, in order: the server's vault (if linked and the MAC is known), the keychain or `$YLCTL_PASSWORD`, and the factory `admin/admin` only if you allow it (`--try-default` or the question).
4. **The table.** Per phone: address, MAC, model and firmware, what the linked server knows, and a state:
   - `managed`: provisioning points at your server and the server knows the MAC
   - `registered to your PBX, not provisioned by it` / `registered elsewhere`
   - `not registered`
   - `password not accepted` / `login locked`
5. **Bring in.** Unmanaged phones that accepted our login are listed. `a` selects all, space and the arrow keys select some, Enter confirms. Each chosen phone gets the server's **enrollment link** as its Auto Provision URL (and DHCP/PnP provisioning switched off unless `--keep-dhcp-provisioning`), then "Auto Provision Now". SIP accounts and passwords are never touched. The tool then watches the server's device list for up to 90 seconds. Finish in the web UI (`/provisioning`): extension, groups, policies, person.
   - The enrollment link is found from `--enroll-url`, `$YLCTL_ENROLL_URL`, the keychain, or made on request. Making a new one **stops the old link working**, so the tool asks first.
6. **Phones that would not let us in.** For each one, choose:
   - `t` zero-touch (only if you state what DHCP hands phones on this network: `--dhcp-url` = the server's enrollment URL in option 66, `--tftp` = the PBX's TFTP server, `--no-tftp` = neither; remembered. With the enrollment URL a new or factory-reset phone enrolls itself and appears as unclaimed on the server, so a reset is often all it takes): power-cycle the phone, and the tool checks the server's device list for the MAC for 10 minutes. If it never appears, the factory reset plan is offered.
   - `r` factory reset steps for the vendor (REPORTED from maker guides), then "wait for you?"
   - `w` wait for me: I am resetting it now. The tool carries on with the other phones and watches this one. When it has restarted, it tries the factory login a few times, spaced out, and if that works it registers the phone as above.
   - `s` skip.

## What recon does not do

- It does not change a phone unless you selected it (or passed `--auto-register-discovered`).
- It does not try passwords in a loop. A locked phone is reported as locked.
- The zero-touch statement is only remembered state; the tool does not change DHCP or start a TFTP server. Option 66 holding the server's `https://` enrollment URL is VERIFIED in the lab (2026-11-07: a T41S on firmware 66.85, moved to the VoIP VLAN and power-cycled, enrolled itself and appeared on the server); the `tftp://` form is VERIFIED too.
- Only Yealink phones are recognised. Reset guides for other makers are included for when more vendors are added.

## Status

VERIFIED on the lab network (read-only runs): subnet prompt with two ranges, scan, state table, the picker (arrows, space, a, n, q). NOT yet exercised on real phones: the registration step, the enrollment link creation, the zero-touch check-back and the wait-for-reset loop. Test those on a spare phone first.
