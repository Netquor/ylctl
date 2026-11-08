# Yealink T4x web interface: what we learned (T41S, firmware 66.83 to 66.86)

Reverse-engineered by reading the phone's own JavaScript (`/js/common/commonjs.js`, `/js/pages/page_login.js`, `/js/pages/page_status.js`, `/js/model/mod_account.js`) and by talking to two lab phones.
Nothing here needs a Yealink account. Verified live on firmware 66.85.0.79 and 66.86.0.15 unless marked otherwise.

## Transport

HTTPS on 443 with a self-signed certificate (HTTP on 80 may redirect or be off). **TLS surprise:** firmware 66.85 negotiates TLS 1.2 with only `DHE-RSA-*` and plain `RSA` key exchange suites
(no ECDHE). Go has no DHE and no longer offers RSA key exchange by default, so a default Go client fails with `tls: handshake failure`. ylctl offers `TLS_RSA_WITH_AES_{128,256}_GCM/CBC`
explicitly. Firmware 66.86 negotiates TLS 1.3. Authenticity comes from the pinned certificate fingerprint, not from the suite.

## Login

1. `GET /servlet?m=mod_listener&p=login&q=loginForm` returns the login form. It sets a `JSESSIONID` cookie and defines `var g_rsa_n = "<hex>"; var g_rsa_e = "<hex>";` (1024 bit key), `g_phonetype`, `g_strFirmware`, and loads assets as `...?66.86.0.15`.
2. The browser builds a hybrid encryption:
   * `key` = 32 hex chars (the page uses `MD5(Math.random())`; any 16 random bytes work), used as 16 raw bytes for AES-128; `iv` likewise;
   * `rsakey` = RSA(PKCS#1 v1.5, phone public key) of the 32-char key **string**, as hex; `rsaiv` the same for the IV. **The hex must be full width (2 x modulus bytes).** A hex string with a stripped leading zero is rejected: the Python prototype did this and failed about one login in eight with `{"authstatus":"error","errorno":"-3"}` (fixed in the prototype);
   * `pwd` = base64(AES-128-CBC, zero padding) of `"<random>;<JSESSIONID>;<password>"`.
3. `POST /servlet?m=mod_listener&p=login&q=login`, body `username=...&pwd=...&rsakey=...&rsaiv=...` (URL-encoded). The answer HTML holds `<div id="_RES_INFO_" ...>{"authstatus":"done"}</div>`. Other values: `error` (with `errorno` such as `-3` for a wrong password), `none`, `lock` (too many failures: stop). The `lock` value and an HTTP 403 on login are handled as "locked" but **were never provoked on a real phone**.
4. **Quirk:** load `/servlet?m=mod_data&p=status&q=load` first, as the UI does; other pages can answer with the login page until the session has landed there once. ylctl does this inside `Login` and reuses the page for `status`.

A page that returns the login form mid-session (`page_login.js` or `id="idUsername"` in the body, or `_RES_INFO_` with `authstatus` other than `done`) means the session was lost. ylctl logs in once more and repeats the request once per run, then gives up with exit 1.

## Reading

`GET /servlet?m=mod_data&p=<page>&q=load&Rajax=<random>` returns a full HTML page (25 to 37 KB). Pages used: `status`, `settings-autop`, `account-register` (`&acc=<n-1>` selects the account).
Current values are in the element attributes, not in rendered text:

* labels: `<label id="PhoneFirmware" dvalue="66.85.0.79">` (`hardware-version`, `tdMACAddress`, `tdWANIP`, `tdSubnetMask`, `tdGateway`, `tdPrimaryDNS`, `tdSecondaryDNS`, `vlanid`, `NetworkWanType` 0 DHCP 1 PPPoE 2 static, `tdPowerOnTime` seconds, `tdWANProtStatus` link bit mask);
* inputs and selects: `name=... dvalue=...` is the current value (`value` for text inputs repeats it). Radio groups have no `value`; `dvalue` is the current state. Select options are built by JavaScript, so only `dvalue` is in the HTML (`Transport1`: 0 UDP, 1 TCP, 2 TLS, 3 DNS NAPTR; `AccountEnable` 0/1);
* secrets: `AutoProvisionPassword`, `AutoProvisionAESKey16`, `AutoProvisionAESKey16MAC`, `AccountPassword` show `********`;
* the model is `var g_phonetype = "T41S";`; the CSRF token is `var g_strToken = "...";`;
* `var g_dataAccStatus = g_json.ParseJSON("{\"Account1\":\"1004@host:2\",\"Account2\":\"0\",...}");`.

Tag attributes may contain `>` (a URL placeholder in a fixture did), so parsers must tokenise quoted attributes.

### Account status codes

From `TransAccountStatus` in `mod_account.js` (the value is `<user>@<host>:<code>`, or a bare `0` for an unused account):

| code | phone text | ylctl state | seen on a real phone |
|---|---|---|---|
| 0 | Disabled | disabled | yes |
| 1 | Registering | registering | no |
| 2 | Registered | registered | yes |
| 3 | Register Failed | failed | no |
| 6 | Inexistence | inexistent | no |
| -1, 4, 7, 8, 9, 10 | shown as code 1 | registering | no |
| 5, 11 | shown as code 2 | registered | no |
| other | Unknown | unknown | no |

Only 0 and 2 were observed live; the others come from the phone's JavaScript and are reported with `observed_live: false` in JSON.

## Writing settings

The Confirm button calls `doSubmit('settings-autop')`:

```
POST /servlet?m=mod_data&p=settings-autop&q=write&Rajax=<random>
Content-Type: application/x-www-form-urlencoded

AutoProvisionServerURL=<urlencoded>&AutoProvisionRepeatMinutes=61&token=<g_strToken>
```

* The UI serialises only **fields whose value differs from `dvalue`** (plus fields marked `effect="forcesub"`), as `name=value`; ylctl sends only the fields you name, even when the value is unchanged (`--force`).
* Password-type inputs are sent as `name=base64(AES(random;session;value))` plus `rsakey=...&rsaiv=...` (same scheme as the login). ylctl does not write secret fields.
* `token` must be the session's `g_strToken`. A missing or wrong token gives **HTTP 403** with an empty body.
* Fields with `effect="reboot"` make the UI offer a reboot; the Auto Provision fields have no effect attribute and apply at once. Network pages on 66.86 use a "cache config" step (`applycacheconfig` / `resetcacheconfig`, see below); Auto Provision and Account pages do not.
* Success answer: `<html><body><div id="_RES_INFO_"></div></body></html>` (empty). The answer carries no detail, so ylctl **verifies by reloading the page** and comparing every written field.

### Provision now

```
POST /servlet?m=mod_data&p=settings-autop&q=autopnow&Rajax=<random>      body: token=<g_strToken>
-> {"ret":"ok","data":"6"}
```

The phone fetches its provisioning URL immediately (two fetches were seen on the provisioning server within seconds on phone B).

### Other endpoints seen, not used

`q=resetconfig` (per-item reset), `m=mod_webd&p=talking` (is a call active; the UI checks it before writes that need an idle phone), upload types `ringtone`, `wallpaper`, `screensaver`, and on 66.86 `servlet?m=mod_data&q=applycacheconfig` / `resetcacheconfig`.

## Firmware differences, 66.85.0.79 vs 66.86.0.15 (T41S)

| | 66.85.0.79 | 66.86.0.15 |
|---|---|---|
| TLS | 1.2, DHE-RSA and RSA key exchange only | 1.3 |
| login form and JS | same `page_login.js` (byte-identical) | same |
| field names on `settings-autop` and `account-register` | identical set | identical set |
| network pages | direct write | "Applies the changed network settings immediately" banner with Apply/Discard (`isPageSupportCacheConfig`: network pages only) |
| status/autop/account pages | | extra hidden `CacheConfigWarn` block, no field changes |

## Discovery fingerprint

No login is needed: the login form is public. A host is a Yealink phone when `GET /servlet?m=mod_listener&p=login&q=loginForm` returns a page that loads `page_login.js` (or says Yealink) and either defines `g_phonetype` / `g_strFirmware`, or has `<title>Yealink T41S Phone</title>` and asset URLs like `/theme/css/style.css?66.86.0.15`.
Model and firmware are read from there. The MAC address is **not** on the login page (it needs a login, or the ARP table: Yealink OUIs include `80:5e:c0`).

## Other things seen

* The phone can capture its own pcap and export logs (`Settings > Configuration`).
* `Rajax=<random>` is a cache buster the UI appends to every request.
