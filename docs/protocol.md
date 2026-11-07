# Yealink T4x web interface: what we learned (T41S, firmware 66.83 to 66.86)

Reverse-engineered by reading the phone's own JavaScript (`/js/common/commonjs.js`, `/js/pages/page_login.js`). Nothing here needs a Yealink account.

## Login

1. `GET /servlet?m=mod_listener&p=login&q=loginForm` returns an HTML page that contains the phone's RSA public key (`rsa_n`, `rsa_e` as hex) and sets a `JSESSIONID` cookie.
2. The browser builds a hybrid encryption:
   * `key` = MD5 hex of a random number (32 hex chars, used as 16 raw bytes for AES-128), `iv` likewise;
   * `rsakey` = RSA(PKCS#1 v1.5, phone public key) of the 32-char key string, as hex; `rsaiv` the same for the IV;
   * `pwd` = base64(AES-128-CBC, zero padding) of `"<random>;<JSESSIONID>;<password>"`.
3. `POST /servlet?m=mod_listener&p=login&q=login` with form fields `username`, `pwd`, `rsakey`, `rsaiv` (each URL-encoded). The response HTML holds `<div id="_RES_INFO_">{"authstatus":"done"}</div>`. Other values: `none`, `error`, `lock` (too many failures: be careful).
4. **Quirk:** load `/servlet?m=mod_data&p=status&q=load` first, as the UI does; other pages can answer with the login page until the session has landed there once.

## Reading

`GET /servlet?m=mod_data&p=<page>&q=load&Rajax=<random>` returns a full HTML page with current values: pages seen include `status`, `settings-autop`, `account-register`. Values are in element ids (`PhoneFirmware`, `tdMACAddress`, `tdWANIP`, ...), input names (`AutoProvisionServerURL`, `server1`, `port1`) and inline JSON (`g_dataAccStatus`: `{"Account1":"<user>@<host>:<code>"}`; code 2 = registered).

## Writing

POST requests must carry the page's CSRF token (`g_strToken`, defined in the page) as `token=...`. Example that works: `POST /servlet?m=mod_data&p=settings-autop&q=autopnow&Rajax=<random>` with body `token=<token>` returns `{"ret":"ok","data":"6"}` and the phone fetches its provisioning files immediately.

## Other things seen

* Resource types for uploads exist in the UI code (`ringtone`, `wallpaper`, `screensaver`): a path to custom ringtones.
* The phone can capture its own pcap and export logs (`Settings > Configuration`).
