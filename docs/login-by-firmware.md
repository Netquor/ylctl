# Web login by firmware (T41S)

Status key: **VERIFIED** = seen on a real phone; **FROM SOURCE** = read in the phone's own JavaScript or HTML, not yet exercised; **OPEN** = unknown.

## Legacy flow: 66.85.0.79 and 66.86.0.15

Verified live (see [live-test.md](live-test.md)). The Go client in `internal/yealink/client.go` implements this.

1. `GET /servlet?m=mod_listener&p=login&q=loginForm` answers with the login form, `g_rsa_n` and `g_rsa_e`, and sets `JSESSIONID`. **VERIFIED**
2. `POST /servlet?m=mod_listener&p=login&q=login` with the username and the RSA-encrypted password. The answer is JSON with `authstatus`: `done`, `error`, `lock`, or `none`. **VERIFIED**
3. Every later request carries the cookie. The page script reads `JSESSIONID` from `document.cookie` before each request. **VERIFIED** (66.86.0.15 `commonjs.js`)

## 66.86.0.180

Checked with GET requests only (no login attempts after the upgrade).

| Check | Result | Status |
|---|---|---|
| Login form loads (`loginForm`) | 200 OK, RSA key present | VERIFIED |
| `loginForm` sets `JSESSIONID` | **No** `Set-Cookie`, for any URL tested, curl or browser User-Agent | VERIFIED |
| `page_login.js` login | Loads `loginForm` into a hidden iframe (`_iframe_login_update`), then `postlogin` to `q=login` with `username` and `pwd` | FROM SOURCE |
| `commonjs.js` | Rewritten (139 KB to 261 KB). No `JSESSIONID` and no `document.cookie` anywhere. The `postlogin` helper no longer checks the session. | FROM SOURCE |
| Session after login | **OPEN.** Most likely set by the `q=login` answer (`Set-Cookie`), not by the form. | OPEN |

What happened on this phone: after the upgrade, `ylctl --try-default status` failed with `no session cookie`. Two login attempts with the default password were made, so we don't know whether the default still works. Stop logging in until that is known.

## Browser capture, 66.86.0.180 (Chrome, `~/Downloads/download`)

A DevTools HAR of a successful browser login on 66.86.0.180. Checked for flow and field names only; no secrets are copied here.

- The page loaded `loginForm` twice: once normally, and once with `Random=` (the hidden iframe from `page_login.js`). **VERIFIED**
- `POST servlet?m=mod_listener&p=login&q=login` with exactly two fields, `username` and `pwd`. `username` was `admin`. `pwd` is the RSA-encrypted password. Answer: `{"authstatus":"done"}`. **VERIFIED**: the browser login succeeded.
- The next `GET servlet?m=mod_data&p=status&q=load` returned 200 with real content.
- **No cookies appear anywhere in the capture**: no `Cookie` on any request, no `Set-Cookie` on any response. Chrome normally records them, so either the export hid them or the phone keeps the session without a cookie. Not settled. A HAR re-exported with cookies on (or Copy as cURL on the `q=login` request, values redacted) would settle it.
- The browser login was accepted, but the capture doesn't show which password was typed. Check whether it was `admin/admin` before drawing a conclusion about the default password.

## Session on 66.86.0.180 (confirmed with a supplied browser cookie)

- The browser login used `admin` with the default password (`admin/admin`). **The default password still works on <phone-ip>**. It must be changed.
- The session cookie is named `JSESSIONID`, the same name as on the old firmware. A GET to `servlet?m=mod_data&p=status&q=load` with that cookie returns the status page (HTTP 200, not the login page). Verified with one read-only request.
- With the wrong cookie name (`JSESSID`) the phone redirects to login, so the name matters.
- **Still open:** which response sets `JSESSIONID`. The capture has no cookies, so it doesn't say. The likeliest answer is the `q=login` response, since the form response sets none. Verify on the next login by reading the `Set-Cookie` headers of the `q=login` answer.
- The cookie was shared in chat, so treat it as exposed. Log out in the browser (or let it expire) to invalidate it.

## Detection (implemented; the signal is the cookie, not the version)

`Login` in `internal/yealink/client.go` decides from the login form alone:

- The form set `JSESSIONID`: legacy flow (password inside the encrypted blob with the session id, plus `rsakey` and `rsaiv`).
- The form set no `JSESSIONID`: post-login flow (only the RSA-encrypted password; the server sets `JSESSIONID` on the login answer).

No firmware version is hardcoded. A future firmware with either behaviour is handled without a code change.

**Verified live:** `ylctl --try-default status <phone-ip>` on 66.86.0.180 used the post-login flow. The default password worked (ylctl warned about it), and the status page showed account <ext> as registered.

## Detection plan (no passwords until the flow is known)

Probe with GET requests only:

1. `GET loginForm`. Record `Set-Cookie` names, `g_strFirmware`, `g_phonetype`, and whether the RSA key is present.
2. Fetch `js/common/commonjs.js`. Search for `JSESSIONID` in the `document.cookie` read. Present means legacy; absent means the newer flow.
3. Fetch `js/pages/page_login.js`. Search for `_iframe_login_update` and `postlogin`. Present means the iframe flow.
4. Pick the flow: legacy if the form sets `JSESSIONID`, iframe/cookie-on-login if not. If the signals disagree, or nothing matches, stop and report instead of guessing.
5. Only then send one login POST with the configured credentials. A wrong password is never retried.

## Open questions

- Does the `q=login` answer on 66.86.0.180 set `JSESSIONID`? One attempt with the correct password would show it.
- Is the default password still `admin/admin` after the update? Check in a browser.
- Does the phone lock after repeated failures, and for how long? The `lock` value in `authstatus` suggests it does.
