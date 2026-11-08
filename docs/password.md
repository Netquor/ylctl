# Changing the phone's web admin password

`ylctl password set <host>` changes the Security > Password page of a Yealink T4x phone and keeps the place that remembers the password in step, in an order that cannot lose it. This is rated **R4** in the UI map (the only recovery from a lost admin password is a factory reset from the phone's keypad), so it has the strongest guards in ylctl.

Status of this document: everything about the phone's side is **read from the phone's own JavaScript and exercised against `internal/fakephone`**. It has **never been sent to a real phone**. The checklist at the end is for the owner.

## What the phone does (from `page_security.js` and `commonjs.js`, firmware 66.86 on phone A)

| | |
|---|---|
| page | Security > Password, `p=security`. Load: `GET /servlet?m=mod_data&p=security&q=load` |
| request | `POST /servlet?m=mod_password&p=security&q=change` (a different module from the other writes) |
| form fields | `mode` (user type: `admin` or `user`), `editOldPassword`, `editNewPassword`, then `rsakey`, `rsaiv`, `token` |
| not sent | `editConfirmPassword`: the page script compares it with the new password and then sets its `dvalue` to the same value, so the generic form serialiser (which sends only fields that differ from `dvalue`) skips it. ylctl does not send it. |
| encryption | the two password fields are `base64(AES-128-CBC, zero padding)` of `"<random>;<JSESSIONID>;<value>"`. Unlike the login, **one** AES key and IV serve the whole post (`YLForm.objEncrypt`); `rsakey` and `rsaiv` are the RSA (PKCS#1 v1.5, the page's `g_rsa_n`/`g_rsa_e`) encryptions of their hex strings, sent once. The password page defines `g_rsa_n`, `g_rsa_e`, `g_curruser` and `g_strToken`. |
| CSRF | `token=<g_strToken>` from the same page. A wrong token gives HTTP 403. |
| answer | JSON `{"result":"N"}`: `0` changed, `-1` not enough permission, `-2` old password wrong, `-4` invalid password, `-5` the new password cannot be the default. (ylctl reads it bare or inside `_RES_INFO_`.) |
| afterwards | the page shows a notice and, when the changed user is the logged-in user, **jumps to `q=logout` after 2 seconds**. So the session ends. Nothing in the script reboots the phone. Whether the phone also drops other sessions is not known (the fake phone ends them all). |
| client side rules | blank password or too simple (shorter than 6, no letter or no digit) only asks `confirm()`; a "complex password" rule (`g_bPasswordRule`) can turn that into a note. The phone may enforce more. |
| `--user` | the page also changes the `user` account (`mode=user`; the old-password field is then disabled and not sent). That is **not supported**: the vault has no slot for it, its behaviour is unverified, and a wrong move there cannot lock you out but nothing here protects the other account's password either. ylctl changes the `admin` password only and refuses any other `--user`. |

## The command

```
ylctl [--mac MAC] password set <host> (--generate | --prompt) [--keychain] [--length 20]
                                      [--dry-run] [--yes] [--yes-i-understand]
ylctl [--mac MAC] password recover <host> [--keychain]
```

* **New password:** `--generate` makes 20 random characters (`--length` 12 to 32) from the server vault's own alphabet `ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_` (no look-alikes, nothing that needs escaping in a config file or URL; at least one upper, one lower, one digit). It is **never shown**: you only ever get it from the place that keeps it. `--prompt` reads it twice on a terminal without echo, then checks it: 8 to 32 characters, letters, digits and `-_.@!*+~^,:` only (a semicolon would be ambiguous in the phone's `random;session;value` envelope; quotes, spaces, `& % # = /` and non-ASCII are refused because forms, config files and URLs can mangle them), at least one letter and one digit, not the factory default, not the old password, not the user name or its reverse. **The new password is never accepted on the command line.**
* **Old password:** the usual resolution: `--mac` vault, `YLCTL_PASSWORD`, keychain, prompt (or `--try-default` for `admin`/`admin`, the normal way to move a fresh phone off its factory password).
* **Where the new one is kept** (exactly one):
  * `--mac MAC`, linked server (`ylctl login`): the vault, through the rotation routes. The MAC must be the phone's own MAC as the status page reports it; otherwise ylctl refuses before recording anything.
  * `--keychain` (or automatically when the old password came from the keychain, so that entry is not left stale): the OS keychain. The new value is first stored as `admin@<host>#pending`, committed to `admin@<host>`.
  * neither: allowed only with `--prompt` (you typed it, you keep it). `--generate` with nowhere to keep it is refused, because you would never see the password.
* **Refusals, all before anything is written:** the phone is not already pinned in `known_phones.json` (this command never pins; run `ylctl info` first and check the fingerprint; `--trust-new` and `--insecure` are refused); the status page does not give a model and a MAC; `--mac` does not match; a call is active (`GET /servlet?m=mod_webd&p=talking`, the check the web UI itself makes) or the call state cannot be read; the password page lacks its fields or the session is not `admin`; stdout/stdin is not a terminal and `--yes` was not given; the typed confirmation fails.
* **Confirmation (R4):** you type the phone's address exactly as given or the last 4 characters of its MAC. `--yes-i-understand` skips that. Without a terminal, `--yes` and `--yes-i-understand` are both required.
* **`--dry-run`:** does the read-only part for real (one login, GETs of status, call state and the password page, and, with `--mac`, one read of the current password from the vault) so that the checks mean something, prints the plan, and stops. It sends no write to the phone, records nothing, and does not ask for the new password. *Decision for the owner:* if you want a dry run that makes no network call at all, say so.

## Order of operations and what each failure leaves

```
 old password ─▶ login ─▶ checks ─▶ plan ─▶ confirm ─▶ new password
 1  store.Begin     record NEW as PENDING (vault: sealed beside the current one; keychain: #pending entry)
 2  phone change    POST once, never repeated, never retried with the old password afterwards
 3  verify          a FRESH client logs in with the NEW password
 4  store.Commit    pending becomes current (retried 3 times); the vault records who and when
```

| What happened | Phone | Record (vault/keychain) | Exit | What you are told |
|---|---|---|---|---|
| record could not be made (step 1) | untouched | untouched | 1 | "the phone was NOT changed" |
| phone refused with a result code (-1 -2 -4 -5) or a bad token | untouched | pending dropped, current = old | 1 | the phone's reason; **no extra logins** |
| no usable answer (HTTP error, dropped connection, unreadable) | unknown | pending | | step 3 decides: |
| ... new password logs in | changed | commit | 0 | success |
| ... new fails, **old still logs in** | untouched | pending dropped | 1 | "NOT changed (the old one still works)" |
| ... neither works or unreachable | unknown | pending **kept**, current = old | 7 | the state, and `recover` |
| phone said result 0, new password logs in | changed | commit | 0 | success |
| phone said result 0, new password does **not** log in | changed (per phone) | pending **kept**, current = old | 7 | the state, and `recover`. Nothing is rolled back, because that would throw away the only copy of the password the phone may be using. |
| commit fails 3 times | changed, verified | pending kept | 7 | "NOT lost, still pending; run recover" |
| dropping the pending record fails after a refusal | untouched | pending remains (harmless, expires in 1 hour) | 1 | a warning |

Login attempts are counted: a clear refusal costs 1 login in total, the worst case (answer unreadable, new fails, old fails) costs 3, and a result-0-but-new-fails case costs 2. The old password is never used after the POST except in the "no usable answer" case, once. A `lock` answer from the phone stops everything (exit 5).

### `ylctl password recover <host> (--mac MAC | --keychain)`

For a run that was killed, lost its connection, or ended with exit 7. It reads the pending value (vault: `reveal` with `which: pending`, logged like any reveal; keychain: the `#pending` entry) and the current one, then:

1. logs in with the **pending** value (attempt 1): accepted ⇒ commit (an expired vault rotation is re-recorded and committed), exit 0;
2. refused ⇒ logs in with the **current** value (attempt 2): accepted ⇒ the phone never changed, the pending value is dropped, exit 0;
3. neither ⇒ keeps everything, tells you so, exit 4. A phone that is unreachable stops after attempt 1 with nothing changed.

At most two logins. No typed confirmation: it only reconciles bookkeeping with what the phone already accepts.

## Server side

The vault routes live in the NQ Phone repo (branch `feat/vault-rotate`, on top of PR #35): `POST /api/v1/vault/secrets/device/{mac}/phone_admin/rotation` (begin), `.../rotation/{id}/commit`, `.../rotation/{id}/abort`. A linked CLI that is not read-only can use them without being able to manage the vault. Pending values expire after 1 hour but stay sealed for 7 days so an interrupted change can be recovered. Reveal keeps returning the current value and says `pending_exists`. Details: `docs/vault.md` there.

## After a change

* The web password is also what `ylctl --mac` fetches from the vault: the next command already uses the new one.
* `YLCTL_PASSWORD` in your shell, or a keychain entry saved by `ylctl auth save` that this run did not update, still hold the OLD password; ylctl warns. A script that retries with the old password can lock the phone.
* If the NQ Phone provisioning later pushes the admin password to the phone (`apply_to_phones` is stored but not acted on yet) it must push the vault's current value, or it will undo this change. Do not turn that on for a phone managed this way until it exists.

## Not verified (never sent to a real phone)

1. The exact body of the real answer to `q=change` (assumed `{"result":"0"}`, plain or in `_RES_INFO_`; anything else is treated as "no usable answer", which is safe: step 3 decides).
2. That the session ends after the change, that other sessions end, and whether the phone is briefly unreachable. ylctl never reuses the old session after the POST and never logs in with the old password afterwards, so either way is safe.
3. That `mode=admin` with only `editOldPassword`/`editNewPassword` is accepted (the confirm field is deliberately not sent, per the serialiser). If the phone insists on it the answer will be a refusal (`-4`) and nothing changes.
4. The call-state endpoint's real format (`{"talking":"0|1"}` per the UI script). If it answers something else ylctl refuses to proceed; `--dry-run` shows this without risk.
5. Which characters the phone's password check really accepts, how many failed logins lock the web account (never provoked), and whether a "complex password" rule is switched on in this firmware.
6. Whether the firmware's provisioning keeps overwriting the admin password from `static.security.user_password` in a config file.
7. The server routes were tested against PostgreSQL with the real handlers, not against a live deployment.

## Live test checklist for the owner (phone B, <phone-B-ip>, firmware 66.85) — do not run on phone A

Prerequisites: a way to reach the phone's keypad (factory reset is the only rescue if everything goes wrong); the server link (`ylctl login`) and a vault entry for phone B's MAC; no call on the phone and nobody else logged into its web interface; the repo build of this branch (`make build`, run `./bin/ylctl`).

1. **Pin and read.** `ylctl --mac 80:5e:c0:00:00:0b info <phone-B-ip>` (correct MAC for phone B). The phone must already be in `known_phones.json`.
2. **Dry run.** `ylctl --mac <MAC> password set <phone-B-ip> --generate --dry-run`. Expect: the plan, "checks passed", no call active, and exit 0. This proves the call-state and password-page reads on the real firmware. Stop here if anything says "cannot tell whether a call is active" or "lacks the expected fields" and send me the message.
3. **Server check.** On the server open Secrets (vault) for the phone and note the current password's `rotated_at`.
4. **Watch (optional).** In another terminal: `ylctl logs follow <phone-B-ip> --dry-run` to see what it would do, or keep the phone's screen in view.
5. **Real change, with the typed confirmation.** `ylctl --mac <MAC> password set <phone-B-ip> --generate` and type the last 4 characters of the MAC when asked. Expect the four numbered steps and "password changed ... verified with a fresh login, and recorded in the vault". Exit 0.
6. **Check it.** `ylctl --mac <MAC> info <phone-B-ip>` works (the vault now serves the new password); the vault shows a new `rotated_at`/`rotated_by` and `pending_exists: false`; logging in at `https://<phone-B-ip>` with the OLD password fails and the new one (reveal it from the vault page, logged) works.
7. **Session behaviour (write down what you see):** did the browser session you left open (if any) get logged out? did the phone reboot or lose its registration? Does the web UI still work? These are open question 2.
8. **Change back / second run.** Run step 5 again to prove a second rotation works and the `#pending` handling is clean (`ylctl --mac <MAC> password recover <phone-B-ip>` must say "Nothing is pending").
9. **Failure drill (optional, only after a clean run):** pause this computer's link on the server's Linked CLIs page and run step 5 again. It must stop at step 1 with "the phone was NOT changed", and the phone's password must be unchanged (check with `ylctl --mac <MAC> info` after resuming the link). Commit and verify failures are covered by the fake-phone tests only; do not try to provoke them on the real phone.
10. **If a run ends with exit 7:** do not retry `set`. Run `ylctl --mac <MAC> password recover <phone-B-ip>`. If it says neither password works, wait 10 minutes (a lock), and run it once more. Last resort: factory reset from the keypad, then re-provision.

Report back: exit codes, the on-screen text of steps 5 to 7, the vault's access log lines (`rot_begin`, `rot_commit`), and anything surprising on the phone.
