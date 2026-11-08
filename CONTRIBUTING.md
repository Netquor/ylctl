# Contributing

Thanks for helping. ylctl talks to real phones, so changes are held to a safety bar.

## Ground rules

* **Never put a phone password, provisioning token, SIP password or full provisioning URL in an issue, pull request, test or fixture.** Replace tokens with `<token>`; MAC addresses may stay. Fixtures under `internal/fakephone/testdata/` come from real phones and are sanitized before commit (`g_strToken` and the token in the provisioning URL become `<token>`).
* Reads first: new commands start read-only. Anything that writes needs `--dry-run`, a before/after diff, verification by re-reading, and a fake-phone test.
* Never add factory reset, firmware upgrade, password change or config import without discussing it in an issue first.
* Wrong passwords must never be retried in a loop: a phone can lock its web login.
* Minimal dependencies: standard library plus cobra and `golang.org/x/term`.

## Workflow

```sh
make test      # go test -race -count=1 ./...
make lint      # go vet, gofmt check, golangci-lint when installed
go test ./internal/cli -update   # rewrite golden files after an intended output change; review the diff
```

Commit messages: short imperative subject, explain why in the body. Go 1.22 is the minimum language level.

## Testing against hardware

The tests never touch a phone. If you verify on hardware, use a spare phone you can factory reset, record the exact commands and sanitized output (see `docs/live-test.md`), and say which firmware you used.
New firmware: save the three pages (`status`, `settings-autop`, `account-register`) and the login form, sanitize them, add a fixture directory and a parser test.
