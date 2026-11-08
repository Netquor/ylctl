# Python prototype

`yl_login.py` is the original proof of concept of the T4x web login, kept for reference. The Go CLI in the repository root replaces it; it is **not maintained** and not used by any test.

Known issue fixed here: the RSA output must be fixed-width hex. Before the fix the prototype stripped a leading zero nibble about one time in eight and the phone answered `{"authstatus":"error","errorno":"-3"}`, which looks exactly like a wrong password. Do not loop on that answer.

It needs `openssl` for AES and defaults to `admin`/`admin` in its `__main__`; do not run it against a phone whose lockout behaviour you do not know.
