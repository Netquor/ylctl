#!/usr/bin/env python3
"""Prototype of the Yealink T4x web login (reverse-engineered from its own JavaScript).
Hybrid scheme: random AES-128 key and IV (MD5 hex of random numbers), each RSA(PKCS#1 v1.5)-encrypted
with the phone's public key; the password is sent as base64(AES-CBC, zero padding) of
"<random>;<JSESSIONID>;<password>"."""
import base64, hashlib, http.cookiejar, json, os, random, re, secrets, ssl, subprocess, sys, urllib.parse, urllib.request

def rsa_encrypt_hex(n_hex, e_hex, msg):
    n = int(n_hex, 16); e = int(e_hex, 16); k = (n.bit_length() + 7) // 8
    ps = bytes(secrets.choice(range(1, 256)) for _ in range(k - len(msg) - 3))
    em = b"\x00\x02" + ps + b"\x00" + msg
    c = pow(int.from_bytes(em, "big"), e, n)
    return format(c, "0%dx" % (2 * k))  # fixed width: an unpadded hex string is rejected by the phone about 1 time in 8

def aes_cbc_zero(key_hex, iv_hex, plaintext):
    pad = (-len(plaintext)) % 16
    data = plaintext + b"\x00" * pad
    out = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-K", key_hex, "-iv", iv_hex, "-nopad"], input=data, capture_output=True, check=True).stdout
    return base64.b64encode(out).decode()

class Phone:
    def __init__(self, host, scheme="https"):
        self.base = f"{scheme}://{host}"
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ctx))
    def get(self, path, timeout=10):
        return self.op.open(self.base + path, timeout=timeout).read().decode(errors="replace")
    def post(self, path, body, timeout=10):
        return self.op.open(urllib.request.Request(self.base + path, data=body.encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=timeout).read().decode(errors="replace")
    def login(self, user, password):
        page = self.get("/servlet?m=mod_listener&p=login&q=loginForm")
        n = re.search(r'rsa_n\s*=\s*"([0-9A-Fa-f]+)"', page).group(1); e = re.search(r'rsa_e\s*=\s*"([0-9A-Fa-f]+)"', page).group(1)
        sid = next(c.value for c in self.jar if c.name == "JSESSIONID")
        key = hashlib.md5(str(random.random()).encode()).hexdigest(); iv = hashlib.md5(str(random.random()).encode()).hexdigest()
        pt = (str(random.random()) + ";" + sid + ";" + password).encode()
        pwd = aes_cbc_zero(key, iv, pt)
        body = "username=%s&pwd=%s&rsakey=%s&rsaiv=%s" % (urllib.parse.quote(user), urllib.parse.quote(pwd), urllib.parse.quote(rsa_encrypt_hex(n, e, key.encode())), urllib.parse.quote(rsa_encrypt_hex(n, e, iv.encode())))
        res = self.post("/servlet?m=mod_listener&p=login&q=login", body)
        m = re.search(r'<div id="_RES_INFO_"[^>]*>(.*?)</div>', res, re.S)
        info = json.loads(m.group(1)) if m and m.group(1).strip() else {}
        return info

if __name__ == "__main__":
    host = sys.argv[1]; p = Phone(host)
    info = p.login("admin", "admin")
    print("login response:", {k: v for k, v in info.items()})
