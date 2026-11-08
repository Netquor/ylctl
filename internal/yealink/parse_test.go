package yealink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Netquor/ylctl/internal/fakephone"
)

func TestStateFromCode(t *testing.T) {
	for _, tc := range []struct {
		code     int
		name     string
		observed bool
	}{
		{0, "disabled", true}, {1, "registering", false}, {2, "registered", true}, {3, "failed", false},
		{6, "inexistent", false}, {-1, "registering", false}, {4, "registering", false}, {7, "registering", false},
		{8, "registering", false}, {9, "registering", false}, {10, "registering", false},
		{5, "registered", false}, {11, "registered", false}, {42, "unknown", false},
	} {
		s := StateFromCode(tc.code)
		if s.Name != tc.name || s.Observed != tc.observed || s.Code != tc.code {
			t.Errorf("code %d: %+v", tc.code, s)
		}
	}
}

func TestSplitAccountStatus(t *testing.T) {
	for _, tc := range []struct {
		in    string
		label string
		code  int
	}{
		{"1004@pbx.example.net:2", "1004@pbx.example.net", 2},
		{"1004@pbx.example.net:5061:3", "1004@pbx.example.net:5061", 3},
		{"0", "", 0},
		{"", "", 99},
		{"x@y:abc", "x@y", 99},
	} {
		l, c := splitAccountStatus(tc.in)
		if l != tc.label || c != tc.code {
			t.Errorf("%q -> %q %d", tc.in, l, c)
		}
	}
}

func TestParseStatusFixtures(t *testing.T) {
	for _, tc := range []struct{ dir, fw, mac, ip, label string }{
		{"phoneB_66.85", "66.85.0.79", "80:5E:C0:00:00:0B", "10.20.30.211", "1004@pbx.example.net"},
		{"phoneA_66.86", "66.86.0.15", "80:5E:C0:00:00:0A", "10.20.30.204", "1002@pbx.example.net"},
	} {
		st, err := ParseStatus(fakephone.Fixture(tc.dir, "status.html"))
		if err != nil {
			t.Fatal(err)
		}
		i := st.Info
		if i.Model != "T41S" || i.Firmware != tc.fw || i.MAC != tc.mac || i.IP != tc.ip || i.Hardware != "68.0.0.0.0.0.0" || i.UptimeSeconds <= 0 {
			t.Errorf("%s info %+v", tc.dir, i)
		}
		if st.Network.WANType != "DHCP" || st.Network.Mask != "255.255.255.0" || st.Network.DNS1 != "1.1.1.1" || st.Network.LinkStatus != "100Mbps Full Duplex" {
			t.Errorf("%s network %+v", tc.dir, st.Network)
		}
		if len(st.Accounts) != 6 || st.Accounts[0].Label != tc.label || st.Accounts[0].State.Name != "registered" || st.Accounts[1].State.Name != "disabled" || st.Accounts[5].Index != 6 {
			t.Errorf("%s accounts %+v", tc.dir, st.Accounts)
		}
	}
}

func TestParseAutopFixtures(t *testing.T) {
	ap, err := ParseAutop(fakephone.Fixture("phoneB_66.85", "settings-autop.html"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		FieldEnablePNP: "0", FieldEnableDHCP: "0", FieldPowerOn: "1", FieldRepeatMinutes: "60",
		"AutoProvisionWeeklyMask": "0123456", "AutoProvisionFlexibleBeginTime": "02:00",
		"AutoProvisionPassword": "********", FieldServerURL: "https://pbx.example.net/webhooks/provision/<token>/",
	}
	for k, v := range want {
		if got, ok := ap.Get(k); !ok || got != v {
			t.Errorf("%s = %q (%v), want %q", k, got, ok, v)
		}
	}
	for _, f := range ap.Fields {
		if strings.HasSuffix(f.Name, "_hour") || strings.HasSuffix(f.Name, "_min") || strings.HasPrefix(f.Name, "CKB_") {
			t.Errorf("helper input %s leaked", f.Name)
		}
	}
	ap, err = ParseAutop(fakephone.Fixture("phoneA_66.86", "settings-autop.html"))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ap.Get(FieldServerURL); v != "" {
		t.Errorf("phone A has no URL, got %q", v)
	}
	if v, _ := ap.Get(FieldEnablePNP); v != "1" {
		t.Errorf("phone A PnP %q", v)
	}
}

func TestParseAccountFixture(t *testing.T) {
	a, err := ParseAccount(fakephone.Fixture("phoneB_66.85", "account-register.html"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Enabled || a.Label != "1004" || a.DisplayName != "Test Phone 2" || a.Password != Masked {
		t.Errorf("%+v", a)
	}
	if len(a.Servers) != 2 || a.Servers[0] != (SIPServer{"pbx.example.net", "5061", "TLS"}) {
		t.Errorf("servers %+v", a.Servers)
	}
	if a.Outbound.Enabled {
		t.Error("outbound proxy should be off")
	}
}

// Parsers must survive anything: cut fixtures at many offsets, feed noise.
func TestParsersNeverPanic(t *testing.T) {
	var inputs []string
	for _, n := range []string{"status.html", "settings-autop.html", "account-register.html", "loginform.html"} {
		full := fakephone.Fixture("phoneB_66.85", n)
		for _, cut := range []int{0, 1, 10, 100, len(full) / 3, len(full) / 2, len(full) - 1} {
			inputs = append(inputs, full[:cut])
		}
		inputs = append(inputs, strings.ReplaceAll(full, `"`, ""), strings.ReplaceAll(full, "</label>", ""), strings.ToUpper(full))
	}
	noise := make([]byte, 4096)
	rand.Read(noise)
	inputs = append(inputs, string(noise), "<input name=", `<label id="PhoneFirmware" dvalue=`, `g_dataAccStatus = g_json.ParseJSON("{`, "\x00\xff<<<>>>")
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d panicked: %v", i, r)
				}
			}()
			ParseStatus(in)
			ParseAutop(in)
			ParseAccount(in, 1)
			IdentifyLoginPage(in)
			IsLoginPage(in)
			ParseFields(in)
			ParseToken(in)
		}()
	}
	if _, err := ParseStatus("<html></html>"); !errors.Is(err, ErrUnexpectedPage) {
		t.Errorf("got %v", err)
	}
	if _, err := ParseAutop("<html></html>"); !errors.Is(err, ErrUnexpectedPage) {
		t.Errorf("got %v", err)
	}
}

func TestIdentifyLoginPage(t *testing.T) {
	id, ok := IdentifyLoginPage(fakephone.Fixture("phoneA_66.86", "loginform.html"))
	if !ok || id.Model != "T41S" || id.Firmware != "66.86.0.15" {
		t.Errorf("%+v %v", id, ok)
	}
	// only the title and asset URLs are available
	page := `<html><head><link href="/theme/css/style.css?66.84.0.5"/><script src="/js/pages/page_login.js?66.84.0.5"></script><title>Yealink T46S Phone</title></head></html>`
	id, ok = IdentifyLoginPage(page)
	if !ok || id.Model != "T46S" || id.Firmware != "66.84.0.5" {
		t.Errorf("%+v %v", id, ok)
	}
	if _, ok := IdentifyLoginPage("<html><title>Router</title></html>"); ok {
		t.Error("a router is not a Yealink phone")
	}
}

func TestMasking(t *testing.T) {
	for _, n := range []string{"AutoProvisionPassword", "AutoProvisionAESKey16", "AccountPassword", "token", "my_secret", "PWD"} {
		if !IsSecretName(n) || MaskValue(n, "x") != Masked {
			t.Errorf("%s should be secret", n)
		}
	}
	if MaskValue("AutoProvisionPassword", "") != "" {
		t.Error("empty stays empty")
	}
	if IsSecretName("AutoProvisionUser") || IsSecretName("AutoProvisionRepeatMinutes") {
		t.Error("over-masking")
	}
	got := MaskURL("https://user:hunter2@pbx.example.net/webhooks/provision/abcdefghijklmnopqrstuvwxyz0123456789/?token=sekrit&x=1")
	for _, bad := range []string{"hunter2", "abcdefghijklmnop", "sekrit"} {
		if strings.Contains(got, bad) {
			t.Errorf("MaskURL leaked %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "pbx.example.net") || !strings.Contains(got, "/webhooks/provision/abcd.../") {
		t.Errorf("MaskURL too aggressive: %s", got)
	}
	if MaskURL("") != "" || MaskURL("not a url at all, really") == "not a url at all, really" {
		t.Error("opaque strings")
	}
	if Display(FieldServerURL, "https://h/p/0123456789abcdefghij/", true) != "https://h/p/0123456789abcdefghij/" {
		t.Error("reveal")
	}
}

func TestEncryptLoginRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseRSAKey(fmt.Sprintf("%X", key.N), fmt.Sprintf("%06X", key.E))
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"admin", "a;b;c", "exactly-sixteen!", ""} {
		sec, err := EncryptLogin(pub, "SESSION123", pw, nil)
		if err != nil {
			t.Fatal(err)
		}
		// RSA parts are full width hex (the phone rejects short ones, see the prototype's fix)
		if len(sec.RSAKey) != 256 || len(sec.RSAIV) != 256 {
			t.Fatalf("rsa hex width %d/%d", len(sec.RSAKey), len(sec.RSAIV))
		}
		dec := func(h string) []byte {
			raw, _ := hex.DecodeString(h)
			pt, err := rsa.DecryptPKCS1v15(nil, key, raw)
			if err != nil {
				t.Fatal(err)
			}
			b, err := hex.DecodeString(string(pt))
			if err != nil || len(b) != 16 {
				t.Fatalf("key material %q", pt)
			}
			return b
		}
		k, iv := dec(sec.RSAKey), dec(sec.RSAIV)
		ct, _ := base64.StdEncoding.DecodeString(sec.Pwd)
		if len(ct)%16 != 0 || len(ct) == 0 {
			t.Fatalf("ciphertext length %d", len(ct))
		}
		// decrypt with the library's own primitive inverse
		blk, _ := aesDecrypt(k, iv, ct)
		parts := strings.SplitN(strings.TrimRight(string(blk), "\x00"), ";", 3)
		if len(parts) != 3 || parts[1] != "SESSION123" || parts[2] != pw {
			t.Fatalf("plaintext %q", blk)
		}
	}
	if _, err := ParseRSAKey("zz", "010001"); err == nil {
		t.Error("bad modulus accepted")
	}
	if _, err := ParseRSAKey("ABCD", "0"); err == nil {
		t.Error("bad exponent accepted")
	}
}

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in, base, label string
		bad             bool
	}{
		{"10.0.0.1", "https://10.0.0.1:443", "10.0.0.1", false},
		{"10.0.0.1:8443", "https://10.0.0.1:8443", "10.0.0.1:8443", false},
		{"http://10.0.0.1", "http://10.0.0.1:80", "10.0.0.1", false},
		{"[fe80::1]:443", "https://[fe80::1]:443", "fe80::1", false},
		{"", "", "", true}, {"ftp://x", "", "", true}, {"https://admin:pw@10.0.0.1", "", "", true},
	} {
		tg, err := ParseTarget(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("%q should fail", tc.in)
			}
			continue
		}
		if err != nil || tg.BaseURL() != tc.base || tg.Label() != tc.label {
			t.Errorf("%q: %+v %v", tc.in, tg, err)
		}
	}
}

func TestWriteErr(t *testing.T) {
	err := writeErr(&HTTPError{Status: 403, Path: "/x"})
	if !errors.Is(err, ErrWriteRejected) {
		t.Errorf("%v", err)
	}
	if e := (&HTTPError{Status: 500}); writeErr(e) != error(e) {
		t.Error("other statuses pass through")
	}
}

// aesDecrypt is the inverse of aesCBCZero (zero padding is left in place); .
func aesDecrypt(key, iv, ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	return out, nil
}
