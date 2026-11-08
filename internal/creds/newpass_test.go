package creds

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		pw, err := GeneratePassword(20)
		if err != nil || len(pw) != 20 {
			t.Fatalf("%q %v", pw, err)
		}
		if strings.Trim(pw, GenAlphabet) != "" {
			t.Fatalf("outside the alphabet: %q", pw)
		}
		if strings.ContainsAny(pw, "0O1lI") {
			t.Fatalf("look-alike in %q", pw)
		}
		if strings.ContainsAny(pw, " ;\"'\\`<>&%$#=/|") {
			t.Fatalf("needs escaping: %q", pw)
		}
		var up, lo, di bool
		for _, c := range pw {
			up = up || (c >= 'A' && c <= 'Z')
			lo = lo || (c >= 'a' && c <= 'z')
			di = di || (c >= '0' && c <= '9')
		}
		if !up || !lo || !di {
			t.Fatalf("missing a class: %q", pw)
		}
		if seen[pw] {
			t.Fatal("repeated password")
		}
		seen[pw] = true
		if err := ValidateNewPassword(pw, "x", "admin"); err != nil {
			t.Errorf("a generated password must pass the typed rules too: %q %v", pw, err)
		}
	}
	for _, n := range []int{0, 11, 33, 100} {
		if _, err := GeneratePassword(n); err == nil {
			t.Errorf("length %d must be refused", n)
		}
	}
	if _, err := GeneratePassword(32); err != nil {
		t.Error(err)
	}
}

func TestGenAlphabetMatchesTheServer(t *testing.T) {
	// internal/vault/service.go in the NQ Phone server uses exactly this alphabet
	if GenAlphabet != "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_" {
		t.Fatal("the alphabet must stay identical to the server's")
	}
}

func TestValidateNewPassword(t *testing.T) {
	ok := []string{"Abcdefg1", "abc12345", "My-Pass_word.9", "A1!*+~^,:xyz"}
	for _, p := range ok {
		if err := ValidateNewPassword(p, "old-Pass-1", "admin"); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	bad := map[string]string{
		"Abc1": "8 to 32", strings.Repeat("a1", 17): "8 to 32", "abcdefgh": "letter and one digit", "12345678": "letter and one digit",
		"Abcd 1234": "letters, digits", "Abcd1234;": "letters, digits", "Pässwort1": "letters, digits", "Ab1\"cdefg": "letters, digits",
		"Admin": "8 to 32", "old-Pass-1": "same as the current", "admin": "8 to 32",
	}
	for p, want := range bad {
		err := ValidateNewPassword(p, "old-Pass-1", "admin")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", p, err, want)
		}
	}
	if err := checkNotDefaultOrOld("ADMIN", "x", "admin"); err == nil {
		t.Error("the factory default in any case must be refused")
	}
	if err := checkNotDefaultOrOld("nimda", "x", "admin"); err == nil {
		t.Error("the reversed user name must be refused")
	}
}
