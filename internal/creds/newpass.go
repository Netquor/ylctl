package creds

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// GenAlphabet is the alphabet of generated passwords. It is the NQ Phone
// server's own (internal/vault): no look-alike characters (0 O 1 l I) and
// nothing that needs escaping in a phone configuration file, a shell or a URL.
const GenAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"

// Limits for a phone web password. The phone's field holds 32 characters.
const (
	MinNewLength = 8
	MaxNewLength = 32
)

// GeneratePassword makes a random password of n characters (12 to 32) with at
// least one upper-case letter, one lower-case letter and one digit.
func GeneratePassword(n int) (string, error) {
	if n < 12 || n > MaxNewLength {
		return "", fmt.Errorf("length must be 12 to %d", MaxNewLength)
	}
	max := big.NewInt(int64(len(GenAlphabet)))
	for tries := 0; tries < 100; tries++ {
		out := make([]byte, n)
		var up, lo, di bool
		for i := range out {
			k, err := rand.Int(rand.Reader, max) // no modulo bias
			if err != nil {
				return "", err
			}
			ch := GenAlphabet[k.Int64()]
			out[i] = ch
			switch {
			case ch >= 'A' && ch <= 'Z':
				up = true
			case ch >= 'a' && ch <= 'z':
				lo = true
			case ch >= '2' && ch <= '9':
				di = true
			}
		}
		if up && lo && di {
			return string(out), nil
		}
	}
	return "", errors.New("could not generate a password")
}

// allowedExtra are the non-alphanumeric characters accepted in a typed password.
// Everything else (space, ; " ' \ ` < > & % $ # = / | and non-ASCII) is refused
// because it can be mangled by the phone's form handling, a configuration file
// or a URL.
const allowedExtra = "-_.@!*+~^,:"

// ValidateNewPassword checks a password someone typed. Generated passwords pass.
func ValidateNewPassword(pw, old, user string) error {
	if len(pw) < MinNewLength || len(pw) > MaxNewLength {
		return fmt.Errorf("the new password must be %d to %d characters", MinNewLength, MaxNewLength)
	}
	var letter, digit bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letter = true
		case r >= '0' && r <= '9':
			digit = true
		case r < 0x80 && strings.ContainsRune(allowedExtra, r):
		default:
			return fmt.Errorf("the new password may use letters, digits and %s only (other characters can be mangled by the phone's form, a config file or a URL)", allowedExtra)
		}
	}
	if !letter || !digit {
		return errors.New("the new password must contain at least one letter and one digit")
	}
	return checkNotDefaultOrOld(pw, old, user)
}

func checkNotDefaultOrOld(pw, old, user string) error {
	if strings.EqualFold(pw, "admin") {
		return errors.New("the new password cannot be the factory default")
	}
	if pw == old {
		return errors.New("the new password is the same as the current one")
	}
	if user != "" {
		rev := []rune(user)
		for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
			rev[i], rev[j] = rev[j], rev[i]
		}
		if pw == user || pw == string(rev) {
			return errors.New("the new password is too similar to the user name")
		}
	}
	return nil
}

// ValidateGenerated is the check for a password we made ourselves: only the
// rules that matter (not the factory default, not the old one).
func ValidateGenerated(pw, old, user string) error { return checkNotDefaultOrOld(pw, old, user) }

// KeychainAvailable reports whether this system has a keychain helper ylctl can use.
func KeychainAvailable(o Options) bool {
	if o.Runner == nil {
		return false
	}
	switch goos(o) {
	case "darwin":
		_, err := o.Runner.LookPath("security")
		return err == nil
	case "linux":
		_, err := o.Runner.LookPath("secret-tool")
		return err == nil
	}
	return false
}
