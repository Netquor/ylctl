package yealink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

// ParseRSAKey builds the phone's public key from the hex values on the login page.
func ParseRSAKey(nHex, eHex string) (*rsa.PublicKey, error) {
	n, ok := new(big.Int).SetString(nHex, 16)
	if !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("%w: bad RSA modulus", ErrUnexpectedPage)
	}
	e, ok := new(big.Int).SetString(eHex, 16)
	if !ok || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: bad RSA exponent", ErrUnexpectedPage)
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// LoginSecret is the encrypted login material the phone expects.
type LoginSecret struct {
	Pwd    string // base64(AES-128-CBC, zero padding) of "<random>;<session>;<password>"
	RSAKey string // hex RSA(PKCS#1 v1.5) of the 32 char AES key string
	RSAIV  string // hex RSA(PKCS#1 v1.5) of the 32 char IV string
}

// EncryptLogin implements the phone's hybrid scheme. The AES key and IV are 16
// random bytes, written as 32 hex characters (the phone uses the MD5 hex of a
// random number; only the format matters). The hex strings are RSA encrypted
// and the same bytes (hex decoded) are used for AES.
func EncryptLogin(pub *rsa.PublicKey, sessionID, password string, rnd io.Reader) (*LoginSecret, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	raw := make([]byte, 33)
	if _, err := io.ReadFull(rnd, raw); err != nil {
		return nil, err
	}
	keyHex := hex.EncodeToString(raw[:16])
	ivHex := hex.EncodeToString(raw[16:32])
	nonce := fmt.Sprintf("0.%d", new(big.Int).SetBytes(raw[32:]).Uint64()*1000003+17)
	plain := []byte(nonce + ";" + sessionID + ";" + password)
	ct, err := aesCBCZero(raw[:16], raw[16:32], plain)
	if err != nil {
		return nil, err
	}
	rk, err := rsa.EncryptPKCS1v15(rnd, pub, []byte(keyHex))
	if err != nil {
		return nil, fmt.Errorf("rsa: %w", err)
	}
	ri, err := rsa.EncryptPKCS1v15(rnd, pub, []byte(ivHex))
	if err != nil {
		return nil, fmt.Errorf("rsa: %w", err)
	}
	return &LoginSecret{Pwd: base64.StdEncoding.EncodeToString(ct), RSAKey: hex.EncodeToString(rk), RSAIV: hex.EncodeToString(ri)}, nil
}

func aesCBCZero(key, iv, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := (aes.BlockSize - len(plain)%aes.BlockSize) % aes.BlockSize
	buf := append(append([]byte{}, plain...), make([]byte, pad)...)
	out := make([]byte, len(buf))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, buf)
	return out, nil
}

// EncryptSecrets encrypts several password-type form values the way the phone's
// own page does for one form post: ONE random AES key and IV for the whole post
// (sent once as rsakey and rsaiv), and a fresh random prefix inside each value.
// Each value is base64(AES-128-CBC, zero padding) of "<random>;<session>;<value>".
func EncryptSecrets(pub *rsa.PublicKey, sessionID string, values []string, rnd io.Reader) (pwds []string, rsaKey, rsaIV string, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	raw := make([]byte, 32)
	if _, err = io.ReadFull(rnd, raw); err != nil {
		return
	}
	key, iv := raw[:16], raw[16:]
	for _, v := range values {
		nb := make([]byte, 8)
		if _, err = io.ReadFull(rnd, nb); err != nil {
			return
		}
		nonce := fmt.Sprintf("0.%d", new(big.Int).SetBytes(nb).Uint64()%1000000000000000)
		var ct []byte
		if ct, err = aesCBCZero(key, iv, []byte(nonce+";"+sessionID+";"+v)); err != nil {
			return
		}
		pwds = append(pwds, base64.StdEncoding.EncodeToString(ct))
	}
	rk, err := rsa.EncryptPKCS1v15(rnd, pub, []byte(hex.EncodeToString(key)))
	if err != nil {
		return nil, "", "", fmt.Errorf("rsa: %w", err)
	}
	ri, err := rsa.EncryptPKCS1v15(rnd, pub, []byte(hex.EncodeToString(iv)))
	if err != nil {
		return nil, "", "", fmt.Errorf("rsa: %w", err)
	}
	return pwds, hex.EncodeToString(rk), hex.EncodeToString(ri), nil
}
