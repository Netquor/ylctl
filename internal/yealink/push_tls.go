package yealink

import "crypto/tls"

// pushTLS is only used for the fallback HTTPS push to a phone on the local network that the operator already
// chose by address; the phone's own certificate is self-signed.
func pushTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: phoneCipherSuites()} //nolint:gosec // self-signed phone certificate, address chosen by the operator
}
