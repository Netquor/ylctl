package yealink

import "crypto/tls"

// phoneCipherSuites returns the cipher suites offered to a phone. The T4x
// firmware (66.85) only offers DHE and plain RSA key exchange; Go has no DHE,
// and no longer enables RSA key exchange by default, so those suites are
// added explicitly. The connection is authenticated by the pinned certificate
// fingerprint, not by the cipher suite, and only ever talks to a phone on the
// local network.
func phoneCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	return append(ids,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	)
}
