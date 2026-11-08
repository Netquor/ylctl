package yealink

import (
	"errors"
	"fmt"
)

// Sentinel errors. Use errors.Is / errors.As to classify failures.
var (
	// ErrAuthFailed means the phone rejected the username or password.
	ErrAuthFailed = errors.New("authentication failed: wrong username or password")
	// ErrLocked means the phone reports the web account as locked after too many failures.
	ErrLocked = errors.New("the phone locked the web login (too many failed attempts); wait and do not retry")
	// ErrSessionLost means the phone kept answering with the login page even after one clean re-login.
	ErrSessionLost = errors.New("session lost: the phone returned its login page")
	// ErrUnexpectedPage means a page did not look like the expected phone page.
	ErrUnexpectedPage = errors.New("unexpected page from phone")
	// ErrTruncated means the response ended before the closing HTML tag.
	ErrTruncated = errors.New("truncated response from phone")
	// ErrTooLarge means the response exceeded the configured size limit.
	ErrTooLarge = errors.New("response from phone is too large")
	// ErrNotYealink means the host did not answer like a Yealink web interface.
	ErrNotYealink = errors.New("host does not look like a Yealink phone")
	// ErrWriteRejected means the phone did not acknowledge a settings write.
	ErrWriteRejected = errors.New("the phone did not accept the write")

	errSessionLost = errors.New("session lost (internal)")
)

// CertChangedError is returned when the phone presents a certificate that
// differs from the pinned fingerprint. It is always a hard error.
type CertChangedError struct {
	Host      string
	Pinned    string
	Presented string
}

func (e *CertChangedError) Error() string {
	return fmt.Sprintf("TLS certificate of %s changed: pinned sha256 %s, presented %s (refusing to continue; remove the entry from known_phones.json only if you expect this)", e.Host, e.Pinned, e.Presented)
}

// UntrustedError is returned for a phone certificate that is not pinned yet.
type UntrustedError struct {
	Host        string
	Fingerprint string
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("TLS certificate of %s is not trusted yet (sha256 %s); verify it, then re-run with --trust-new", e.Host, e.Fingerprint)
}

// HTTPError is a non-200 answer.
type HTTPError struct {
	Status int
	Path   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("phone answered HTTP %d for %s", e.Status, e.Path)
}
