package yealink

import (
	"net/url"
	"regexp"
	"strings"
)

// Masked is what secret values print as.
const Masked = "********"

var secretName = regexp.MustCompile(`(?i)pass|pwd|aes|secret|key|token`)

// IsSecretName reports whether a field name holds a secret.
func IsSecretName(name string) bool { return secretName.MatchString(name) }

// MaskValue returns Masked for non-empty values of secret-named fields.
func MaskValue(name, value string) string {
	if IsSecretName(name) && value != "" {
		return Masked
	}
	return value
}

// MaskURL shortens secret-looking parts of a URL: long path segments keep
// their first four characters, userinfo passwords and query values are hidden.
// The provisioning URL of a phone normally contains a token in its path.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return maskOpaque(raw)
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if len(s) > 12 {
			segs[i] = s[:4] + "..."
		}
	}
	u.Path = strings.Join(segs, "/")
	u.RawPath = ""
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			q.Set(k, "...")
		}
		u.RawQuery = q.Encode()
	}
	out := u.String()
	return strings.ReplaceAll(out, "%2E%2E%2E", "...")
}

func maskOpaque(s string) string {
	if len(s) > 12 {
		return s[:4] + "..."
	}
	return s
}
