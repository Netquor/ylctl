package pbx

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Link is what is remembered about the server this tool is linked to. The
// token itself lives in the OS keychain (or $YLCTL_PBX_TOKEN), not in this file.
type Link struct {
	Server    string `json:"server"`
	KeyName   string `json:"key_name"`
	LinkedAt  string `json:"linked_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Expired reports whether the trust period has ended (the server enforces it too).
func (l Link) Expired(now time.Time) bool {
	if l.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, l.ExpiresAt)
	return err == nil && !t.After(now)
}

// ErrNotLinked means no server is linked.
var ErrNotLinked = errors.New("not linked to a server: run 'ylctl login https://your-pbx'")

func linkPath(dir string) string { return filepath.Join(dir, "pbx.json") }

// LoadLink reads the saved link.
func LoadLink(dir string) (Link, error) {
	b, err := os.ReadFile(linkPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return Link{}, ErrNotLinked
	}
	if err != nil {
		return Link{}, err
	}
	var l Link
	if err := json.Unmarshal(b, &l); err != nil || l.Server == "" {
		return Link{}, errors.New("the saved link is unreadable; run 'ylctl logout' and 'ylctl login' again")
	}
	return l, nil
}

// SaveLink writes the link atomically with mode 0600.
func SaveLink(dir string, l Link) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(l, "", " ")
	tmp := linkPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, linkPath(dir))
}

// ForgetLink removes the saved link.
func ForgetLink(dir string) error {
	if err := os.Remove(linkPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
