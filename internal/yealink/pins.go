package yealink

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Pin is one trusted certificate fingerprint.
type Pin struct {
	SHA256    string    `json:"sha256"`
	FirstSeen time.Time `json:"first_seen"`
}

// PinStore is the trust-on-first-use store, a JSON file with mode 0600.
type PinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]Pin
}

// ConfigDir returns $YLCTL_CONFIG_DIR, or $XDG_CONFIG_HOME/ylctl, or ~/.config/ylctl.
func ConfigDir(getenv func(string) string) (string, error) {
	if d := getenv("YLCTL_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "ylctl"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "ylctl"), nil
}

// OpenPinStore loads the store at path (missing file is an empty store).
func OpenPinStore(path string) (*PinStore, error) {
	s := &PinStore{path: path, pins: map[string]Pin{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.pins); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Get returns the pin for a host:port key.
func (s *PinStore) Get(key string) (Pin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[key]
	return p, ok
}

// Add stores a pin and writes the file.
func (s *PinStore) Add(key, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[key] = Pin{SHA256: fingerprint, FirstSeen: time.Now().UTC().Truncate(time.Second)}
	return s.saveLocked()
}

func (s *PinStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.pins, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Fingerprint returns the lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}
