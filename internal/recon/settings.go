package recon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Settings are the few things recon remembers between runs.
type Settings struct {
	// TFTPOnNetwork says whether DHCP option 66 points phones at the PBX's TFTP
	// server on this network. nil = not asked yet. For now this is only a stated
	// fact the tool uses to choose a plan for phones it cannot log in to.
	TFTPOnNetwork *bool `json:"tftp_on_network,omitempty"`
	// DHCPURLOnNetwork says the DHCP server hands phones the server's enrollment URL itself
	// (option 66 = https://server/.../<token>/), so a new or factory-reset phone enrolls without any tool.
	// nil = not asked yet.
	DHCPURLOnNetwork *bool    `json:"dhcp_url_on_network,omitempty"`
	Subnets          []string `json:"subnets,omitempty"`
}

func path(dir string) string { return filepath.Join(dir, "recon.json") }

// ZeroTouch is how a phone on this network gets its first configuration without help.
type ZeroTouch int

const (
	ZTUnknown ZeroTouch = iota // not asked yet
	ZTNone                     // nothing: a reset phone needs a person
	ZTTFTP                     // DHCP points at the PBX's TFTP server
	ZTDHCPURL                  // DHCP hands out the enrollment URL
)

// ZeroTouch reads the stated mode. The enrollment URL wins over TFTP when both are set.
func (s Settings) ZeroTouch() ZeroTouch {
	switch {
	case s.DHCPURLOnNetwork != nil && *s.DHCPURLOnNetwork:
		return ZTDHCPURL
	case s.TFTPOnNetwork != nil && *s.TFTPOnNetwork:
		return ZTTFTP
	case s.DHCPURLOnNetwork == nil && s.TFTPOnNetwork == nil:
		return ZTUnknown
	}
	return ZTNone
}

// SetZeroTouch records the stated mode.
func (s *Settings) SetZeroTouch(z ZeroTouch) {
	t, f := true, false
	switch z {
	case ZTDHCPURL:
		s.DHCPURLOnNetwork, s.TFTPOnNetwork = &t, &f
	case ZTTFTP:
		s.DHCPURLOnNetwork, s.TFTPOnNetwork = &f, &t
	case ZTNone:
		s.DHCPURLOnNetwork, s.TFTPOnNetwork = &f, &f
	}
}

// Load reads the settings; a missing file is empty settings.
func Load(dir string) Settings {
	var s Settings
	if b, err := os.ReadFile(path(dir)); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

// Save writes the settings (mode 0600) atomically.
func Save(dir string, s Settings) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", " ")
	tmp := path(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(dir))
}

// ErrNone is returned by helpers that find nothing.
var ErrNone = errors.New("none")
