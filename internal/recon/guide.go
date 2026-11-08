package recon

// ResetGuide is how to factory-reset a phone of one vendor so it accepts the
// factory login again. Steps are REPORTED from vendor documentation, not
// verified on every model; the first line says so.
type ResetGuide struct {
	Vendor string
	Steps  []string
}

var guides = map[string]ResetGuide{
	"yealink": {"Yealink", []string{
		"On the idle screen press and HOLD the OK key for about 10 seconds, then confirm 'Reset to factory'.",
		"Or: Menu > Settings > Advanced Settings (default admin password) > Reset Config > Reset to Factory.",
		"The phone restarts by itself; wait until it shows the date. The factory web login is admin / admin.",
		"This erases its accounts and settings. If DHCP option 66 or a provisioning server is set, it will fetch its configuration again after the restart.",
	}},
	"polycom": {"Polycom / Poly", []string{
		"Hold the 1, 3, 5 and 7 keys while powering the phone on (older VVX), or Settings > Advanced (default 456) > Administration Settings > Reset to Factory.",
	}},
	"cisco": {"Cisco", []string{
		"Hold # while powering up and, when the lights flash, press 123456789*0#. Or Settings > Factory Reset on newer models.",
	}},
	"grandstream": {"Grandstream", []string{
		"Menu > Settings > Factory Reset on the phone, or hold the reset pinhole for 10 seconds while powered.",
	}},
	"fanvil": {"Fanvil", []string{
		"Menu > Settings > Factory Reset, or hold the OK / Cancel key while powering up.",
	}},
}

// GuideFor returns the guide for a vendor name (case-insensitive), or the generic one.
func GuideFor(vendor string) ResetGuide {
	if g, ok := guides[lower(vendor)]; ok {
		return g
	}
	return ResetGuide{Vendor: vendor, Steps: []string{"Look up 'factory reset' for this model in the maker's guide: most phones have it under Menu > Settings > Factory Reset, or a long press of a key while powering up."}}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
