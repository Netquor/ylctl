package cli

import "testing"

func TestSubcommandName(t *testing.T) {
	for in, want := range map[string][]string{
		"info":           {"--trust-new", "--mac", "80:5e:c0:00:00:0b", "info", "10.0.0.5"},
		"capture follow": {"capture", "follow", "10.0.0.5", "--filter", "tls"},
		"status":         {"status", "10.0.0.5"},
		"":               {"--json"},
	} {
		if got := subcommandName(want); got != in && !(in == "info" && got == "info 10.0.0.5") && !(in == "status" && got == "status 10.0.0.5") {
			t.Errorf("%v -> %q", want, got)
		}
	}
}
