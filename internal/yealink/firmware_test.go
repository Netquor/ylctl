package yealink

import (
	"strings"
	"testing"
)

func romBytes(model, version string) []byte {
	b := make([]byte, 0x100)
	copy(b[0x24:], model)
	copy(b[0x44:], version)
	return b
}

func TestParseROMHeader(t *testing.T) {
	h, err := ParseROMHeader(romBytes("T46S", "66.86.0.180"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Model != "T46S" || h.Version != "66.86.0.180" || h.Size != 0x100 {
		t.Fatalf("got %+v", h)
	}
}

func TestParseROMHeaderRejects(t *testing.T) {
	cases := map[string][]byte{
		"too short":  make([]byte, 10),
		"no version": romBytes("T46S", "not-a-version"),
		"no model":   romBytes("", "66.86.0.180"),
		"too large":  make([]byte, FirmwareMaxSize+1),
	}
	for name, b := range cases {
		if _, err := ParseROMHeader(b); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := ParseROMHeader(romBytes("T46S", "x")); err == nil || !strings.Contains(err.Error(), "firmware version") {
		t.Errorf("want a version error, got %v", err)
	}
}
