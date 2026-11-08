package syslog

import (
	"testing"
	"time"
)

func TestParse3164(t *testing.T) {
	m := Parse([]byte("<134>Nov  7 04:55:01 T41S sip[123]: [SIP] REGISTER sent"), "10.0.0.5", time.Time{})
	if m.Severity != 6 || m.Facility != 16 || m.Tag != "sip" || m.Text != "[SIP] REGISTER sent" || m.Host != "T41S" {
		t.Fatalf("%+v", m)
	}
}

func TestParse5424(t *testing.T) {
	m := Parse([]byte("<11>1 2026-11-07T04:55:01Z phone ylapp 77 ID1 - hello world"), "x", time.Time{})
	if m.Severity != 3 || m.Tag != "ylapp" || m.Text != "hello world" {
		t.Fatalf("%+v", m)
	}
}

func TestParseGarbage(t *testing.T) {
	for _, in := range []string{"", "<", "<999>x", "<13>", "\xff\xfe<13>\x00\x01", "<13>1 a b", "<13>Nov  7 04:55:01", string(make([]byte, 9000))} {
		m := Parse([]byte(in), "x", time.Time{})
		if m.SeverityName() == "" {
			t.Fatal("no severity name")
		}
	}
}

func TestModuleFromPhoneText(t *testing.T) {
	m := Parse([]byte("<133>[580.586: SYS <5+notice> backup syslog.level=6"), "x", time.Time{})
	if m.Module != "SYS" || m.Key() != "SYS" {
		t.Fatalf("%+v", m)
	}
	m = Parse([]byte("<134>Nov  7 04:55:01 T41S sip[1]: hello"), "x", time.Time{})
	if m.Module != "" || m.Key() != "sip" {
		t.Fatalf("%+v", m)
	}
}

func TestModuleShapes(t *testing.T) {
	for in, want := range map[string]string{
		"<133>[580.586: SYS <5+notice> backup":  "SYS",
		"<133>IPVP<5+notice> 518.606.565:Msg":   "IPVP",
		"<134>[758:758: UIMG<6+info  > 518.905": "UIMG",
		"<134>just some words":                  "",
	} {
		if got := Parse([]byte(in), "x", time.Time{}).Module; got != want {
			t.Errorf("%q: module %q, want %q", in, got, want)
		}
	}
}
