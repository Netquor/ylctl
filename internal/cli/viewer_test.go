package cli

import (
	"strings"
	"testing"
)

func TestWrapANSIKeepsEscapesAndWidth(t *testing.T) {
	got := wrapANSI("\x1b[1;36mabcdefghij\x1b[0m klmno", 10)
	if len(got) != 2 {
		t.Fatalf("%q", got)
	}
	if !strings.HasPrefix(got[0], "\x1b[1;36m") || !strings.Contains(got[0], "abcdefghij") {
		t.Errorf("escapes must take no width: %q", got[0])
	}
	if lines := wrapANSI("a\n\nb\n", 20); len(lines) != 3 || lines[1] != "" {
		t.Errorf("blank lines kept: %q", lines)
	}
	if lines := wrapANSI("tab\there", 20); strings.Contains(lines[0], "\t") {
		t.Error("tabs become spaces")
	}
	_ = wrapANSI("", 0) // must not panic on tiny widths
}

func TestViewerScrollAndKeys(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("line\n")
	}
	v := newViewer(sb.String(), 40, 11) // 10 text rows
	if v.maxTop() != 20 {
		t.Fatalf("maxTop %d", v.maxTop())
	}
	for _, c := range []struct {
		key  string
		want int
	}{{"j", 1}, {"j", 2}, {"k", 1}, {"\x1b[B", 2}, {"\x1b[A", 1}, {" ", 10}, {"b", 1}, {"G", 20}, {"j", 20}, {"g", 0}, {"k", 0}, {"\x1b[6~", 9}, {"\x1b[F", 20}, {"\x1b[H", 0}} {
		if v.Key([]byte(c.key)); v.top != c.want {
			t.Errorf("after %q top=%d, want %d", c.key, v.top, c.want)
		}
	}
	if v.Key([]byte("q")) != viewQuit || v.Key([]byte{3}) != viewQuit || v.Key([]byte("\x1b")) != viewQuit {
		t.Error("q, Ctrl-C and Esc close")
	}
	if v.Key([]byte("p")) != viewPrint {
		t.Error("p keeps the text on screen")
	}
	if v.Key(nil) != viewNone || v.Key([]byte("\x1b[Z")) != viewNone {
		t.Error("unknown keys do nothing")
	}
	out := v.Render("ylctl help")
	if !strings.Contains(out, "q close") || strings.Count(out, "\r\n") != v.height {
		t.Errorf("render: %d rows", strings.Count(out, "\r\n"))
	}
	// a narrow terminal still shows how to close
	if n := newViewer("x\n", 12, 5); !strings.Contains(n.Render("ylctl recon"), "q close") {
		t.Error("q close must survive a narrow terminal")
	}
	// a short text never scrolls
	s := newViewer("one\ntwo\n", 40, 20)
	s.Key([]byte("j"))
	if s.top != 0 {
		t.Error("short text must not scroll")
	}
}
