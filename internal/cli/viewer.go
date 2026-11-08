package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"
)

// A viewer shows text on the terminal's alternate screen, like less or man: when it
// closes, the terminal is restored exactly as it was, so a long help leaves nothing
// behind but the command that was typed. It is only used on a terminal; pipes and
// scripts get the plain text.

const (
	altOn  = "\x1b[?1049h"
	altOff = "\x1b[?1049l"
)

type viewer struct {
	lines  []string
	top    int
	height int // visible text rows
	width  int
}

type viewAction int

const (
	viewNone viewAction = iota
	viewQuit
	viewPrint // close, then print the text into the normal scrollback
)

// wrapANSI splits text into lines no wider than width visible cells. Escape sequences take no width.
func wrapANSI(text string, width int) []string {
	if width < 10 {
		width = 10
	}
	var out []string
	for _, raw := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		raw = strings.TrimRight(raw, "\r")
		var cur strings.Builder
		cells := 0
		inEsc := false
		for _, r := range raw {
			switch {
			case inEsc:
				cur.WriteRune(r)
				if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
					inEsc = false
				}
				continue
			case r == 0x1b:
				inEsc = true
				cur.WriteRune(r)
				continue
			case r == '\t':
				r = ' '
			}
			if cells >= width {
				out = append(out, cur.String()+"\x1b[0m")
				cur.Reset()
				cells = 0
			}
			cur.WriteRune(r)
			cells++
		}
		out = append(out, cur.String())
	}
	return out
}

func newViewer(text string, width, height int) *viewer {
	v := &viewer{width: width, height: height - 1}
	if v.height < 3 {
		v.height = 3
	}
	v.lines = wrapANSI(text, width)
	return v
}

func (v *viewer) maxTop() int {
	m := len(v.lines) - v.height
	if m < 0 {
		return 0
	}
	return m
}

func (v *viewer) scroll(d int) {
	v.top += d
	if v.top < 0 {
		v.top = 0
	}
	if v.top > v.maxTop() {
		v.top = v.maxTop()
	}
}

// resize keeps the same place while changing the size.
func (v *viewer) resize(text string, width, height int) {
	top := v.top
	*v = *newViewer(text, width, height)
	v.top = top
	v.scroll(0)
}

// Key handles the bytes of one key press.
func (v *viewer) Key(b []byte) viewAction {
	if len(b) == 0 {
		return viewNone
	}
	if b[0] == 0x1b {
		switch string(b) {
		case "\x1b[A":
			v.scroll(-1)
		case "\x1b[B":
			v.scroll(1)
		case "\x1b[5~":
			v.scroll(-(v.height - 1))
		case "\x1b[6~":
			v.scroll(v.height - 1)
		case "\x1b[H", "\x1b[1~":
			v.top = 0
		case "\x1b[F", "\x1b[4~":
			v.top = v.maxTop()
		case "\x1b":
			return viewQuit
		}
		return viewNone
	}
	switch b[0] {
	case 'q', 'Q', 3, 4:
		return viewQuit
	case 'p', 'P':
		return viewPrint
	case 'j', '\r', '\n':
		v.scroll(1)
	case 'k':
		v.scroll(-1)
	case ' ', 'f':
		v.scroll(v.height - 1)
	case 'b':
		v.scroll(-(v.height - 1))
	case 'g':
		v.top = 0
	case 'G':
		v.top = v.maxTop()
	case 'd':
		v.scroll(v.height / 2)
	case 'u':
		v.scroll(-v.height / 2)
	}
	return viewNone
}

// Render draws the visible window and a status line.
func (v *viewer) Render(title string) string {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J")
	for i := 0; i < v.height; i++ {
		if v.top+i < len(v.lines) {
			b.WriteString(v.lines[v.top+i])
		}
		b.WriteString("\x1b[0m\r\n")
	}
	pct := 100
	if m := v.maxTop(); m > 0 {
		pct = v.top * 100 / m
	}
	// the longest hint that fits; "q close" is always kept
	var status string
	for _, c := range []string{
		fmt.Sprintf(" %s · ↑/↓ j/k scroll · space/b page · g/G top/end · p keep on screen · q close · %d%% ", title, pct),
		fmt.Sprintf(" %s · j/k scroll · p keep · q close · %d%% ", title, pct),
		fmt.Sprintf(" j/k scroll · p keep · q close "),
		" p keep · q close ",
		" q close ",
	} {
		status = c
		if len([]rune(c)) <= v.width {
			break
		}
	}
	if rs := []rune(status); len(rs) > v.width {
		status = string(rs[:v.width])
	}
	b.WriteString("\x1b[7m" + status + strings.Repeat(" ", max(0, v.width-len([]rune(status)))) + "\x1b[0m")
	return b.String()
}

// show runs the viewer. It returns true when the user asked to keep the text on screen.
func (a *app) showInViewer(title, text string) (keep bool) {
	f, ok := a.env.Stdout.(*os.File)
	if !ok {
		return true
	}
	fd := int(os.Stdin.Fd())
	st, err := term.MakeRaw(fd)
	if err != nil {
		return true
	}
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil || w < 20 || h < 5 {
		term.Restore(fd, st)
		return true
	}
	fmt.Fprint(f, altOn+"\x1b[?25l")
	defer func() {
		fmt.Fprint(f, "\x1b[?25h"+altOff)
		term.Restore(fd, st)
	}()
	v := newViewer(text, w, h)
	fmt.Fprint(f, v.Render(title))
	winch := make(chan os.Signal, 1)
	if sigwinch != nil {
		signal.Notify(winch, sigwinch)
	}
	defer signal.Stop(winch)
	keys := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 16)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(keys)
				return
			}
			keys <- append([]byte(nil), buf[:n]...)
		}
	}()
	for {
		select {
		case <-winch:
			if nw, nh, err := term.GetSize(int(f.Fd())); err == nil && nw >= 20 && nh >= 5 {
				v.resize(text, nw, nh)
			}
			fmt.Fprint(f, v.Render(title))
		case k, ok := <-keys:
			if !ok {
				return false
			}
			switch v.Key(k) {
			case viewQuit:
				return false
			case viewPrint:
				return true
			}
			fmt.Fprint(f, v.Render(title))
		}
	}
}

// helpToViewer reports whether help should open in the viewer: a person at a terminal, not turned off.
func (a *app) helpToViewer() bool {
	return a.isInteractive() && a.env.Getenv("YLCTL_NO_VIEWER") == "" && a.env.Getenv("TERM") != "dumb"
}
