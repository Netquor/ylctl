package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/term"
)

// crlfWriter turns \n into \r\n while the terminal is in raw mode.
type crlfWriter struct{ w io.Writer }

func (c crlfWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	for _, b := range p {
		if b == '\n' {
			out = append(out, '\r')
		}
		out = append(out, b)
	}
	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// liveKeys puts the terminal in raw mode and returns a channel of key presses.
// It does nothing (nil channel) when there is no person at a terminal.
// Ctrl-C is delivered as the byte 3, because raw mode turns off the signal.
func (a *app) liveKeys() (<-chan byte, func()) {
	if !a.isInteractive() {
		return nil, func() {}
	}
	fd := int(os.Stdin.Fd())
	st, err := term.MakeRaw(fd)
	if err != nil {
		return nil, func() {}
	}
	a.crlf = true
	a.pinBar()
	ch := make(chan byte, 8)
	go func() {
		buf := make([]byte, 8)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(ch)
				return
			}
			if n == 1 || buf[0] != 27 { // ignore escape sequences such as arrow keys
				select {
				case ch <- buf[0]:
				default:
				}
			}
		}
	}()
	// keep the bar right when the window is resized
	winch := make(chan os.Signal, 1)
	if sigwinch != nil {
		signal.Notify(winch, sigwinch)
	}
	go func() {
		for range winch {
			a.pinBar()
		}
	}()
	return ch, func() {
		signal.Stop(winch)
		a.unpinBar()
		term.Restore(fd, st)
		a.crlf = false
	}
}

// saver writes to a file that the user can turn on and off with the s key.
type saver struct {
	a     *app
	kind  string
	host  string
	file  *os.File
	name  string
	count int
}

func (s *saver) toggle(onStart func(f *os.File) error) {
	if s.file != nil {
		s.file.Close()
		fmt.Fprintf(s.a.errw(), "%s saved %d %s to %s\n", s.a.color("1;32", "[stop]"), s.count, "records", s.name)
		s.file, s.count = nil, 0
		return
	}
	s.name = fmt.Sprintf("ylctl-%s-%s-%s.log", s.kind, safeName(s.host), time.Now().Format("20060102-150405"))
	if s.kind == "capture" {
		s.name = s.name[:len(s.name)-4] + ".pcap"
	}
	f, err := os.OpenFile(s.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(s.a.errw(), "%s cannot create %s: %v\n", s.a.color("1;31", "[save]"), s.name, err)
		return
	}
	if onStart != nil {
		if err := onStart(f); err != nil {
			f.Close()
			fmt.Fprintf(s.a.errw(), "%s %v\n", s.a.color("1;31", "[save]"), err)
			return
		}
	}
	s.file = f
	fmt.Fprintf(s.a.errw(), "%s saving to %s (press s again to stop)\n", s.a.color("1;32", "[save]"), s.name)
}

func (s *saver) close() {
	if s.file != nil {
		s.file.Close()
		fmt.Fprintf(s.a.errw(), "saved %d records to %s\n", s.count, s.name)
		s.file = nil
	}
}

func safeName(h string) string {
	b := []byte(h)
	for i, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-') {
			b[i] = '_'
		}
	}
	return string(b)
}

const keyHelp = " q quit  |  s save to file on/off  |  c clear  |  ? help "

var barMu sync.Mutex

// pinBar reserves the bottom terminal row for the key hint: output scrolls in
// the rows above it. Safe to call again after a resize or a screen clear.
func (a *app) pinBar() {
	f, ok := a.env.Stdout.(*os.File)
	if !ok {
		return
	}
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil || h < 4 || w < 20 {
		return
	}
	barMu.Lock()
	defer barMu.Unlock()
	a.barRows = h
	text := keyHelp
	if len(text) > w {
		text = text[:w]
	}
	text += spaces(w - len(text))
	// set scroll region to rows 1..h-1, draw the bar on row h in reverse video, put the cursor back
	fmt.Fprintf(f, "\x1b7\x1b[1;%dr\x1b[%d;1H\x1b[7m%s\x1b[0m\x1b8", h-1, h, text)
	if a.firstPin {
		return
	}
	a.firstPin = true
	fmt.Fprintf(f, "\x1b[%d;1H", h-1) // start output just above the bar
}

// unpinBar gives the whole screen back.
func (a *app) unpinBar() {
	f, ok := a.env.Stdout.(*os.File)
	if !ok || a.barRows == 0 {
		return
	}
	barMu.Lock()
	defer barMu.Unlock()
	fmt.Fprintf(f, "\x1b[r\x1b[%d;1H\x1b[2K\r\n", a.barRows)
	a.barRows = 0
	a.firstPin = false
}

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

// clearScreen clears the scrolling area and redraws the bar.
func (a *app) clearScreen() {
	fmt.Fprint(a.out(), "\x1b[2J\x1b[H")
	a.pinBar()
}

func (a *app) showKeyHelp() { a.pinBar() }
