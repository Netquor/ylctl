package recon

import (
	"fmt"
	"strings"
)

// Picker is a multi-select list driven by key presses: arrows or j/k move,
// space toggles, a selects all, n selects none, Enter confirms, q cancels.
type Picker struct {
	Items    []string
	Cursor   int
	Selected map[int]bool
	Done     bool
	Canceled bool
}

// NewPicker starts with the given indexes selected.
func NewPicker(items []string, preselect ...int) *Picker {
	p := &Picker{Items: items, Selected: map[int]bool{}}
	for _, i := range preselect {
		if i >= 0 && i < len(items) {
			p.Selected[i] = true
		}
	}
	return p
}

// Key feeds the bytes of one key press (an arrow arrives as ESC [ A).
func (p *Picker) Key(b []byte) {
	if len(b) == 0 || p.Done {
		return
	}
	if len(b) >= 3 && b[0] == 27 && b[1] == '[' {
		switch b[2] {
		case 'A':
			p.move(-1)
		case 'B':
			p.move(1)
		}
		return
	}
	switch b[0] {
	case 'k':
		p.move(-1)
	case 'j':
		p.move(1)
	case ' ':
		p.Selected[p.Cursor] = !p.Selected[p.Cursor]
	case 'a', 'A':
		for i := range p.Items {
			p.Selected[i] = true
		}
	case 'n', 'N':
		p.Selected = map[int]bool{}
	case '\r', '\n':
		p.Done = true
	case 'q', 'Q', 3, 27:
		p.Canceled, p.Done = true, true
	}
}

func (p *Picker) move(d int) {
	if len(p.Items) == 0 {
		return
	}
	p.Cursor = (p.Cursor + d + len(p.Items)) % len(p.Items)
}

// Chosen returns the selected indexes in order.
func (p *Picker) Chosen() []int {
	var out []int
	for i := range p.Items {
		if p.Selected[i] {
			out = append(out, i)
		}
	}
	return out
}

// Render draws the list; color wraps a string with an ANSI code (identity when colors are off).
func (p *Picker) Render(title string, color func(code, s string) string) string {
	var b strings.Builder
	b.WriteString(color("1;36", title) + "\n")
	for i, it := range p.Items {
		box := "[ ]"
		if p.Selected[i] {
			box = color("1;32", "[x]")
		}
		line := fmt.Sprintf(" %s %s", box, it)
		if i == p.Cursor {
			line = color("7", fmt.Sprintf(" %s %s ", "▸", strings.TrimPrefix(line, " ")))
		}
		b.WriteString(line + "\n")
	}
	b.WriteString(color("2", " space select · a all · n none · ↑/↓ move · enter confirm · q cancel") + "\n")
	return b.String()
}
