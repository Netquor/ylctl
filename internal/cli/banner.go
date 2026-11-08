package cli

import (
	"fmt"
	"os"
	"strings"
)

const credit = "by Jay Peters @ Netquor Technologies  -  www.netquor.com"

// phoneArt is a desk phone in the style of a Yealink T4 series; the figlet
// text sits to its right. Each row is padded to the same width before use.
var phoneArt = []string{
	`    .--------------------------.`,
	`   /  .--------------------.    \`,
	`  |   | ylctl         [ok] |  ==|`,
	`  |   | > discover  capture|    |`,
	`  |   | > logs      status |    |`,
	`  |   '--------------------'    |`,
	`  |    (o)(o)(o)(o)   [ ^ ]     |`,
	`  |    [1][2][3]    <( OK )>    |`,
	`  |    [4][5][6]      [ v ]     |`,
	`  |    [7][8][9]                |`,
	`  |    [*][0][#]   (( ))(( ))   |`,
	`   \____________________________/`,
}

var figletArt = []string{
	``,
	``,
	`          _      _   _ `,
	`    _   _| | ___| |_| |`,
	`   | | | | |/ __| __| |`,
	`   | |_| | | (__| |_| |`,
	`    \__, |_|\___|\__|_|`,
	`    |___/              `,
}

var gradient = []string{"1;96", "1;36", "1;94", "1;34", "1;95", "1;35"}

// banner prints the phone and the name. Colors only appear on a terminal.
func (a *app) banner() { a.bannerTo(func(s string) { fmt.Fprint(a.out(), s) }) }

// bannerTo writes the banner through put (so raw-mode terminals get \r\n).
func (a *app) bannerTo(put func(string)) {
	colorOn := false
	if f, ok := a.env.Stdout.(*os.File); ok && isTTY(f) && !a.noColor && a.env.Getenv("NO_COLOR") == "" {
		colorOn = true
	}
	paint := func(code, s string) string {
		if !colorOn {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	put("\n")
	for i, p := range phoneArt {
		// colour the screen cyan, the keys dim, the body blue
		var line string
		switch {
		case i >= 1 && i <= 5:
			line = paint("94", p[:min(len(p), 6)]) + paint("36", p[min(len(p), 6):min(len(p), 28)]) + paint("94", p[min(len(p), 28):])
		case i >= 6 && i <= 10:
			line = paint("94", p[:min(len(p), 6)]) + paint("2", p[min(len(p), 6):min(len(p), 32)]) + paint("94", p[min(len(p), 32):])
		default:
			line = paint("94", p)
		}
		pad := strings.Repeat(" ", max(0, 36-len(p)))
		right := ""
		if i < len(figletArt) {
			right = paint(gradient[i%len(gradient)], figletArt[i])
		}
		if i == 9 {
			right = paint("2", "   drive Yealink phones from a terminal")
		}
		if i == 10 {
			right = paint("2", "   "+credit)
		}
		put(line + pad + right + "\n")
	}
	put("\n")
}
