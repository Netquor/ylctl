package dob

import (
	"image"
	"image/color"
	"strings"
	"testing"
)

func solid(w, h int, c color.Color) image.Image {
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.Set(x, y, c)
		}
	}
	return m
}

func TestWhiteAndBlackAndInvert(t *testing.T) {
	w, _ := Convert(solid(8, 4, color.White), Options{Width: 8, Height: 4})
	if h := w.Hex(); len(h) != 32 || strings.Trim(h, "f") != "" {
		t.Fatalf("white must be all f: %q", h)
	}
	b, _ := Convert(solid(8, 4, color.Black), Options{Width: 8, Height: 4})
	if strings.Trim(b.Hex(), "0") != "" {
		t.Fatalf("black must be all 0: %q", b.Hex())
	}
	inv, _ := Convert(solid(8, 4, color.White), Options{Width: 8, Height: 4, Invert: true})
	if strings.Trim(inv.Hex(), "0") != "" {
		t.Fatalf("inverted white must be 0: %q", inv.Hex())
	}
}

func TestOneDigitPerPixelAndFit(t *testing.T) {
	// a wide image on a 192x64 canvas: scaled to the width, centered, rows above and below filled with the background
	m, err := Convert(solid(800, 230, color.Black), Options{Width: 192, Height: 64})
	if err != nil || len(m.Hex()) != 192*64 || m.Width != 192 || m.Height != 64 {
		t.Fatalf("%v %d", err, len(m.Hex()))
	}
	rows := func(y int) string { return m.Hex()[y*192 : (y+1)*192] }
	if strings.Trim(rows(0), "f") != "" || strings.Trim(rows(63), "f") != "" {
		t.Error("the letterbox rows must be background (white = f)")
	}
	if strings.Trim(rows(32), "0") != "" {
		t.Error("the middle row is the image (black = 0)")
	}
}

func TestLevelsAndTransparency(t *testing.T) {
	gray := color.Gray{Y: 128}
	for lv, want := range map[int]string{2: "f", 4: "a", 16: "8"} { // 128/255 = 0.50
		m, err := Convert(solid(4, 4, gray), Options{Width: 4, Height: 4, Levels: lv})
		if err != nil {
			t.Fatal(err)
		}
		got := m.Hex()[0:1]
		if lv == 2 && got != "f" && got != "0" {
			t.Errorf("2 levels: %q", got)
		}
		if lv != 2 && got != want {
			t.Errorf("%d levels: got %q want %q", lv, got, want)
		}
	}
	// fully transparent pixels become the background: white by default, black with Dark
	clear := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	a, _ := Convert(clear, Options{Width: 4, Height: 4})
	b, _ := Convert(clear, Options{Width: 4, Height: 4, Dark: true})
	if strings.Trim(a.Hex(), "f") != "" || strings.Trim(b.Hex(), "0") != "" {
		t.Errorf("transparency: %q %q", a.Hex(), b.Hex())
	}
	// a white logo on transparent shows when composited over black
	wl := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	wl.Set(1, 1, color.NRGBA{255, 255, 255, 255})
	d, _ := Convert(wl, Options{Width: 4, Height: 4, Dark: true})
	if d.Hex()[1*4+1] != 'f' || d.Hex()[0] != '0' {
		t.Errorf("white on dark: %q", d.Hex())
	}
}

func TestRejectsBadInput(t *testing.T) {
	for _, o := range []Options{{Width: 0, Height: 4}, {Width: 4, Height: 2000}, {Width: 4, Height: 4, Levels: 3}} {
		if _, err := Convert(solid(2, 2, color.White), o); err == nil {
			t.Errorf("%+v must be refused", o)
		}
	}
	if _, err := Convert(image.NewRGBA(image.Rect(0, 0, 0, 0)), Options{Width: 4, Height: 4}); err == nil {
		t.Error("empty image")
	}
}

func TestXML(t *testing.T) {
	m, _ := Convert(solid(2, 2, color.White), Options{Width: 2, Height: 2})
	x := MonoXML(m, true)
	for _, want := range []string{"<YealinkIPPhoneImageScreen", `mode="fullscreen"`, `height="2" width="2">ffff</Image>`, "</YealinkIPPhoneImageScreen>"} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q in %s", want, x)
		}
	}
	if c, err := ColorXML("https://pbx/x.png"); err != nil || !strings.Contains(c, ">https://pbx/x.png</Image>") {
		t.Errorf("%v %s", err, c)
	}
	for _, bad := range []string{"ftp://x", "https://x/<a>", "https://x/a&b", ""} {
		if _, err := ColorXML(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if !strings.Contains(m.Preview(), "█") {
		t.Error("preview of a white image shows filled blocks")
	}
}

func TestCustomXML(t *testing.T) {
	x, err := CustomXML(CustomOptions{Lines: []string{"A & B"}, Clock: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"<YealinkIPPhoneCustomScreenSaver", "<SystemTime", ">A &amp; B</Line>"} {
		if !strings.Contains(x, w) {
			t.Fatalf("missing %q in %s", w, x)
		}
	}
	if _, err := CustomXML(CustomOptions{}); err == nil {
		t.Fatal("empty document accepted")
	}
	if _, err := CustomXML(CustomOptions{ImageURL: "ftp://x"}); err == nil {
		t.Fatal("bad image URL accepted")
	}
}

func TestDOBLayout(t *testing.T) {
	m := Image{Width: 4, Height: 1, Levels: 16, Pix: []uint8{15, 0, 8, 1}}
	b, err := m.DOB(true)
	if err != nil {
		t.Fatal(err)
	}
	// header 4,1 then (pixel1 high | pixel0 low), with black = high: bright 15 -> 0, bright 0 -> 15
	want := []byte{4, 1, 0xF0, 0xE7}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("byte %d = %#x, want %#x (all %x)", i, b[i], want[i], b)
		}
	}
	if _, err := (Image{Width: 300, Height: 1, Levels: 2, Pix: make([]uint8, 300)}).DOB(false); err == nil {
		t.Fatal("width over 255 accepted")
	}
}
