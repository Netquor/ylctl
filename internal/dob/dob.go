// Package dob converts an image into what Yealink's XML browser wants for an ImageScreen on the phones with
// small monochrome or grayscale screens (T41S, T42S, T43U, T40, T31, T30, T27, T23, T21, T19 and CP860/CP920):
// the picture as a string of hexadecimal characters inside the XML, one character per pixel, row by row, from
// the top left. The maker's guide calls this a "dob" string and ships a Windows tool for it; this package makes
// the same kind of string without that tool.
//
// What is documented (Yealink XML Browser Developer's Guide, ImageScreen object): the image is a series of
// hexadecimal characters, the XML carries its width and height, and the guide's own example for an 8x12 image
// has 96 characters (one per pixel) using the digits 0, 5, a and f. What is NOT documented, and so is exposed as
// options to try on a real phone: which end of the scale is dark (Invert), and how many gray levels the screen
// distinguishes (Levels: 2, 4 or 16).
package dob

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"strings"
)

// Options controls the conversion.
type Options struct {
	Width, Height int     // the target canvas, in pixels (the screen size, or smaller)
	Levels        int     // gray levels: 2, 4 or 16 (default 16)
	Invert        bool    // swap which end of the scale is dark
	Dark          bool    // composite transparency over black instead of white (for white-on-transparent logos)
	Threshold     bool    // with Levels 2: hard threshold at the middle instead of nearest level (same thing; kept for clarity)
	Sharpen       float64 // unsharp mask strength after scaling (0 = off, 0.5 to 2 is useful for small pictures)
	Gamma         float64 // brightness curve (1 = unchanged; above 1 darkens midtones, below 1 lightens them); 0 = unchanged
	Contrast      bool    // stretch the brightness range to use the whole scale
	Pool          string  // "max": each pixel takes the brightest source pixel of its block, so thin strokes stay solid instead of fading to gray; default is the average
	Cut           float64 // with Levels 2: brightness 0..1 at or above which a pixel is lit (0 = the middle); a low value fills in thin strokes
	Bold          int     // thicken lit areas by this many pixels (each step adds one pixel all round)
	Dither        string  // "", "fs" (Floyd-Steinberg), "atkinson" or "bayer": spread rounding error so grays become fine dots
}

// Image is a converted picture.
type Image struct {
	Width, Height int
	Pix           []uint8 // one value 0..Levels-1 per pixel, row-major
	Levels        int
}

// Convert scales img to fit inside the canvas (keeping its aspect ratio, centered, never enlarged beyond the
// canvas) and quantizes it to the requested gray levels.
func Convert(img image.Image, o Options) (Image, error) {
	if o.Width < 1 || o.Height < 1 || o.Width > 1024 || o.Height > 1024 {
		return Image{}, fmt.Errorf("canvas must be 1 to 1024 pixels each way")
	}
	if o.Levels == 0 {
		o.Levels = 16
	}
	if o.Levels != 2 && o.Levels != 4 && o.Levels != 16 {
		return Image{}, fmt.Errorf("levels must be 2, 4 or 16")
	}
	b := img.Bounds()
	if b.Dx() < 1 || b.Dy() < 1 {
		return Image{}, fmt.Errorf("empty image")
	}
	// target size inside the canvas
	tw, th := o.Width, o.Height
	if b.Dx()*o.Height > b.Dy()*o.Width { // wider than the canvas aspect: fit to width
		th = (b.Dy()*o.Width + b.Dx()/2) / b.Dx()
	} else {
		tw = (b.Dx()*o.Height + b.Dy()/2) / b.Dy()
	}
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	if tw > o.Width {
		tw = o.Width
	}
	if th > o.Height {
		th = o.Height
	}
	ox, oy := (o.Width-tw)/2, (o.Height-th)/2
	bg := 1.0 // white
	if o.Dark {
		bg = 0.0
	}
	out := Image{Width: o.Width, Height: o.Height, Levels: o.Levels, Pix: make([]uint8, o.Width*o.Height)}
	// brightness 0..1 of every canvas pixel (background outside the scaled picture)
	g := make([]float64, o.Width*o.Height)
	for i := range g {
		g[i] = bg
	}
	for y := 0; y < th; y++ {
		sy0 := b.Min.Y + y*b.Dy()/th
		sy1 := b.Min.Y + (y+1)*b.Dy()/th
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for x := 0; x < tw; x++ {
			sx0 := b.Min.X + x*b.Dx()/tw
			sx1 := b.Min.X + (x+1)*b.Dx()/tw
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var sum, mx float64
			n := 0
			for sy := sy0; sy < sy1; sy++ {
				for sx := sx0; sx < sx1; sx++ {
					l := lum(img.At(sx, sy), bg)
					sum += l
					if l > mx {
						mx = l
					}
					n++
				}
			}
			if o.Pool == "max" {
				g[(oy+y)*o.Width+ox+x] = mx
			} else {
				g[(oy+y)*o.Width+ox+x] = sum / float64(n)
			}
		}
	}
	if o.Sharpen > 0 {
		g = unsharp(g, o.Width, o.Height, o.Sharpen)
	}
	if o.Contrast {
		lo, hi := 1.0, 0.0
		for _, v := range g {
			if v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
		}
		if hi-lo > 0.05 {
			for i, v := range g {
				g[i] = (v - lo) / (hi - lo)
			}
		}
	}
	if o.Gamma > 0 && o.Gamma != 1 {
		for i, v := range g {
			if v < 0 {
				v = 0
			}
			g[i] = math.Pow(v, o.Gamma)
		}
	}
	for k := 0; k < o.Bold; k++ {
		g = dilate(g, o.Width, o.Height)
	}
	if o.Cut > 0 && o.Levels == 2 {
		for i, v := range g {
			if v >= o.Cut {
				g[i] = 1
			} else {
				g[i] = 0
			}
		}
	}
	top := float64(o.Levels - 1)
	finish := func(q int) uint8 {
		if q < 0 {
			q = 0
		}
		if q > int(top) {
			q = int(top)
		}
		if o.Invert {
			q = int(top) - q
		}
		return uint8(q)
	}
	switch o.Dither {
	case "", "none":
		for i, v := range g {
			out.Pix[i] = finish(int(clamp01(v)*top + 0.5))
		}
	case "fs", "atkinson":
		w, h := o.Width, o.Height
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				i := y*w + x
				v := clamp01(g[i])
				q := math.Round(v * top)
				e := v - q/top
				out.Pix[i] = finish(int(q))
				add := func(dx, dy int, f float64) {
					xx, yy := x+dx, y+dy
					if xx >= 0 && xx < w && yy < h {
						g[yy*w+xx] += e * f
					}
				}
				if o.Dither == "fs" {
					add(1, 0, 7.0/16)
					add(-1, 1, 3.0/16)
					add(0, 1, 5.0/16)
					add(1, 1, 1.0/16)
				} else { // Atkinson spreads only 6/8 of the error: crisper, higher contrast
					for _, d := range [][2]int{{1, 0}, {2, 0}, {-1, 1}, {0, 1}, {1, 1}, {0, 2}} {
						add(d[0], d[1], 1.0/8)
					}
				}
			}
		}
	case "bayer":
		m := [4][4]float64{{0, 8, 2, 10}, {12, 4, 14, 6}, {3, 11, 1, 9}, {15, 7, 13, 5}}
		for y := 0; y < o.Height; y++ {
			for x := 0; x < o.Width; x++ {
				v := clamp01(g[y*o.Width+x]) * top
				base := math.Floor(v)
				frac := v - base
				q := base
				if frac > (m[y%4][x%4]+0.5)/16 {
					q++
				}
				out.Pix[y*o.Width+x] = finish(int(q))
			}
		}
	default:
		return Image{}, fmt.Errorf("dither must be fs, atkinson or bayer")
	}
	return out, nil
}

// lum is the brightness 0..1 of a pixel after laying it over the background (transparency becomes background).
func lum(c color.Color, bg float64) float64 {
	r, g, b, a := c.RGBA()
	af := float64(a) / 65535
	if af == 0 {
		return bg
	}
	// un-premultiply, then Rec. 601 luma
	rr, gg, bb := float64(r)/float64(a), float64(g)/float64(a), float64(b)/float64(a)
	y := 0.299*rr + 0.587*gg + 0.114*bb
	return y*af + bg*(1-af)
}

// Hex returns the picture as the hexadecimal string: one digit per pixel, row by row. With 16 levels each digit
// is the level; with 4 or 2 levels the level is spread over 0..f (0, 5, a, f and 0, f).
func (m Image) Hex() string {
	var sb strings.Builder
	sb.Grow(len(m.Pix))
	for _, p := range m.Pix {
		v := int(p)
		switch m.Levels {
		case 2:
			v *= 15
		case 4:
			v *= 5
		}
		sb.WriteByte("0123456789abcdef"[v&15])
	}
	return sb.String()
}

// Preview draws the picture with block shades for a terminal, two pixel rows per line.
func (m Image) Preview() string {
	shades := []rune{' ', '░', '▒', '▓', '█'}
	top := m.Levels - 1
	var sb strings.Builder
	for y := 0; y < m.Height; y += 2 {
		for x := 0; x < m.Width; x++ {
			a := int(m.Pix[y*m.Width+x])
			bb := a
			if y+1 < m.Height {
				bb = int(m.Pix[(y+1)*m.Width+x])
			}
			// brightness here is the level itself: higher = brighter. Show bright as a filled block.
			v := (a + bb) * 4 / (2 * top)
			if v > 4 {
				v = 4
			}
			sb.WriteRune(shades[v])
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// MonoXML is the ImageScreen document for the small-screen phones: the picture inline as hex.
func MonoXML(m Image, fullscreen bool) string {
	mode := "regular"
	if fullscreen {
		mode = "fullscreen"
	}
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"+
		"<YealinkIPPhoneImageScreen Beep=\"no\" Timeout=\"0\" LockIn=\"no\" mode=\"%s\">\n"+
		"  <Image horizontalAlign=\"middle\" verticalAlign=\"middle\" height=\"%d\" width=\"%d\">%s</Image>\n"+
		"</YealinkIPPhoneImageScreen>\n", mode, m.Height, m.Width, m.Hex())
}

// ColorXML is the ImageScreen document for the color-screen phones (T46U/T46G/T48/T54W/T58A/T57W/T29G/T33...):
// the picture is a jpg, jpeg, bmp or png at a URL the phone can download.
func ColorXML(imageURL string) (string, error) {
	if !strings.HasPrefix(imageURL, "https://") && !strings.HasPrefix(imageURL, "http://") {
		return "", fmt.Errorf("the image URL must start with https:// or http://")
	}
	if strings.ContainsAny(imageURL, "<>\"&\r\n") {
		return "", fmt.Errorf("the image URL contains characters that need escaping")
	}
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"+
		"<YealinkIPPhoneImageScreen Beep=\"no\" Timeout=\"0\" LockIn=\"no\" mode=\"fullscreen\">\n"+
		"  <Image horizontalAlign=\"middle\" verticalAlign=\"middle\">%s</Image>\n"+
		"</YealinkIPPhoneImageScreen>\n", imageURL), nil
}

// CustomOptions describes a screensaver document in Yealink's screensaver schema (the one the phone's Preference
// page "XML Screensaver URL" loads; it is not one of the XML Browser objects).
type CustomOptions struct {
	Lines       []string // text lines, top to bottom
	Clock       bool     // show the time and date
	StatusIcons bool     // show the status icons
	ImageURL    string   // color phones: an image the phone downloads
	LineSpacing int      // 0 = leave the default (2)
}

// CustomXML builds the screensaver document. Verified on a T41S (firmware 66.86): the elements and attributes
// below are accepted and the text shows. The allowed attribute values are not listed on Yealink's page, so the
// ones used here (size normal/large, align center, color white) are the ones that were tried on that phone.
// Attribute names must be capitalized (Size, Align, Color, HorizontalAlign, VerticalAlign): on the T41S the
// lowercase spellings were silently ignored (text stayed at the left) and the capitalized ones were honored.
func CustomXML(o CustomOptions) (string, error) {
	var sb strings.Builder
	sp := o.LineSpacing
	if sp == 0 {
		sp = 2
	}
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	fmt.Fprintf(&sb, "<YealinkIPPhoneCustomScreenSaver LineSpacing=\"%d\" InsertImageLineNum=\"0\">\n", sp)
	// Left out, the clock and status icons still reserve room (the 5th row of a T41S stayed empty); saying "hide"
	// gives the room back (verified on a T41S: 5 text rows instead of 4).
	if !o.Clock {
		sb.WriteString("  <SystemTime Size=\"normal\" HorizontalAlign=\"center\" VerticalAlign=\"top\" Color=\"white\">hide</SystemTime>\n")
	}
	if !o.StatusIcons {
		sb.WriteString("  <StatusIcons HorizontalAlign=\"center\" VerticalAlign=\"top\">hide</StatusIcons>\n")
	}
	if o.Clock {
		sb.WriteString("  <SystemTime Size=\"large\" HorizontalAlign=\"center\" VerticalAlign=\"top\" Color=\"white\">show</SystemTime>\n")
	}
	if o.StatusIcons {
		sb.WriteString("  <StatusIcons HorizontalAlign=\"center\" VerticalAlign=\"bottom\">show</StatusIcons>\n")
	}
	if o.ImageURL != "" {
		if !strings.HasPrefix(o.ImageURL, "https://") && !strings.HasPrefix(o.ImageURL, "http://") {
			return "", fmt.Errorf("the image URL must start with https:// or http://")
		}
		if strings.ContainsAny(o.ImageURL, "<>\"&\r\n") {
			return "", fmt.Errorf("the image URL contains characters that need escaping")
		}
		fmt.Fprintf(&sb, "  <Image HorizontalAlign=\"center\" VerticalAlign=\"middle\">%s</Image>\n", o.ImageURL)
	}
	for _, l := range o.Lines {
		if strings.ContainsAny(l, "\r\n") {
			return "", fmt.Errorf("a text line cannot contain a line break")
		}
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		fmt.Fprintf(&sb, "  <Line Size=\"normal\" Align=\"center\" Color=\"white\">%s</Line>\n", r.Replace(l))
	}
	if len(o.Lines) == 0 && !o.Clock && !o.StatusIcons && o.ImageURL == "" {
		return "", fmt.Errorf("nothing to show: give text, the clock, status icons or an image URL")
	}
	sb.WriteString("</YealinkIPPhoneCustomScreenSaver>\n")
	return sb.String(), nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// unsharp sharpens by adding back the difference from a 3x3 blur.
func unsharp(g []float64, w, h int, amount float64) []float64 {
	out := make([]float64, len(g))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var sum float64
			n := 0
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					xx, yy := x+dx, y+dy
					if xx >= 0 && xx < w && yy >= 0 && yy < h {
						sum += g[yy*w+xx]
						n++
					}
				}
			}
			c := g[y*w+x]
			out[y*w+x] = c + amount*(c-sum/float64(n))
		}
	}
	return out
}

// dilate grows bright areas by one pixel (3x3 maximum).
func dilate(g []float64, w, h int) []float64 {
	out := make([]float64, len(g))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m := g[y*w+x]
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					xx, yy := x+dx, y+dy
					if xx >= 0 && xx < w && yy >= 0 && yy < h && g[yy*w+xx] > m {
						m = g[yy*w+xx]
					}
				}
			}
			out[y*w+x] = m
		}
	}
	return out
}

// DOB returns the picture as Yealink's .dob logo file, as documented by the open-source BrixIT converter for the
// older phones: one byte of width, one byte of height, then the pixels row by row, four bits each, two pixels to a
// byte with the FIRST pixel in the low nibble. In that file a higher value is darker (15 is black). Which way the
// T41S wants it is not documented, so blackHigh selects it. The width and height must be 255 or less.
func (m Image) DOB(blackHigh bool) ([]byte, error) {
	if m.Width < 1 || m.Height < 1 || m.Width > 255 || m.Height > 255 {
		return nil, fmt.Errorf("a .dob picture is at most 255 pixels each way")
	}
	nib := func(p uint8) byte {
		v := int(p)
		switch m.Levels {
		case 2:
			v *= 15
		case 4:
			v *= 5
		}
		if blackHigh {
			v = 15 - v
		}
		return byte(v & 15)
	}
	out := []byte{byte(m.Width), byte(m.Height)}
	for i := 0; i < len(m.Pix); i += 2 {
		lo := nib(m.Pix[i])
		var hi byte
		if i+1 < len(m.Pix) {
			hi = nib(m.Pix[i+1])
		} else if blackHigh {
			hi = 15
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}
