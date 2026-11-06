package server

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

const pngDataURLPrefix = "data:image/png;base64,"

func decodePNGDataURL(t *testing.T, u string) image.Image {
	t.Helper()
	b64, ok := strings.CutPrefix(u, pngDataURLPrefix)
	if !ok {
		t.Fatalf("%.40q... is not a PNG data URL", u)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func dark(img image.Image, x, y int) bool {
	return color.GrayModel.Convert(img.At(x, y)).(color.Gray).Y < 128
}

// A 100-character activation link fits a version 5-7 code (37-45 modules);
// with the quiet zone at 6 px per module that is 270-318 px.
func TestQRDataURL(t *testing.T) {
	link := ActivationLink(host, "DU"+strings.Repeat("A", 26), strings.Repeat("B", 26))
	u, err := qrDataURL(link)
	if err != nil {
		t.Fatal(err)
	}
	img := decodePNGDataURL(t, u)
	b := img.Bounds()
	if b.Dx() != b.Dy() || b.Dx() < 270 || b.Dx() > 318 || b.Dx()%6 != 0 {
		t.Fatalf("image %v, want a square of 270-318 px in 6 px modules", b)
	}
	const quiet = 4 * 6
	for _, p := range []image.Point{{0, 0}, {quiet - 1, quiet - 1}, {b.Dx() - 1, b.Dy() - 1}} {
		if dark(img, p.X, p.Y) {
			t.Errorf("pixel %v is dark, want the white quiet zone", p)
		}
	}
	if !dark(img, quiet, quiet) || !dark(img, b.Dx()-quiet-1, quiet) || !dark(img, quiet, b.Dy()-quiet-1) {
		t.Error("finder pattern corners are not dark")
	}
	if other, _ := qrDataURL(link + "x"); other == u {
		t.Error("different input, same image")
	}
}
