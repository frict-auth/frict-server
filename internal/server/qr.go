package server

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"github.com/boombuler/barcode/qr"
)

// qrDataURL renders s as a QR code PNG data URL: error correction M, 6 px
// per module, and the 4-module white quiet zone scanners need.
func qrDataURL(s string) (string, error) {
	code, err := qr.Encode(s, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}
	const quiet, px = 4, 6
	n := code.Bounds().Dx()
	side := (n + 2*quiet) * px
	img := image.NewGray(image.Rect(0, 0, side, side))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	for y := range n {
		for x := range n {
			if color.GrayModel.Convert(code.At(x, y)).(color.Gray).Y < 128 {
				r := image.Rect(x+quiet, y+quiet, x+quiet+1, y+quiet+1)
				draw.Draw(img, image.Rectangle{r.Min.Mul(px), r.Max.Mul(px)}, image.Black, image.Point{}, draw.Src)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
