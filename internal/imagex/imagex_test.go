// SPDX-License-Identifier: Apache-2.0

package imagex

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func pngOf(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 100, 255})
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func TestProcess(t *testing.T) {
	src := pngOf(400, 200)
	out, f, info, err := Process(src, Params{Op: "thumbnail", Width: 100, Height: 100})
	if err != nil || f != "png" || info.Width != 100 || info.Height != 50 {
		t.Fatalf("%v %v %+v", err, f, info)
	}
	if c, _, err := image.DecodeConfig(bytes.NewReader(out)); err != nil || c.Width != 100 {
		t.Fatal(c, err)
	}
	if _, f, info, err := Process(src, Params{Op: "scale", Percent: 50, Format: "jpg"}); err != nil || f != "jpeg" || info.Width != 200 {
		t.Fatalf("%v %v %+v", err, f, info)
	}
	if _, f, _, err := Process(src, Params{Op: "convert", Format: "gif"}); err != nil || f != "gif" {
		t.Fatal(err, f)
	}
	if _, _, _, err := Process(src, Params{Op: "scale", Width: 20000}); err == nil {
		t.Fatal("huge scale accepted")
	}
	if _, _, _, err := Process([]byte("not an image"), Params{Op: "convert"}); err == nil {
		t.Fatal("garbage accepted")
	}
	// bomb: header claims 50000x50000
	bomb := pngOf(1, 1)
	copy(bomb[16:24], []byte{0, 0, 0xc3, 0x50, 0, 0, 0xc3, 0x50})
	if _, err := Probe(bomb); err == nil {
		t.Fatal("bomb accepted")
	}
}
