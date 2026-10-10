// SPDX-License-Identifier: Apache-2.0

// Package imagex is the Images tool (cPanel Thumbnailer / Scaler /
// Converter) in pure Go: decode JPEG/PNG/GIF, resize with an area-average
// (box) filter, encode JPEG/PNG/GIF. Decompression bombs are refused from
// the header before any pixel is decoded.
package imagex

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
)

const (
	MaxBytes  = 8 << 20  // input file
	MaxPixels = 40 << 20 // decoded width*height
	MaxSide   = 10000
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// Params of one operation.
type Params struct {
	Op      string `json:"op"` // thumbnail | scale | convert
	Width   int    `json:"width,omitempty"`
	Height  int    `json:"height,omitempty"`
	Percent int    `json:"percent,omitempty"` // scale by percent (1..400) when Width/Height are 0
	Format  string `json:"format,omitempty"`  // jpeg | png | gif ("" = keep)
	Quality int    `json:"quality,omitempty"` // JPEG 1..100 (default 85)
}

// Info is the header of an image.
type Info struct {
	Format string `json:"format"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// Probe reads the header only.
func Probe(b []byte) (Info, error) {
	if len(b) > MaxBytes {
		return Info{}, &Error{Code: "image_too_large"}
	}
	c, f, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return Info{}, &Error{Code: "image_unsupported"}
	}
	if c.Width <= 0 || c.Height <= 0 || c.Width > MaxSide || c.Height > MaxSide || c.Width*c.Height > MaxPixels {
		return Info{}, &Error{Code: "image_too_large"}
	}
	return Info{Format: f, Width: c.Width, Height: c.Height}, nil
}

// Target computes the output size: thumbnail = fit inside WxH keeping the
// aspect ratio (never upscale); scale = exact WxH, one side 0 keeps ratio,
// or Percent; convert = same size.
func Target(in Info, p Params) (int, int, error) {
	w, h := in.Width, in.Height
	switch p.Op {
	case "convert":
		return w, h, nil
	case "thumbnail":
		if p.Width <= 0 && p.Height <= 0 {
			p.Width, p.Height = 200, 200
		}
		if p.Width <= 0 {
			p.Width = MaxSide
		}
		if p.Height <= 0 {
			p.Height = MaxSide
		}
		r := min(float64(p.Width)/float64(w), float64(p.Height)/float64(h), 1)
		return max(1, int(float64(w)*r+0.5)), max(1, int(float64(h)*r+0.5)), nil
	case "scale":
		switch {
		case p.Width > 0 && p.Height > 0:
			w, h = p.Width, p.Height
		case p.Width > 0:
			h, w = max(1, int(float64(h)*float64(p.Width)/float64(w)+0.5)), p.Width
		case p.Height > 0:
			w, h = max(1, int(float64(w)*float64(p.Height)/float64(h)+0.5)), p.Height
		case p.Percent > 0 && p.Percent <= 400:
			w, h = max(1, w*p.Percent/100), max(1, h*p.Percent/100)
		default:
			return 0, 0, &Error{Code: "image_bad_size"}
		}
		if w > MaxSide || h > MaxSide || w*h > MaxPixels {
			return 0, 0, &Error{Code: "image_too_large"}
		}
		return w, h, nil
	}
	return 0, 0, &Error{Code: "image_bad_op"}
}

// resize is an area-average downscale / bilinear-ish upscale on RGBA.
func resize(src image.Image, w, h int) *image.RGBA {
	sb := src.Bounds()
	s := image.NewRGBA(image.Rect(0, 0, sb.Dx(), sb.Dy()))
	draw.Draw(s, s.Bounds(), src, sb.Min, draw.Src)
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	sw, sh := sb.Dx(), sb.Dy()
	for y := 0; y < h; y++ {
		y0 := y * sh / h
		y1 := max((y+1)*sh/h, y0+1)
		for x := 0; x < w; x++ {
			x0 := x * sw / w
			x1 := max((x+1)*sw/w, x0+1)
			var r, g, b, a, n uint64
			for yy := y0; yy < y1 && yy < sh; yy++ {
				off := s.PixOffset(x0, yy)
				for xx := x0; xx < x1 && xx < sw; xx++ {
					r += uint64(s.Pix[off])
					g += uint64(s.Pix[off+1])
					b += uint64(s.Pix[off+2])
					a += uint64(s.Pix[off+3])
					off += 4
					n++
				}
			}
			if n == 0 {
				continue
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), uint8(a / n)})
		}
	}
	return dst
}

// Process runs p on an encoded image and returns the encoded result and its
// format.
func Process(b []byte, p Params) ([]byte, string, Info, error) {
	in, err := Probe(b)
	if err != nil {
		return nil, "", in, err
	}
	w, h, err := Target(in, p)
	if err != nil {
		return nil, "", in, err
	}
	src, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, "", in, &Error{Code: "image_unsupported"}
	}
	var img image.Image = src
	if w != in.Width || h != in.Height {
		img = resize(src, w, h)
	}
	f := strings.ToLower(p.Format)
	if f == "" || f == "jpg" {
		if f == "jpg" {
			f = "jpeg"
		} else {
			f = in.Format
		}
	}
	var out bytes.Buffer
	switch f {
	case "jpeg":
		q := p.Quality
		if q <= 0 || q > 100 {
			q = 85
		}
		// JPEG has no alpha: flatten on white
		rgba := image.NewRGBA(img.Bounds())
		draw.Draw(rgba, rgba.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
		draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Over)
		err = jpeg.Encode(&out, rgba, &jpeg.Options{Quality: q})
	case "png":
		err = png.Encode(&out, img)
	case "gif":
		err = gif.Encode(&out, img, nil)
	default:
		return nil, "", in, &Error{Code: "image_bad_format"}
	}
	if err != nil {
		return nil, "", in, &Error{Code: "image_encode_failed"}
	}
	return out.Bytes(), f, Info{Format: f, Width: w, Height: h}, nil
}

// Ext is the file extension of a format.
func Ext(format string) string {
	if format == "jpeg" {
		return "jpg"
	}
	return format
}
