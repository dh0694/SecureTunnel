// Package agenticon draws the agent's tray icons (a shield on a coloured
// rounded square, one colour per connection state) without image files.
package agenticon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Colours for each state.
var (
	Connected    = color.RGBA{0x15, 0x7f, 0x3c, 0xff} // green
	Reconnecting = color.RGBA{0xc2, 0x7c, 0x0e, 0xff} // amber
	Disconnected = color.RGBA{0x6b, 0x72, 0x80, 0xff} // grey
	Office       = color.RGBA{0x25, 0x57, 0xd6, 0xff} // blue
	Brand        = Office
)

// PNG draws the icon at the given size.
func PNG(size int, bg color.RGBA) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	r := s * 0.22 // corner radius
	shield := []point{{0.50, 0.17}, {0.78, 0.28}, {0.78, 0.50}, {0.72, 0.66}, {0.50, 0.84}, {0.28, 0.66}, {0.22, 0.50}, {0.22, 0.28}}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// 4x4 supersampling for smooth edges.
			var cover, white float64
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/4) / s
					py := (float64(y) + (float64(sy)+0.5)/4) / s
					if inRoundedRect(px*s, py*s, s, r) {
						cover++
						if inPolygon(px, py, shield) {
							white++
						}
					}
				}
			}
			if cover == 0 {
				continue
			}
			a := cover / 16
			w := white / cover
			c := color.RGBA{
				R: uint8(float64(bg.R)*(1-w) + 255*w),
				G: uint8(float64(bg.G)*(1-w) + 255*w),
				B: uint8(float64(bg.B)*(1-w) + 255*w),
				A: 255,
			}
			// premultiply for image.RGBA
			img.SetRGBA(x, y, color.RGBA{uint8(float64(c.R) * a), uint8(float64(c.G) * a), uint8(float64(c.B) * a), uint8(255 * a)})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ICO returns a Windows .ico with 16, 24, 32 and 48 px images (PNG-encoded).
func ICO(bg color.RGBA) []byte {
	sizes := []int{16, 24, 32, 48, 256}
	var imgs [][]byte
	for _, s := range sizes {
		imgs = append(imgs, PNG(s, bg))
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		dim := uint8(s)
		if s >= 256 {
			dim = 0
		}
		_ = binary.Write(&buf, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, BPP            uint16
			Size, Offset           uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(imgs[i])), uint32(offset)})
		offset += len(imgs[i])
	}
	for _, b := range imgs {
		buf.Write(b)
	}
	return buf.Bytes()
}

type point struct{ x, y float64 }

func inRoundedRect(x, y, s, r float64) bool {
	cx := math.Max(r, math.Min(s-r, x))
	cy := math.Max(r, math.Min(s-r, y))
	dx, dy := x-cx, y-cy
	return x >= 0 && y >= 0 && x <= s && y <= s && dx*dx+dy*dy <= r*r
}

func inPolygon(x, y float64, p []point) bool {
	in := false
	for i, j := 0, len(p)-1; i < len(p); j, i = i, i+1 {
		if (p[i].y > y) != (p[j].y > y) && x < (p[j].x-p[i].x)*(y-p[i].y)/(p[j].y-p[i].y)+p[i].x {
			in = !in
		}
	}
	return in
}
