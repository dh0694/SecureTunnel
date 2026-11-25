package agenticon

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestICOStructure(t *testing.T) {
	ico := ICO(Connected)
	var hdr [3]uint16
	if err := binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 0 || hdr[1] != 1 || hdr[2] != 5 {
		t.Fatalf("header = %v, want [0 1 5]", hdr)
	}
}

func TestPNGHasShield(t *testing.T) {
	img, err := png.Decode(bytes.NewReader(PNG(32, Connected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a > 0x8000 {
		t.Error("corner should be transparent (rounded)")
	}
	if r, g, b, _ := img.At(16, 14).RGBA(); r < 0xf000 || g < 0xf000 || b < 0xf000 {
		t.Error("centre should be the white shield")
	}
	if r, g, _, _ := img.At(3, 16).RGBA(); g <= r {
		t.Error("edge should be the green background")
	}
}
