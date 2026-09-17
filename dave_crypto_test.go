package discordgo

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDAVEFrameValidation(t *testing.T) {
	cipher, err := newDAVECipher(bytes.Repeat([]byte{1}, daveKeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []uint32{0, 1, 127, 128, 1 << 24, ^uint32(0)} {
		frame := encryptSecureFrame(cipher, nonce, []byte("audio"))
		ciphertext, tag, got, err := parseSecureFrame(frame)
		if err != nil || got != nonce || len(ciphertext) != 5 || len(tag) != daveTagSize {
			t.Fatalf("valid nonce %d: got %d, error %v", nonce, got, err)
		}
	}

	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{"unterminated", []byte{0x80}},
		{"overflow uint32", binary.AppendUvarint(nil, 1<<32)},
		{"overflow uint64", bytes.Repeat([]byte{0xff}, 11)},
		{"trailing bytes", []byte{1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := []byte("audio")
			frame = append(frame, make([]byte, daveTagSize)...)
			frame = append(frame, tc.nonce...)
			frame = append(frame, byte(daveTagSize+len(tc.nonce)+3), 0xfa, 0xfa)
			_, _, _, err := parseSecureFrame(frame)
			if err == nil {
				t.Fatal("accepted malformed nonce trailer")
			}
		})
	}

	for length := range minSupplementalBytesSize {
		frame := make([]byte, length)
		_, _, _, err := parseSecureFrame(frame)
		if err == nil {
			t.Fatalf("accepted frame with length %d", length)
		}
	}
}

func FuzzParseDAVEFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0x80, 12, 0xfa, 0xfa})
	f.Fuzz(func(t *testing.T, data []byte) {
		ciphertext, tag, _, err := parseSecureFrame(data)
		if err == nil && (len(tag) != daveTagSize || len(ciphertext) > len(data)-minSupplementalBytesSize) {
			t.Fatal("accepted inconsistent frame boundaries")
		}
	})
}
