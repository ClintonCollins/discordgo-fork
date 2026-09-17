package mls

import "testing"

func TestVectorLengthBounds(t *testing.T) {
	for _, length := range []uint64{1, 1 << 31, 1 << 32, (1 << 62) - 1} {
		w := &tlsWriter{}
		w.writeVarint(length)
		r := &tlsReader{data: w.bytes()}
		got := r.readVec()
		if r.err == nil || got != nil {
			t.Fatalf("accepted vector length %d without its contents", length)
		}
	}

	w := &tlsWriter{}
	w.writeVec([]byte("valid"))
	r := &tlsReader{data: w.bytes()}
	got := r.readVec()
	if r.err != nil || string(got) != "valid" || r.remaining() != 0 {
		t.Fatalf("valid vector: got %q, error %v", got, r.err)
	}
}
