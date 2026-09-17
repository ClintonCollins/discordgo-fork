package discordgo

import (
	"bytes"
	"testing"
)

func TestActivatePreparedTransitionActivatesSenderWhenKeyIsPrepared(t *testing.T) {
	d := &DAVESession{
		senderKey:           []byte{1, 2, 3},
		frameCipher:         testAEAD{},
		hasPendingKey:       true,
		exporterSecret:      []byte{9, 9, 9},
		pendingTransitionID: 0,
		pendingVersion:      1,
	}

	if d.CanEncrypt() {
		t.Fatal("expected session to start inactive")
	}
	if err := d.ActivatePreparedTransition(0); err != nil {
		t.Fatalf("ActivatePreparedTransition returned error: %v", err)
	}
	if !d.CanEncrypt() {
		t.Fatal("expected prepared transition activation to enable encryption")
	}
}

type testAEAD struct{}

func (testAEAD) NonceSize() int { return 12 }
func (testAEAD) Overhead() int  { return 16 }
func (testAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}
func (testAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func testDAVESession(t *testing.T, userID string) *DAVESession {
	t.Helper()
	d := NewDAVESession(userID)
	d.exporterSecret = bytes.Repeat([]byte{1}, 32)
	err := d.DeriveSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	d.Activate()
	return d
}

func TestDAVESenderKeyLifecycle(t *testing.T) {
	for _, initialNonce := range []uint32{0, (1 << 24) - 1} {
		d := testDAVESession(t, "123")
		d.senderNonce = initialNonce
		first, err := d.EncryptFrame([]byte("audio"))
		if err != nil {
			t.Fatal(err)
		}
		err = d.DeriveSenderKey()
		if err != nil {
			t.Fatal(err)
		}
		second, err := d.EncryptFrame([]byte("audio"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, nonce, err := parseSecureFrame(second)
		if err != nil || nonce != initialNonce+2 {
			t.Fatalf("repeated derivation changed nonce: got %d, error %v", nonce, err)
		}
		if bytes.Equal(first, second) {
			t.Fatal("repeated derivation reused the key and nonce")
		}
		if d.currentGeneration != (initialNonce+2)>>24 {
			t.Fatal("repeated derivation reset the ratchet generation")
		}
		d.HandlePrepareTransition(9, 0)
		err = d.HandleExecuteTransition(9)
		if err != nil {
			t.Fatal(err)
		}
		err = d.DeriveSenderKey()
		if err != nil {
			t.Fatal(err)
		}
		d.Activate()
		third, err := d.EncryptFrame([]byte("audio"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, nonce, err = parseSecureFrame(third)
		if err != nil || nonce != initialNonce+3 {
			t.Fatalf("reactivating unchanged key reset nonce: got %d, error %v", nonce, err)
		}
	}

	d := testDAVESession(t, "123")
	first, err := d.EncryptFrame([]byte("audio"))
	if err != nil {
		t.Fatal(err)
	}
	d.exporterSecret = bytes.Repeat([]byte{2}, 32)
	err = d.DeriveSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.EncryptFrame([]byte("audio"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, nonce, err := parseSecureFrame(second)
	if err != nil || nonce != 1 || bytes.Equal(first, second) {
		t.Fatalf("new epoch failed to rotate key and reset nonce: nonce %d, error %v", nonce, err)
	}
}

func TestDAVEEncryptionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*DAVESession)
	}{
		{"inactive", func(d *DAVESession) { d.active = false }},
		{"missing cipher", func(d *DAVESession) { d.frameCipher = nil }},
		{"exhausted nonce", func(d *DAVESession) { d.senderNonce = ^uint32(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDAVESession(t, "123")
			tc.prepare(d)
			if d.CanEncrypt() {
				t.Fatal("unavailable encryption reported ready")
			}
			oldNonce := d.senderNonce
			for range 2 {
				frame, err := d.EncryptFrame([]byte("audio"))
				if err == nil || frame != nil {
					t.Fatal("unavailable encryption returned an audio frame")
				}
				if d.senderNonce != oldNonce {
					t.Fatal("failed encryption changed the nonce")
				}
			}
		})
	}
}

func TestDAVEReassignedSSRC(t *testing.T) {
	receiver := testDAVESession(t, "999")
	for _, userID := range []string{"123", "456"} {
		sender := testDAVESession(t, userID)
		receiver.SetSSRC(10, userID)
		frame, err := sender.EncryptFrame([]byte("audio from " + userID))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := receiver.DecryptFrame(10, frame)
		if err != nil || string(plain) != "audio from "+userID {
			t.Fatalf("SSRC reassigned to %s: plaintext %q, error %v", userID, plain, err)
		}
	}
}

func TestDAVEReplayWindow(t *testing.T) {
	sender := testDAVESession(t, "123")
	receiver := testDAVESession(t, "999")
	receiver.SetSSRC(10, "123")
	var frames [][]byte
	for range 5 {
		frame, err := sender.EncryptFrame([]byte("audio"))
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	for _, index := range []int{0, 2, 1} {
		plain, err := receiver.DecryptFrame(10, frames[index])
		if err != nil || string(plain) != "audio" {
			t.Fatalf("fresh or reordered nonce %d: plaintext %q, error %v", index+1, plain, err)
		}
	}
	for _, index := range []int{0, 1, 2} {
		plain, err := receiver.DecryptFrame(10, frames[index])
		if err == nil || plain != nil {
			t.Fatalf("accepted replay of nonce %d", index+1)
		}
	}

	invalid := bytes.Clone(frames[3])
	invalid[0] ^= 1
	plain, err := receiver.DecryptFrame(10, invalid)
	if err == nil || plain != nil {
		t.Fatal("accepted modified ciphertext")
	}
	plain, err = receiver.DecryptFrame(10, frames[3])
	if err != nil || string(plain) != "audio" {
		t.Fatalf("invalid frame consumed the nonce: %v", err)
	}

	receiver.SetSSRC(11, "123")
	plain, err = receiver.DecryptFrame(11, frames[3])
	if err == nil || plain != nil {
		t.Fatal("accepted a replay through another SSRC for the same sender")
	}

	sender.senderNonce = 2 * maxDAVEMissingNonces
	newFrame, err := sender.EncryptFrame([]byte("audio"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err = receiver.DecryptFrame(10, newFrame)
	if err != nil || string(plain) != "audio" {
		t.Fatalf("fresh nonce with a large gap: %v", err)
	}
	plain, err = receiver.DecryptFrame(10, frames[4])
	if err == nil || plain != nil {
		t.Fatal("accepted a nonce outside the bounded replay window")
	}
	sender.senderNonce = maxDAVEMissingNonces
	missingFrame, err := sender.EncryptFrame([]byte("audio"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err = receiver.DecryptFrame(10, missingFrame)
	if err != nil || string(plain) != "audio" {
		t.Fatalf("missing nonce at window boundary: %v", err)
	}
}

func TestDAVEReceivePassthroughTransitions(t *testing.T) {
	d := testDAVESession(t, "123")
	check := func(passthrough bool) {
		t.Helper()
		for _, data := range [][]byte{[]byte("plaintext opus data"), {0xf8, 1}} {
			plain, err := d.DecryptFrame(10, data)
			if passthrough {
				if err != nil || !bytes.Equal(plain, data) {
					t.Fatalf("passthrough rejected plaintext: %v", err)
				}
			} else if err == nil || plain != nil {
				t.Fatal("active DAVE accepted plaintext")
			}
		}
		plain, err := d.DecryptFrame(10, opusSilencePacket[:])
		if err != nil || !bytes.Equal(plain, opusSilencePacket[:]) {
			t.Fatalf("silence packet rejected: %v", err)
		}
	}
	check(false)
	d.HandlePrepareTransition(1, 0)
	check(true)
	err := d.HandleExecuteTransition(1)
	if err != nil {
		t.Fatal(err)
	}
	check(true)
	d.HandlePrepareTransition(2, 1)
	check(true)
	err = d.DeriveSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	err = d.ActivatePreparedTransition(2)
	if err != nil {
		t.Fatal(err)
	}
	check(false)
	d.HandlePrepareTransition(3, 0)
	err = d.HandleExecuteTransition(2)
	if err != nil {
		t.Fatal(err)
	}
	check(true)
	d.HandlePrepareTransition(4, 1)
	err = d.HandleExecuteTransition(4)
	if err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestDAVESendPassthroughRequiresExecutedDowngrade(t *testing.T) {
	d := testDAVESession(t, "123")
	d.HandlePrepareTransition(1, 0)
	if d.canSendPassthrough() {
		t.Fatal("sender downgraded before execute_transition")
	}
	err := d.HandleExecuteTransition(1)
	if err != nil || !d.canSendPassthrough() {
		t.Fatalf("executed downgrade did not enable transport-only audio: %v", err)
	}
	d.HandlePrepareTransition(2, 1)
	if !d.canSendPassthrough() {
		t.Fatal("sender stopped before the upgrade completed")
	}
	err = d.DeriveSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	err = d.ActivatePreparedTransition(2)
	if err != nil || d.canSendPassthrough() {
		t.Fatalf("activated encryption still allows transport-only audio: %v", err)
	}
	d.Reset()
	if d.canSendPassthrough() {
		t.Fatal("reset enabled plaintext sending")
	}
}
