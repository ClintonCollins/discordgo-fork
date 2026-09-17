package discordgo

import "testing"

func TestDAVELifecycleFailsClosed(t *testing.T) {
	d := NewDAVESession("123")
	defer d.Close()
	for _, reset := range []func(){func() {}, d.Reset, d.Close} {
		reset()
		frame, err := d.EncryptFrame([]byte("private audio"))
		if err == nil || frame != nil || d.CanEncrypt() || d.canSendPassthrough() {
			t.Fatal("unavailable DAVE session permitted plaintext or reported ready")
		}
	}
}
