package discordgo

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestVoiceResumeRestartsMedia(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "successful resume and replay"
		if canceled {
			name = "canceled resume"
		}
		t.Run(name, func(t *testing.T) {
			group := testMLSParticipants(t, "101", "202")
			group.join(t, 1, 0)
			group.transition(t, 0, 0, 1)
			dave, peer := group.members[0], group.members[1]
			testMLSDecrypt(t, peer, 1, testMLSEncrypt(t, dave))
			epoch := dave.activeEpoch
			local, remote, aead := voiceUDPPair(t)
			vc := lifecycleVoice()
			vc.dave, vc.udpConn, vc.cipher = dave, remote, aead
			vc.speaking, vc.op2.SSRC, vc.transportNonce = true, 1, 11
			ctx, cancel := context.WithCancel(t.Context())
			vc.wsCancel = cancel
			t.Cleanup(func() {
				cancel()
				_ = remote.Close()
				vc.Kill()
				vc.receiverWG.Wait()
			})
			if canceled {
				cancel()
			}
			vc.onEvent(ctx, false, []byte(`{"op":9,"d":{}}`))
			vc.onEvent(ctx, false, []byte(`{"op":9,"d":{}}`))
			vc.Cond.L.Lock()
			status, retainedDAVE := vc.Status, vc.dave == dave
			vc.Cond.L.Unlock()
			if !retainedDAVE || dave.activeEpoch != epoch || !dave.CanEncrypt() {
				t.Fatal("resuming replaced the established DAVE session or keys")
			}
			if canceled {
				if status != VoiceConnectionStatusConnecting {
					t.Error("canceled resume changed transport readiness")
				}
			} else if status != VoiceConnectionStatusReady {
				t.Error("successful OP9 resume left the connection unready")
			}

			// Both directions use the epoch negotiated before the transport resumed.
			header := make([]byte, 12)
			header[0], header[1] = 0x80, 0x78
			binary.BigEndian.PutUint32(header[8:], 2)
			nonce := make([]byte, aead.NonceSize())
			incoming := aead.Seal(header, nonce, testMLSEncrypt(t, peer), header)
			incoming = append(incoming, nonce[:4]...)
			_, err := local.WriteToUDP(incoming, remote.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			for range 8 {
				vc.OpusSend <- bytes.Clone(testMLSOpus)
			}
			timeout := time.Second
			if canceled {
				timeout = 100 * time.Millisecond
			}
			err = local.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				t.Fatal(err)
			}
			for index := range 8 {
				packet := make([]byte, 2048)
				n, readErr := local.Read(packet)
				if canceled {
					if readErr == nil {
						t.Error("canceled resume started sending audio")
					}
					break
				}
				if readErr != nil {
					t.Errorf("resumed sender did not deliver frame %d: %v", index, readErr)
					break
				}
				packet = packet[:n]
				if n < 12+4+aead.Overhead() {
					t.Fatalf("resumed sender produced a truncated packet: %d bytes", n)
				}
				sequence := binary.BigEndian.Uint16(packet[2:4])
				counter := binary.LittleEndian.Uint32(packet[n-4:])
				if int(sequence) != index || counter != uint32(11+index) {
					t.Fatalf("replayed OP9 duplicated senders or reset transport state: sequence=%d nonce=%d, want %d and %d", sequence, counter, index, 11+index)
				}
				copy(nonce, packet[n-4:])
				frame, decryptErr := aead.Open(nil, nonce, packet[12:n-4], packet[:12])
				if decryptErr != nil {
					t.Fatal(decryptErr)
				}
				testMLSDecrypt(t, peer, 1, frame)
			}
			select {
			case packet := <-vc.OpusRecv:
				if canceled {
					t.Fatal("canceled resume started receiving audio")
				}
				if packet == nil || !bytes.Equal(packet.Opus, testMLSOpus) {
					t.Fatal("resumed receiver could not decrypt the established DAVE epoch")
				}
			case <-time.After(timeout):
				if !canceled {
					t.Error("resumed receiver did not deliver audio")
				}
			}
		})
	}
}
