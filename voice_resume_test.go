package discordgo

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestVoiceWebsocketResumePreservesTransport(t *testing.T) {
	group := testMLSParticipants(t, "101", "202")
	group.join(t, 1, 0)
	group.transition(t, 0, 0, 1)
	dave, peer := group.members[0], group.members[1]
	epoch := dave.activeEpoch
	local, _, aead := voiceUDPPair(t)
	packets := make(chan []byte, 16)
	var discoveries, selections, resumes atomic.Int32
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, address, err := local.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n == 74 && binary.BigEndian.Uint16(buffer) == 1 {
				discoveries.Add(1)
				response := make([]byte, 74)
				binary.BigEndian.PutUint16(response, 2)
				binary.BigEndian.PutUint16(response[2:], 70)
				copy(response[4:8], buffer[4:8])
				copy(response[8:], "127.0.0.1")
				binary.BigEndian.PutUint16(response[72:], uint16(address.Port))
				_, _ = local.WriteToUDP(response, address)
			} else if n > 8 {
				select {
				case packets <- bytes.Clone(buffer[:n]):
				case <-t.Context().Done():
					return
				}
			}
		}
	}()
	sockets := make(chan *websocket.Conn, 3)
	resumePending := make(chan struct{}, 2)
	resumeAllowed := make(chan struct{})
	resumedEvents := make(chan struct{}, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		var event voiceWebsocketMessage
		err = ws.ReadJSON(&event)
		if err != nil {
			return
		}
		sockets <- ws
		_ = ws.WriteJSON(map[string]any{"op": 8, "d": voiceOP8{HeartbeatInterval: 60000}})
		if event.Operation == 0 {
			address := local.LocalAddr().(*net.UDPAddr)
			_ = ws.WriteJSON(map[string]any{"op": 2, "d": voiceOP2{SSRC: 1, IP: "127.0.0.1", Port: address.Port, Modes: []string{"aead_aes256_gcm_rtpsize"}}})
		} else if event.Operation == 7 {
			attempt := resumes.Add(1)
			var resume struct {
				Sequence int `json:"seq_ack"`
			}
			err = json.Unmarshal(event.RawData, &resume)
			if err != nil || resume.Sequence != 32+int(attempt) {
				t.Errorf("resume sequence = %d, error = %v; want %d", resume.Sequence, err, 32+attempt)
			}
			resumePending <- struct{}{}
			select {
			case <-resumeAllowed:
			case <-t.Context().Done():
				return
			}
			_ = ws.WriteJSON(map[string]any{"op": 9, "seq": 33 + attempt, "d": nil})
			_ = ws.WriteJSON(map[string]any{"op": 5, "seq": 33 + attempt, "d": map[string]any{"user_id": "202", "ssrc": 2, "speaking": 1}})
		} else {
			t.Errorf("unexpected voice handshake opcode %d", event.Operation)
			return
		}
		for {
			err = ws.ReadJSON(&event)
			if err != nil {
				return
			}
			if event.Operation == 1 {
				selections.Add(1)
				_ = ws.WriteJSON(map[string]any{"op": 4, "seq": 33, "d": voiceOP4{SecretKey: make([]byte, 32), Mode: "aead_aes256_gcm_rtpsize"}})
			}
		}
	}))
	t.Cleanup(server.Close)
	vc := lifecycleVoice()
	vc.channelID, vc.sessionID, vc.speaking = testMLSChannel, "local-session", true
	vc.session.State = NewState()
	vc.session.State.User = &User{ID: "101"}
	vc.session.Dialer = &websocket.Dialer{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig}
	vc.AddHandler(func(*VoiceConnection, *VoiceSpeakingUpdate) { resumedEvents <- struct{}{} })
	ctx, cancel := context.WithCancel(t.Context())
	vc.wsCancel = cancel
	done := make(chan struct{})
	go func() {
		vc.websocket(ctx, strings.TrimPrefix(server.URL, "https://"), "local-token")
		close(done)
	}()
	t.Cleanup(func() {
		vc.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("voice websocket did not stop")
		}
		select {
		case _, open := <-vc.OpusRecv:
			if open {
				t.Error("voice receiver did not close")
			}
		case <-time.After(2 * time.Second):
			t.Error("voice receiver survived shutdown")
		}
	})
	waitCtx, waitCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer waitCancel()
	err := vc.waitUntilStatus(waitCtx, VoiceConnectionStatusReady)
	if err != nil {
		t.Fatal(err)
	}
	vc.eventMu.Lock()
	vc.Cond.L.Lock()
	vc.dave.Close()
	vc.dave = dave
	udp := vc.udpConn
	vc.Cond.L.Unlock()
	vc.eventMu.Unlock()

	exchange := func(turn int) {
		t.Helper()
		vc.Cond.L.Lock()
		retained := vc.udpConn == udp && vc.dave == dave
		status := vc.Status
		vc.Cond.L.Unlock()
		if !retained || discoveries.Load() != 1 || selections.Load() != 1 {
			t.Fatalf("resume renegotiated the established transport: retained=%v discoveries=%d selections=%d", retained, discoveries.Load(), selections.Load())
		}
		if status != VoiceConnectionStatusReady || dave.activeEpoch != epoch || !dave.CanEncrypt() {
			t.Fatal("resume lost media readiness or the established DAVE epoch")
		}
		vc.OpusSend <- bytes.Clone(testMLSOpus)
		select {
		case packet := <-packets:
			if len(packet) < 12+4+aead.Overhead() {
				t.Fatal("truncated audio packet")
			}
			sequence := binary.BigEndian.Uint16(packet[2:4])
			counter := binary.LittleEndian.Uint32(packet[len(packet)-4:])
			if sequence != uint16(turn) || counter != uint32(turn) {
				t.Fatalf("resume reset audio state: sequence=%d nonce=%d, want %d", sequence, counter, turn)
			}
			nonce := make([]byte, aead.NonceSize())
			copy(nonce, packet[len(packet)-4:])
			frame, decryptErr := aead.Open(nil, nonce, packet[12:len(packet)-4], packet[:12])
			if decryptErr != nil {
				t.Fatal(decryptErr)
			}
			testMLSDecrypt(t, peer, 1, frame)
		case <-time.After(2 * time.Second):
			t.Fatal("resumed sender did not deliver audio")
		}
		header := make([]byte, 12)
		header[0], header[1] = 0x80, 0x78
		binary.BigEndian.PutUint32(header[8:], 2)
		nonce := make([]byte, aead.NonceSize())
		binary.LittleEndian.PutUint32(nonce, uint32(turn))
		packet := aead.Seal(header, nonce, testMLSEncrypt(t, peer), header)
		packet = append(packet, nonce[:4]...)
		_, err = local.WriteToUDP(packet, udp.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case received := <-vc.OpusRecv:
			if received == nil || !bytes.Equal(received.Opus, testMLSOpus) {
				t.Fatal("resumed receiver could not decrypt the established DAVE epoch")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("resumed receiver did not deliver audio")
		}
	}
	exchange(0)
	for attempt := range 2 {
		select {
		case socket := <-sockets:
			_ = socket.UnderlyingConn().Close()
		case <-time.After(2 * time.Second):
			t.Fatal("voice websocket did not connect")
		}
		select {
		case <-resumePending:
		case <-time.After(2 * time.Second):
			t.Fatal("voice websocket did not resume")
		}
		// A delayed websocket resume must not interrupt the established UDP stream.
		exchange(2*attempt + 1)
		resumeAllowed <- struct{}{}
		select {
		case <-resumedEvents:
		case <-time.After(2 * time.Second):
			t.Fatal("resumed websocket did not deliver buffered events")
		}
		exchange(2*attempt + 2)
	}
}

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
			vc.onEvent(ctx, ctx, false, []byte(`{"op":9,"d":{}}`))
			vc.onEvent(ctx, ctx, false, []byte(`{"op":9,"d":{}}`))
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
