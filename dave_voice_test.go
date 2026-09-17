package discordgo

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestDAVEVoiceRejectsIncompleteTransition(t *testing.T) {
	for _, data := range []string{"null", "{}", `{"transition_id":0}`, `{"protocol_version":0}`} {
		t.Run(data, func(t *testing.T) {
			vc := lifecycleVoice()
			defer vc.Kill()
			vc.dave = testDAVESession(t, "101")
			vc.onEvent(t.Context(), false, []byte(`{"op":21,"d":`+data+`}`))
			if !vc.dave.CanEncrypt() || vc.dave.canSendPassthrough() {
				t.Fatal("incomplete transition enabled plaintext sending")
			}
		})
	}
}

func TestDAVEVoiceHandshakeAndRecovery(t *testing.T) {
	t.Run("encrypted session", func(t *testing.T) { testDAVEVoiceHandshake(t, 1) })
	t.Run("upgrade from plaintext", func(t *testing.T) { testDAVEVoiceHandshake(t, 0) })
}

func testDAVEVoiceHandshake(t *testing.T, initialVersion int) {
	type outgoing struct {
		kind int
		data []byte
	}
	messages := make(chan outgoing, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			kind, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			messages <- outgoing{kind, data}
		}
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http", "ws", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	read := func(kind, opcode int) []byte {
		t.Helper()
		select {
		case message := <-messages:
			if message.kind != kind {
				t.Fatalf("message kind = %d, want %d", message.kind, kind)
			}
			if kind == websocket.BinaryMessage {
				if len(message.data) == 0 || int(message.data[0]) != opcode {
					t.Fatalf("expected binary opcode %d", opcode)
				}
				return message.data[1:]
			}
			var envelope struct {
				Op int `json:"op"`
			}
			err := json.Unmarshal(message.data, &envelope)
			if err != nil || envelope.Op != opcode {
				t.Fatalf("opcode = %d, want %d (%v)", envelope.Op, opcode, err)
			}
			return message.data
		case <-time.After(time.Second):
			t.Fatalf("no outbound opcode %d", opcode)
			return nil
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	vc := lifecycleVoice()
	defer vc.Kill()
	vc.channelID, vc.wsConn, vc.deaf = testMLSChannel, ws, true
	vc.session.State = NewState()
	vc.session.State.User = &User{ID: "101"}
	_, remote, _ := voiceUDPPair(t)
	vc.udpConn = remote
	vc.onEvent(ctx, false, []byte(`{"op":11,"d":{"user_ids":["202"]}}`))
	op4, err := json.Marshal(struct {
		Op   int      `json:"op"`
		Data voiceOP4 `json:"d"`
	}{4, voiceOP4{SecretKey: make([]byte, 32), Mode: "aead_aes256_gcm_rtpsize", DAVEProtocolVersion: initialVersion}})
	if err != nil {
		t.Fatal(err)
	}
	vc.onEvent(ctx, false, op4)
	if initialVersion == 0 {
		if vc.dave == nil || !vc.dave.canSendPassthrough() {
			t.Fatal("version zero session cannot prepare a later DAVE upgrade")
		}
		vc.onEvent(ctx, false, []byte(`{"op":24,"d":{"epoch":1,"protocol_version":1}}`))
		if !vc.dave.canSendPassthrough() {
			t.Fatal("preparing the upgrade changed the sending mode before execute")
		}
	}
	keyPackage := read(websocket.BinaryMessage, 26)
	if len(keyPackage) == 0 || vc.dave.CanEncrypt() {
		t.Fatal("voice published keys or readiness incorrectly")
	}
	g := testMLSParticipants(t, "101", "202")
	g.members[0].Close()
	g.members[0], g.packages[0] = vc.dave, keyPackage
	incoming := func(opcode byte, data []byte) {
		t.Helper()
		vc.onEvent(ctx, true, append([]byte{0, 1, opcode}, data...))
	}
	incoming(25, g.sender.packageBytes(t))
	incoming(27, g.sender.proposal(t, 0, 1, g.packages[1]))
	commit, welcome := splitTestMLSCommit(t, read(websocket.BinaryMessage, 28))
	incoming(29, append(binary.BigEndian.AppendUint16(nil, 1), commit...))
	read(websocket.TextMessage, 23)
	if vc.dave.CanEncrypt() {
		t.Fatal("nonzero transition sent audio before execute")
	}
	err = g.members[1].HandleWelcome(welcome)
	if err != nil {
		t.Fatal(err)
	}
	err = g.members[1].HandlePrepareTransition(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	vc.onEvent(ctx, false, []byte(`{"op":22,"d":{"transition_id":1}}`))
	err = g.members[1].HandleExecuteTransition(1)
	if err != nil {
		t.Fatal(err)
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, time.Second)
	defer readyCancel()
	err = vc.WaitForDAVEReady(readyCtx)
	if err != nil {
		t.Fatal(err)
	}
	testMLSDecrypt(t, g.members[1], 1, testMLSEncrypt(t, vc.dave))
	vc.onEvent(ctx, false, []byte(`{"op":13,"d":{"user_id":"202"}}`))
	vc.dave.SetSSRC(2, "202")
	_, err = vc.dave.DecryptFrame(2, testMLSEncrypt(t, g.members[1]))
	if err == nil {
		t.Fatal("disconnected participant remained recognized")
	}
	incoming(30, []byte{0, 2, 0xff})
	read(websocket.TextMessage, 31)
	read(websocket.BinaryMessage, 26)
	if vc.dave.CanEncrypt() || vc.dave.canSendPassthrough() {
		t.Fatal("invalid Welcome retained send permission")
	}
}
