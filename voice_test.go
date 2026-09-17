package discordgo

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestVoiceConnectionDeadChannelReturnsDead(t *testing.T) {
	dead := make(chan struct{})
	vc := &VoiceConnection{Dead: dead}
	if got := vc.DeadChannel(); got != dead {
		t.Fatalf("DeadChannel() returned unexpected channel")
	}
}

func newTestVoiceConnection() *VoiceConnection {
	return &VoiceConnection{Cond: sync.NewCond(&sync.Mutex{})}
}

func TestGetSSRCMapCopiesTheMapping(t *testing.T) {
	vc := newTestVoiceConnection()
	vc.ssrcToUserID = map[uint32]string{42: "user-a", 7: "user-b"}

	got := vc.GetSSRCMap()

	if len(got) != 2 || got[42] != "user-a" || got[7] != "user-b" {
		t.Fatalf("GetSSRCMap() = %v, want the two stored mappings", got)
	}

	got[42] = "mutated"
	delete(got, 7)
	if vc.ssrcToUserID[42] != "user-a" || vc.ssrcToUserID[7] != "user-b" {
		t.Error("mutating the returned map changed the connection's own mapping")
	}
}

func TestGetSSRCMapIsEmptyBeforeAnySpeaker(t *testing.T) {
	vc := newTestVoiceConnection()

	if got := vc.GetSSRCMap(); len(got) != 0 {
		t.Errorf("GetSSRCMap() = %v, want an empty map", got)
	}
}

func TestOnEventOP12NotifiesSpeakingHandlers(t *testing.T) {
	vc := newTestVoiceConnection()

	var got []*VoiceSpeakingUpdate
	vc.AddHandler(func(_ *VoiceConnection, vs *VoiceSpeakingUpdate) {
		got = append(got, vs)
	})

	vc.onEvent(context.Background(), false, []byte(`{"op":12,"d":{"user_id":"user-a","audio_ssrc":4242}}`))

	if len(got) != 1 {
		t.Fatalf("handlers were called %d times, want 1 for an op12 with an audio SSRC", len(got))
	}
	if got[0].UserID != "user-a" || got[0].SSRC != 4242 {
		t.Errorf("handler received %+v, want the op12 user and audio SSRC", got[0])
	}
	if vc.GetSSRCMap()[4242] != "user-a" {
		t.Errorf("GetSSRCMap() = %v, want the op12 mapping recorded", vc.GetSSRCMap())
	}
}

func TestOnEventOP12WithoutAnSSRCNotifiesNobody(t *testing.T) {
	vc := newTestVoiceConnection()

	called := false
	vc.AddHandler(func(_ *VoiceConnection, _ *VoiceSpeakingUpdate) { called = true })

	vc.onEvent(context.Background(), false, []byte(`{"op":12,"d":{"user_id":"user-a","audio_ssrc":0}}`))

	if called {
		t.Error("handlers were called for an op12 carrying no audio SSRC")
	}
}

func lifecycleVoice() *VoiceConnection {
	vc := newTestVoiceConnection()
	vc.Status = VoiceConnectionStatusConnecting
	vc.GuildID = "guild"
	vc.dead = make(chan struct{})
	vc.Dead = vc.dead
	vc.OpusSend = make(chan []byte, 16)
	vc.OpusRecv = make(chan *Packet, 2)
	vc.session = &Session{VoiceConnections: map[string]*VoiceConnection{vc.GuildID: vc}}
	return vc
}

func TestVoiceWaitCancellationAndShutdown(t *testing.T) {
	for _, daveWait := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			vc := lifecycleVoice()
			vc.dave = NewDAVESession("123")
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				if daveWait {
					result <- vc.WaitForDAVEReady(ctx)
				} else {
					result <- vc.waitUntilStatus(ctx, VoiceConnectionStatusReady)
				}
			}()
			synctest.Wait()
			cancel()
			synctest.Wait()
			err := <-result
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled waiter returned %v", err)
			}
			vc.Kill()
			err = vc.WaitForDAVEReady(context.Background())
			if !errors.Is(err, ErrVoiceConnectionClosed) {
				t.Fatalf("dead connection returned %v", err)
			}
		})
	}

	synctest.Test(t, func(t *testing.T) {
		vc := lifecycleVoice()
		result := make(chan error, 1)
		go func() { result <- vc.waitUntilStatus(context.Background(), VoiceConnectionStatusReady) }()
		synctest.Wait()
		vc.Cond.L.Lock()
		vc.Status = VoiceConnectionStatusReady
		vc.Cond.Broadcast()
		vc.Cond.L.Unlock()
		synctest.Wait()
		err := <-result
		if err != nil {
			t.Fatal(err)
		}
		vc.Kill()
	})
}

func TestVoiceFailureClosesNotificationsAndWaitsForReceiver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vc := lifecycleVoice()
		vc.receiverWG.Add(1)
		failure := errors.New("transport failed")
		vc.failure(context.Background(), failure)
		select {
		case <-vc.Dead:
		default:
			t.Fatal("failure did not close the dead notification")
		}
		if vc.session.VoiceConnections[vc.GuildID] != nil || !errors.Is(vc.Err, failure) {
			t.Fatal("failure did not remove the connection and retain its error")
		}
		_, open := <-vc.OpusSend
		if open {
			t.Fatal("send channel remains open")
		}
		synctest.Wait()
		select {
		case <-vc.OpusRecv:
			t.Fatal("receive channel closed before the receiver stopped")
		default:
		}
		vc.receiverWG.Done()
		synctest.Wait()
		_, open = <-vc.OpusRecv
		if open {
			t.Fatal("receive channel remains open after the receiver stopped")
		}
		vc.Kill()
	})
}

func TestCanceledVoiceSessionWaitDoesNotFailReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vc := lifecycleVoice()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			vc.websocket(ctx, "unused.invalid", "")
			close(done)
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		<-done
		vc.failure(ctx, errors.New("old socket closed"))
		if vc.Err != nil || vc.Status == VoiceConnectionStatusDead {
			t.Fatal("cancellation killed the replacement connection")
		}
		vc.Kill()
	})
}

func voiceUDPPair(t *testing.T) (*net.UDPConn, *net.UDPConn, cipher.AEAD) {
	t.Helper()
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	remote, err := net.DialUDP("udp4", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.Close() })
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return local, remote, aead
}

func TestVoiceReceiverRejectsMalformedPacketsAndPreservesPayload(t *testing.T) {
	local, remote, aead := voiceUDPPair(t)
	vc := lifecycleVoice()
	vc.udpConn, vc.cipher = local, aead
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { vc.opusReceiver(ctx); close(done) }()
	defer func() {
		cancel()
		_ = local.Close()
		<-done
	}()
	for size := 12; size < 36; size++ {
		packet := make([]byte, size)
		packet[0] = 0x90
		_, err := remote.Write(packet)
		if err != nil {
			t.Fatal(err)
		}
	}
	writePacket := func(payload []byte, extension bool) {
		t.Helper()
		header := make([]byte, 12)
		header[0], header[1] = 0x80, 0x78
		if extension {
			header[0] = 0x90
			header = append(header, 0xbe, 0xde, 0xff, 0xff)
		}
		nonce := make([]byte, aead.NonceSize())
		packet := aead.Seal(append([]byte(nil), header...), nonce, payload, header)
		packet = append(packet, nonce[:4]...)
		_, err := remote.Write(packet)
		if err != nil {
			t.Fatal(err)
		}
	}
	readPacket := func() *Packet {
		t.Helper()
		select {
		case packet := <-vc.OpusRecv:
			return packet
		case <-time.After(2 * time.Second):
			t.Fatal("valid audio was not received")
			return nil
		}
	}
	writePacket([]byte("short extension"), true)
	writePacket([]byte("first audio"), false)
	first := readPacket()
	writePacket([]byte("next audio overwrites the read buffer"), false)
	second := readPacket()
	if !bytes.Equal(first.Opus, []byte("first audio")) || !bytes.Equal(second.Opus, []byte("next audio overwrites the read buffer")) {
		t.Fatal("a malformed packet was delivered or an earlier payload was overwritten")
	}
}

func TestVoiceSenderNeverFallsBackAfterDAVEEncryptionError(t *testing.T) {
	for _, ready := range []bool{false, true} {
		local, remote, aead := voiceUDPPair(t)
		vc := lifecycleVoice()
		vc.udpConn, vc.cipher, vc.speaking = remote, aead, true
		vc.dave = testDAVESession(t, "123")
		if ready {
			vc.dave.Close()
		} else {
			vc.dave.Reset()
		}
		vc.OpusSend <- []byte("private audio")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		vc.opusSender(ctx, 48000, 960)
		cancel()
		err := local.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2048)
		_, err = local.Read(buffer)
		if err == nil {
			t.Fatal("audio was sent while DAVE could not encrypt")
		}
		vc.Kill()
	}
}

func TestVoiceTransportNonceSurvivesSenderRestart(t *testing.T) {
	local, remote, aead := voiceUDPPair(t)
	vc := lifecycleVoice()
	vc.udpConn, vc.cipher, vc.speaking = remote, aead, true
	for expected := uint32(0); expected < 2; expected++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		vc.OpusSend <- []byte("audio")
		go func() { vc.opusSender(ctx, 48000, 960); close(done) }()
		err := local.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2048)
		n, err := local.Read(buffer)
		cancel()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		counter := binary.LittleEndian.Uint32(buffer[n-4 : n])
		if counter != expected {
			t.Fatalf("transport nonce = %d, want %d", counter, expected)
		}
	}
	vc.Kill()
}

func TestBinaryVoiceMessagesAdvanceResumeSequence(t *testing.T) {
	vc := lifecycleVoice()
	vc.handleDAVEBinary([]byte{0x01, 0x02, 27})
	if vc.seqAck != 258 {
		t.Fatalf("binary message sequence = %d, want 258", vc.seqAck)
	}
	vc.handleDAVEBinary([]byte{0xff, 0xff})
	if vc.seqAck != 258 {
		t.Fatal("truncated binary message changed the resume sequence")
	}
	vc.Kill()
}

func TestTerminalVoiceCloseCleansConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, _, err = ws.ReadMessage()
		if err == nil {
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4014, "disconnected"), time.Now().Add(time.Second))
		}
	}))
	defer server.Close()
	vc := lifecycleVoice()
	vc.session.State = NewState()
	vc.session.State.User = &User{ID: "123"}
	vc.session.Dialer = &websocket.Dialer{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig}
	vc.sessionID = "local-session"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	vc.wsCancel = cancel
	vc.websocket(ctx, strings.TrimPrefix(server.URL, "https://"), "local-token")
	select {
	case <-vc.Dead:
	default:
		t.Fatal("terminal voice close left the connection alive")
	}
	if vc.session.VoiceConnections[vc.GuildID] != nil {
		t.Fatal("terminal voice close left a stale map entry")
	}
}

type voiceLockGate struct {
	sync.Mutex
	once    sync.Once
	entered chan struct{}
}

func (g *voiceLockGate) Lock() {
	g.once.Do(func() { close(g.entered) })
	g.Mutex.Lock()
}

func TestStaleVoiceReadyCannotReplaceTransport(t *testing.T) {
	vc := lifecycleVoice()
	gate := &voiceLockGate{entered: make(chan struct{})}
	vc.Cond = sync.NewCond(gate)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	gate.Mutex.Lock()
	go func() {
		vc.onEvent(ctx, false, []byte(`{"op":2,"d":{"ssrc":55,"port":1,"ip":"127.0.0.1"}}`))
		close(done)
	}()
	<-gate.entered
	cancel()
	gate.Mutex.Unlock()
	<-done
	if vc.op2.SSRC != 0 || vc.udpConn != nil || vc.Err != nil {
		t.Fatal("canceled transport event replaced live connection state")
	}
	err := vc.udpOpen(ctx)
	if !errors.Is(err, context.Canceled) || vc.udpConn != nil {
		t.Fatalf("canceled UDP setup returned %v or created a socket", err)
	}
	vc.Kill()
}

type voiceWriteGate struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (g *voiceWriteGate) Write(data []byte) (int, error) {
	if g.entered != nil {
		close(g.entered)
		<-g.release
		g.entered = nil
	}
	return g.Conn.Write(data)
}

func TestVoiceSenderDropsFrameIfDAVEChangesAfterReadinessCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			_, _, err = ws.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()
	var gate *voiceWriteGate
	dialer := websocket.Dialer{NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		gate = &voiceWriteGate{Conn: conn}
		return gate, nil
	}}
	ws, _, err := dialer.Dial(strings.Replace(server.URL, "http", "ws", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	gate.entered, gate.release = make(chan struct{}), make(chan struct{})
	entered := gate.entered
	local, remote, aead := voiceUDPPair(t)
	vc := lifecycleVoice()
	vc.udpConn, vc.cipher, vc.wsConn = remote, aead, ws
	vc.dave = testDAVESession(t, "123")
	vc.OpusSend <- []byte("private audio")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { vc.opusSender(ctx, 48000, 960); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("sender did not reach speaking notification")
	}
	vc.dave.Reset()
	close(gate.release)
	<-done
	err = local.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = local.Read(make([]byte, 2048))
	if err == nil {
		t.Fatal("DAVE reset caused the sender to transmit plaintext audio")
	}
	vc.Kill()
}

func TestDAVETransitionAcknowledgesPrepareOnce(t *testing.T) {
	ops := make(chan int, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			var message struct {
				Op int `json:"op"`
			}
			err = ws.ReadJSON(&message)
			if err != nil {
				return
			}
			ops <- message.Op
		}
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http", "ws", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	vc := lifecycleVoice()
	vc.wsConn, vc.dave = ws, testDAVESession(t, "123")
	vc.handleDAVEPrepareTransition([]byte(`{"transition_id":1,"protocol_version":0}`))
	vc.handleDAVEExecuteTransition([]byte(`{"transition_id":1}`))
	err = vc.Speaking(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []int{23, 5} {
		select {
		case op := <-ops:
			if op != expected {
				t.Fatalf("voice opcode = %d, want %d; readiness must be acknowledged only before execute", op, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("voice transition did not send its acknowledgement")
		}
	}
	vc.Kill()
}
