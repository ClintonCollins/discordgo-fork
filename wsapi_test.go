package discordgo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestOnEventOP1WithoutAConnectionReturnsAnError(t *testing.T) {
	s := &Session{sequence: new(int64)}

	e, err := s.onEvent(websocket.TextMessage, []byte(`{"op":1,"d":null}`))

	if !errors.Is(err, ErrWSNotFound) {
		t.Fatalf("onEvent returned %v, want ErrWSNotFound", err)
	}
	if e == nil || e.Operation != 1 {
		t.Errorf("onEvent returned event %+v, want the decoded op1 event", e)
	}
}

func TestChannelVoiceJoinFailurePreservesLifecycle(t *testing.T) {
	t.Run("new connection is removed on gateway failure", func(t *testing.T) {
		s := &Session{}
		voice, err := s.ChannelVoiceJoin(context.Background(), "guild", "channel", false, true)
		if !errors.Is(err, ErrWSNotFound) {
			t.Fatalf("ChannelVoiceJoin() error = %v, want ErrWSNotFound", err)
		}
		if len(s.VoiceConnections) != 0 {
			t.Fatal("failed join left a connection in the session")
		}
		if voice == nil || voice.Cond == nil || voice.Dead == nil || voice.OpusSend == nil || voice.OpusRecv == nil {
			t.Fatal("join returned a partially initialized connection")
		}
		select {
		case <-voice.Dead:
		default:
			t.Fatal("failed connection did not signal termination")
		}
	})

	t.Run("existing connection survives gateway failure", func(t *testing.T) {
		dead := make(chan struct{})
		voice := &VoiceConnection{
			Cond:   sync.NewCond(&sync.Mutex{}),
			Status: VoiceConnectionStatusReady,
			Dead:   dead,
			dead:   dead,
		}
		s := &Session{VoiceConnections: map[string]*VoiceConnection{"guild": voice}}
		cond := voice.Cond
		got, err := s.ChannelVoiceJoin(context.Background(), "guild", "channel", false, true)
		if !errors.Is(err, ErrWSNotFound) {
			t.Fatalf("ChannelVoiceJoin() error = %v, want ErrWSNotFound", err)
		}
		if got != voice || s.VoiceConnections["guild"] != voice || voice.Cond != cond || voice.Dead != dead || voice.Status != VoiceConnectionStatusReady {
			t.Fatal("failed rejoin replaced or reset the existing connection")
		}
	})

	t.Run("already canceled request has no side effects", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s := &Session{}
		voice, err := s.ChannelVoiceJoin(ctx, "guild", "channel", false, true)
		if !errors.Is(err, context.Canceled) || voice != nil || len(s.VoiceConnections) != 0 {
			t.Fatalf("canceled join = (%v, %v), connections = %d", voice, err, len(s.VoiceConnections))
		}
	})
}

func TestConcurrentVoiceJoinsShareInitializedConnection(t *testing.T) {
	requests := make(chan struct{}, 2)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(requests)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for range 2 {
			var request voiceChannelJoinOp
			err = conn.ReadJSON(&request)
			if err != nil {
				return
			}
			requests <- struct{}{}
		}
	}))
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s := &Session{wsConn: conn}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		voice *VoiceConnection
		err   error
	}
	results := make(chan result, 2)
	join := func() {
		voice, err := s.ChannelVoiceJoin(ctx, "guild", "channel", false, true)
		results <- result{voice, err}
	}
	waitRequest := func() {
		t.Helper()
		select {
		case _, ok := <-requests:
			if !ok {
				t.Fatal("gateway closed before receiving the voice request")
			}
		case <-ctx.Done():
			t.Fatal("voice request did not reach the gateway")
		}
	}
	go join()
	waitRequest()
	s.RLock()
	voice := s.VoiceConnections["guild"]
	s.RUnlock()
	if voice == nil || voice.Cond == nil || voice.Dead == nil || voice.OpusSend == nil || voice.OpusRecv == nil {
		t.Fatal("gateway observed an uninitialized connection")
	}
	cond := voice.Cond
	dead := voice.Dead
	go join()
	waitRequest()
	if voice.Cond != cond || voice.Dead != dead {
		t.Fatal("second join replaced synchronization on the first connection")
	}
	voice.Cond.L.Lock()
	voice.Status = VoiceConnectionStatusReady
	voice.Cond.Broadcast()
	voice.Cond.L.Unlock()
	for range 2 {
		select {
		case got := <-results:
			if got.err != nil || got.voice != voice {
				t.Fatalf("join returned (%p, %v), want (%p, nil)", got.voice, got.err, voice)
			}
		case <-ctx.Done():
			t.Fatal("join did not observe the ready connection")
		}
	}
	voice.Kill()
}

func TestVoiceStateUpdateRequiresLiveSelfConnection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		user   *User
		status VoiceConnectionStatus
		self   bool
		want   string
	}{
		{name: "state has no user", status: VoiceConnectionStatusNew},
		{name: "another user", user: &User{ID: "other"}, status: VoiceConnectionStatusNew},
		{name: "dead connection", user: &User{ID: "self"}, status: VoiceConnectionStatusDead},
		{name: "server mute and deaf", user: &User{ID: "self"}, status: VoiceConnectionStatusNew, want: "session"},
		{name: "self mute and deaf", user: &User{ID: "self"}, status: VoiceConnectionStatusNew, self: true, want: "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			voice := &VoiceConnection{Cond: sync.NewCond(&sync.Mutex{}), Status: tc.status}
			s := &Session{State: NewState(), VoiceConnections: map[string]*VoiceConnection{"guild": voice}}
			s.State.User = tc.user
			s.onVoiceStateUpdate(&VoiceStateUpdate{VoiceState: &VoiceState{
				GuildID: "guild", UserID: "self", ChannelID: "channel", SessionID: "session",
				Mute: !tc.self, Deaf: !tc.self, SelfMute: tc.self, SelfDeaf: tc.self,
			}})
			if voice.sessionID != tc.want || voice.mute != (tc.want != "") || voice.deaf != (tc.want != "") {
				t.Fatalf("voice state = (%q, mute %v, deaf %v), want session %q", voice.sessionID, voice.mute, voice.deaf, tc.want)
			}
		})
	}
}

func TestHeartbeatLatencyConcurrentUpdates(t *testing.T) {
	const latency = 25 * time.Millisecond
	start := time.Now()
	s := &Session{LastHeartbeatSent: start, LastHeartbeatAck: start.Add(latency)}
	var updates sync.WaitGroup
	updates.Add(1)
	go func() {
		defer updates.Done()
		for i := range 10000 {
			s.Lock()
			s.LastHeartbeatSent = start.Add(time.Duration(i) * time.Second)
			s.LastHeartbeatAck = s.LastHeartbeatSent.Add(latency)
			s.Unlock()
		}
	}()
	defer updates.Wait()
	for range 10000 {
		got := s.HeartbeatLatency()
		if got != latency {
			t.Fatalf("HeartbeatLatency() = %v, want %v", got, latency)
		}
	}
}
