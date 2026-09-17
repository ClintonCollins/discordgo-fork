package discordgo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
)

func cleanupGatewayVoice(t *testing.T) (*Session, *VoiceConnection) {
	t.Helper()
	s, err := New("Bot test")
	if err != nil {
		t.Fatal(err)
	}
	s.ShouldReconnectOnError = false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, upgradeErr := upgrader.Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"op":10,"d":{"heartbeat_interval":60000}}`))
		_, _, readErr := conn.ReadMessage()
		if readErr != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"op":0,"t":"READY","s":1,"d":{"user":{"id":"bot","username":"bot"},"session_id":"test","guilds":[]}}`))
		for {
			var event struct {
				Op   int             `json:"op"`
				Data json.RawMessage `json:"d"`
			}
			readErr = conn.ReadJSON(&event)
			if readErr != nil {
				return
			}
			switch event.Op {
			case 1:
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"op":11}`))
			case 4:
				var request voiceChannelJoinData
				readErr = json.Unmarshal(event.Data, &request)
				if readErr != nil {
					return
				}
				if request.ChannelID == nil {
					continue // Deliberately omit the disconnect acknowledgement.
				}
				s.RLock()
				voice := s.VoiceConnections["guild"]
				s.RUnlock()
				voice.Cond.L.Lock()
				voice.Status = VoiceConnectionStatusReady
				voice.Cond.Broadcast()
				voice.Cond.L.Unlock()
			}
		}
	}))
	t.Cleanup(server.Close)
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")
	err = s.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	voice, err := s.ChannelVoiceJoin(ctx, "guild", "channel", false, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(voice.Kill)
	return s, voice
}

func requireVoiceCleanup(t *testing.T, voice *VoiceConnection) {
	t.Helper()
	voice.session.RLock()
	registered := voice.session.VoiceConnections[voice.GuildID] == voice
	voice.session.RUnlock()
	voice.Cond.L.Lock()
	status := voice.Status
	voice.Cond.L.Unlock()
	if registered || status != VoiceConnectionStatusDead {
		t.Errorf("voice after cleanup: registered=%v, status=%v; want unregistered and dead", registered, status)
	}
	select {
	case <-voice.Dead:
	default:
		t.Error("voice cleanup did not close the dead notification")
	}
	select {
	case _, open := <-voice.OpusSend:
		if open {
			t.Error("voice send channel remains open")
		}
	default:
		t.Error("voice send channel remains open")
	}
}

func TestDisconnectCleansVoiceAfterFailure(t *testing.T) {
	for _, name := range []string{"missing acknowledgement", "gateway unavailable", "already canceled"} {
		t.Run(name, func(t *testing.T) {
			var voice *VoiceConnection
			if name == "missing acknowledgement" {
				_, voice = cleanupGatewayVoice(t)
			} else {
				voice = lifecycleVoice()
				voice.Status = VoiceConnectionStatusReady
				t.Cleanup(voice.Kill)
			}
			transportCtx, stopTransport := context.WithCancel(t.Context())
			defer stopTransport()
			voice.wsCancel = stopTransport
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			want := context.DeadlineExceeded
			if name == "gateway unavailable" {
				want = ErrWSNotFound
			}
			if name == "already canceled" {
				cancel()
				want = context.Canceled
			}
			err := voice.Disconnect(ctx)
			if !errors.Is(err, want) {
				t.Fatalf("Disconnect() error = %v, want %v", err, want)
			}
			requireVoiceCleanup(t, voice)
			if transportCtx.Err() == nil {
				t.Error("disconnect failure left the voice transport running")
			}
		})
	}
}

func TestSessionCloseCleansVoice(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(map[bool]string{false: "gateway absent", true: "gateway connected"}[connected], func(t *testing.T) {
			var s *Session
			var voice *VoiceConnection
			if connected {
				s, voice = cleanupGatewayVoice(t)
			} else {
				voice = lifecycleVoice()
				s = voice.session
				t.Cleanup(voice.Kill)
			}
			transportCtx, stopTransport := context.WithCancel(t.Context())
			defer stopTransport()
			voice.wsCancel = stopTransport
			err := s.Close()
			if err != nil {
				t.Fatal(err)
			}
			requireVoiceCleanup(t, voice)
			if transportCtx.Err() == nil {
				t.Error("session close left the voice transport running")
			}
			err = s.Close()
			if err != nil {
				t.Fatalf("second Close() = %v", err)
			}
		})
	}
}

func TestSessionCloseDrainsActiveVoiceReceiver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		voice := lifecycleVoice()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		voice.wsCancel = cancel
		voice.receiverWG.Add(1)
		releaseReceiver := make(chan struct{})
		go func() {
			defer voice.receiverWG.Done()
			<-ctx.Done()
			<-releaseReceiver
		}()
		err := voice.session.Close()
		if err != nil {
			t.Fatal(err)
		}
		requireVoiceCleanup(t, voice)
		synctest.Wait()
		select {
		case <-voice.OpusRecv:
			t.Error("receive channel closed before its active receiver stopped")
		default:
		}
		close(releaseReceiver)
		synctest.Wait()
		select {
		case _, open := <-voice.OpusRecv:
			if open {
				t.Error("receive channel remains open after the receiver stopped")
			}
		default:
			t.Error("receive channel remains open after the receiver stopped")
		}
	})
}

func TestGatewayCloseForResumePreservesVoice(t *testing.T) {
	voice := lifecycleVoice()
	t.Cleanup(voice.Kill)
	voice.Status = VoiceConnectionStatusReady
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	voice.wsCancel = cancel
	err := voice.session.closeWithCode(websocket.CloseServiceRestart, false)
	if err != nil {
		t.Fatal(err)
	}
	if voice.session.VoiceConnections[voice.GuildID] != voice || voice.Status != VoiceConnectionStatusReady || ctx.Err() != nil {
		t.Fatal("gateway-only close destroyed the established voice transport")
	}
	select {
	case <-voice.Dead:
		t.Fatal("gateway-only close terminated the established voice connection")
	default:
	}
	err = voice.session.Close()
	if err != nil {
		t.Fatal(err)
	}
	requireVoiceCleanup(t, voice)
}
