package discordgo

import (
	"context"
	"sync"
	"testing"
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
