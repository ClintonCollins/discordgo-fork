package discordgo

import (
	"errors"
	"testing"

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
