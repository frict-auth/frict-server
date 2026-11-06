package push

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Fake is a Sender for tests. Every message it is given arrives on Sent,
// whether or not the send then fails.
type Fake struct {
	// Err, if set, is what every Send returns after recording the message.
	Err error
	// Gate, if set, holds every Send until it is closed or ctx ends.
	Gate chan struct{}

	sent chan Message
	n    atomic.Int64
}

func NewFake() *Fake { return &Fake{sent: make(chan Message, 256)} }

// Sent delivers each message in the order Send was called.
func (f *Fake) Sent() <-chan Message { return f.sent }

func (f *Fake) Send(ctx context.Context, m Message) (string, error) {
	f.sent <- m
	if f.Gate != nil {
		select {
		case <-f.Gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if f.Err != nil {
		return "", f.Err
	}
	return fmt.Sprintf("projects/fake/messages/%d", f.n.Add(1)), nil
}
