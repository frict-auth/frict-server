// Package push wakes a device through FCM. A push carries only an opaque ID
// (docs/device-protocol.md, Push); the device fetches everything else over
// the signed device API, and polls when a push doesn't arrive.
package push

import (
	"context"
	"errors"
)

// Message is one FCM data message to one device.
type Message struct {
	FID  string
	Data map[string]string
}

// Sender delivers a message and returns the message name FCM assigned it.
type Sender interface {
	Send(ctx context.Context, m Message) (name string, err error)
}

// ErrUnregistered means FCM reports the target FID will never be valid
// again.
var ErrUnregistered = errors.New("fcm: target is unregistered")
