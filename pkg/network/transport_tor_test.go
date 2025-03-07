package network

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/busybox42/Aegis/pkg/protocol"
)

// Helper function for creating test messages
func NewTestMessage(content []byte, sender, recipient ed25519.PublicKey) *protocol.Message {
	msg := &protocol.Message{
		Type:      protocol.TextMessage,
		Sender:    sender,
		Recipient: recipient,
		Content:   content,
		Timestamp: time.Now(),
	}
	return msg
}

func TestTorTransport(t *testing.T) {
	// Rest of the test implementation...
}
