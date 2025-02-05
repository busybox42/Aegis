// pkg/protocol/message_test.go
package protocol

import (
    "testing"
    "github.com/busybox42/Aegis/pkg/crypto"
    "bytes"
)

func TestNewMessage(t *testing.T) {
    // Generate a test key pair
    senderKP, err := crypto.GenerateKeyPair()
    if err != nil {
        t.Fatalf("Failed to generate sender key pair: %v", err)
    }

    recipientKP, err := crypto.GenerateKeyPair()
    if err != nil {
        t.Fatalf("Failed to generate recipient key pair: %v", err)
    }

    content := []byte("test message")
    
    msg := NewMessage(TextMessage, senderKP.PublicKey, recipientKP.PublicKey, content)

    if msg == nil {
        t.Fatal("NewMessage returned nil")
    }

    if msg.Type != TextMessage {
        t.Errorf("Expected message type %v, got %v", TextMessage, msg.Type)
    }

    if !bytes.Equal(msg.Content, content) {
        t.Error("Message content does not match input")
    }

    if msg.Timestamp.IsZero() {
        t.Error("Message timestamp was not set")
    }

    if len(msg.ID) == 0 {
        t.Error("Message ID was not generated")
    }
}

func TestMessageSigningAndVerification(t *testing.T) {
    senderKP, _ := crypto.GenerateKeyPair()
    recipientKP, _ := crypto.GenerateKeyPair()
    content := []byte("test message")

    msg := NewMessage(TextMessage, senderKP.PublicKey, recipientKP.PublicKey, content)
    
    // Test signing
    err := msg.Sign(senderKP.PrivateKey)
    if err != nil {
        t.Fatalf("Failed to sign message: %v", err)
    }

    // Test verification
    if !msg.Verify() {
        t.Error("Message verification failed for valid signature")
    }

    // Test tampering detection
    tamperedMsg := *msg
    tamperedMsg.Content = []byte("tampered content")
    if tamperedMsg.Verify() {
        t.Error("Verification passed for tampered message")
    }
}

func TestMessageSerializationRoundTrip(t *testing.T) {
    senderKP, _ := crypto.GenerateKeyPair()
    recipientKP, _ := crypto.GenerateKeyPair()
    content := []byte("test message")
    
    original := NewMessage(TextMessage, senderKP.PublicKey, recipientKP.PublicKey, content)
    original.Sign(senderKP.PrivateKey)

    data, err := original.Serialize()
    if err != nil {
        t.Fatalf("Serialize failed: %v", err)
    }

    recovered, err := DeserializeMessage(data)
    if err != nil {
        t.Fatalf("Deserialize failed: %v", err)
    }

    if !bytes.Equal(original.ID, recovered.ID) {
        t.Error("ID mismatch")
    }
    if original.Type != recovered.Type {
        t.Error("Type mismatch")
    }
    if !bytes.Equal(original.Sender, recovered.Sender) {
        t.Error("Sender mismatch")
    }
    if !bytes.Equal(original.Content, recovered.Content) {
        t.Error("Content mismatch")
    }
    if !bytes.Equal(original.Signature, recovered.Signature) {
        t.Error("Signature mismatch")
    }
    if !recovered.Verify() {
        t.Error("Signature verification failed")
    }
}