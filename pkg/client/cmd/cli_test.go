package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewAegisCLI ensures that a new AegisCLI instance is properly initialized.
func TestNewAegisCLI(t *testing.T) {
	cli := newAegisCLI()

	if cli == nil {
		t.Fatal("Failed to initialize AegisCLI")
	}

	if len(cli.messageHistory) != 0 {
		t.Errorf("Expected empty message history, got %d entries", len(cli.messageHistory))
	}
}

// TestInitializeKeys ensures key generation and loading work as expected.
func TestInitializeKeys(t *testing.T) {
	port := 9090
	cli := newAegisCLI()

	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	pubKeyPath := filepath.Join(keyDir, "public_9090.key")
	privKeyPath := filepath.Join(keyDir, "private_9090.key")

	// Ensure cleanup before test
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)

	err := cli.initializeKeys(port)
	if err != nil {
		t.Fatalf("Failed to initialize keys: %v", err)
	}

	// Check if files exist
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Errorf("Public key file not created")
	}
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		t.Errorf("Private key file not created")
	}

	// Ensure keys are loaded
	if cli.publicKey == nil || cli.privateKey == nil {
		t.Fatal("Public or private key is nil after initialization")
	}

	// Cleanup
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)
}

// TestAddToHistory ensures that messages are correctly added to the history.
func TestAddToHistory(t *testing.T) {
	cli := newAegisCLI()

	record := MessageRecord{
		Timestamp: time.Now(),
		Sender:    "Alice",
		Recipient: "Bob",
		Content:   "Hello",
		Status:    "sent",
	}

	cli.addToHistory(record)

	cli.historyMu.RLock()
	defer cli.historyMu.RUnlock()

	if len(cli.messageHistory) != 1 {
		t.Fatalf("Expected 1 message in history, got %d", len(cli.messageHistory))
	}

	lastRecord := cli.messageHistory[0]
	if lastRecord.Content != "Hello" {
		t.Errorf("Expected message content 'Hello', got %s", lastRecord.Content)
	}
}

// TestSendMessage ensures that sending a message records it in history.
func TestSendMessage(t *testing.T) {
	cli := newAegisCLI()

	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}
	cli.publicKey = pub
	cli.privateKey = priv

	// Initialize network 
	err = cli.initializeNetwork(9092, 8080)
	if err != nil {
		t.Fatalf("Failed to initialize network: %v", err)
	}

	// Simulate a recipient key
	recipient := make([]byte, 32)
	hex.Decode(recipient, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

	err = cli.sendMessage(recipient, "Test message")

	// Even if sending fails due to no actual server, the function should not panic
	if err != nil {
		t.Logf("Expected failure due to missing peer, got: %v", err)
	}

	// Ensure the message was added to history
	cli.historyMu.RLock()
	defer cli.historyMu.RUnlock()

	if len(cli.messageHistory) != 1 {
		t.Fatalf("Expected 1 message in history, got %d", len(cli.messageHistory))
	}

	lastRecord := cli.messageHistory[0]
	if lastRecord.Content != "Test message" {
		t.Errorf("Expected message content 'Test message', got %s", lastRecord.Content)
	}
}

