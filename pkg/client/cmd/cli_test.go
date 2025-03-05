package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"net"
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
	// Get a random available port for testing
	port, err := getAvailablePort()
	if err != nil {
		t.Fatalf("Failed to get available port: %v", err)
	}

	cli := newAegisCLI()

	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	pubKeyPath := filepath.Join(keyDir, fmt.Sprintf("public_%d.key", port))
	privKeyPath := filepath.Join(keyDir, fmt.Sprintf("private_%d.key", port))

	// Ensure cleanup before test
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)

	err = cli.initializeKeys(port)
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

// Helper function to get an available port
func getAvailablePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
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
	
	// Disable Tor for tests
	cli.useTor = false

	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}
	cli.publicKey = pub
	cli.privateKey = priv

	// Get random available ports for testing
	clientPort, err := getAvailablePort()
	if err != nil {
		t.Fatalf("Failed to get available client port: %v", err)
	}
	
	bootstrapPort, err := getAvailablePort()
	if err != nil {
		t.Fatalf("Failed to get available bootstrap port: %v", err)
	}

	// Initialize network 
	err = cli.initializeNetwork(clientPort, bootstrapPort)
	if err != nil {
		t.Fatalf("Failed to initialize network: %v", err)
	}
	defer cli.transport.Stop()

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