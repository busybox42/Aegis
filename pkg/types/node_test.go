package types

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

func TestNewNode(t *testing.T) {
	// Generate a random Ed25519 key pair for testing
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Define a test TCP address
	addr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}

	// Create a new node
	node := NewNode(publicKey, addr)

	// Check if the node was created correctly
	if node == nil {
		t.Fatal("NewNode returned a nil node")
	}

	// Validate ID length (SHA-1 produces a 20-byte hash)
	if len(node.ID) != 20 {
		t.Errorf("Expected ID length of 20, got %d", len(node.ID))
	}

	// Validate PublicKey assignment
	if !publicKeyEqual(node.PublicKey, publicKey) {
		t.Errorf("PublicKey does not match expected value")
	}

	// Validate Address assignment
	if node.Address.String() != addr.String() {
		t.Errorf("Expected address %v, got %v", addr, node.Address)
	}

	// Validate LastSeen timestamp
	if time.Since(node.LastSeen) > time.Second {
		t.Errorf("LastSeen timestamp is not recent")
	}
}

// Helper function to compare public keys
func publicKeyEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
