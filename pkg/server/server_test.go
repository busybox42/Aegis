package main

import (
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestNewAegisServer ensures that the AegisServer initializes properly.
func TestNewAegisServer(t *testing.T) {
	port := 8081 // Use a non-standard port to avoid conflicts

	server, err := newAegisServer(port)
	if err != nil {
		t.Fatalf("Failed to initialize Aegis server: %v", err)
	}

	// Ensure keys are generated
	if server.publicKey == nil || server.privateKey == nil {
		t.Fatal("Public or private key is nil after initialization")
	}

	// Ensure local node is created
	if server.localNode == nil {
		t.Fatal("Local node is nil after initialization")
	}

	// Ensure transport is initialized
	if server.transport == nil {
		t.Fatal("Transport is nil after initialization")
	}

	// Ensure DHT is initialized
	if server.dht == nil {
		t.Fatal("DHT is nil after initialization")
	}
}

// TestInitializeKeys ensures key generation and loading work correctly.
func TestInitializeKeys(t *testing.T) {
	port := 8082
	server := &AegisServer{}

	// Define expected key file paths
	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	pubKeyPath := filepath.Join(keyDir, "public_8082.key")
	privKeyPath := filepath.Join(keyDir, "private_8082.key")

	// Ensure cleanup before test
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)

	err := server.initializeKeys(port)
	if err != nil {
		t.Fatalf("Failed to initialize keys: %v", err)
	}

	// Check if files exist
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Errorf("Public key file not created: %v", err)
	}
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		t.Errorf("Private key file not created: %v", err)
	}

	// Ensure keys are loaded correctly
	if server.publicKey == nil || server.privateKey == nil {
		t.Fatal("Public or private key is nil after initialization")
	}

	// Cleanup
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)
}

// TestInitializeNetwork ensures that the network initializes properly.
func TestInitializeNetwork(t *testing.T) {
	port := 8083
	server := &AegisServer{}

	// Generate dummy keys for testing
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}
	server.publicKey = pub
	server.privateKey = priv

	err = server.initializeNetwork(port)
	if err != nil {
		t.Fatalf("Failed to initialize network: %v", err)
	}

	// Ensure local node is created
	if server.localNode == nil {
		t.Fatal("Local node is nil after network initialization")
	}

	// Ensure address is assigned correctly
	expectedAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	if server.localNode.Address.String() != expectedAddr.String() {
		t.Errorf("Expected address %v, got %v", expectedAddr, server.localNode.Address)
	}

	// Ensure transport is initialized
	if server.transport == nil {
		t.Fatal("Transport is nil after network initialization")
	}

	// Ensure DHT is initialized
	if server.dht == nil {
		t.Fatal("DHT is nil after network initialization")
	}
}
