package main

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitForPortRelease waits until a port is available
func waitForPortRelease(port int) {
	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return // Port is available
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
}

// TestNewAegisServer ensures that the AegisServer initializes properly.
func TestNewAegisServer(t *testing.T) {
	port := 8081
	waitForPortRelease(port)

	server, err := newAegisServer(port, false)
	if err != nil {
		t.Fatalf("Failed to initialize Aegis server: %v", err)
	}
	defer server.Shutdown()

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
	waitForPortRelease(port)

	server := &AegisServer{}

	// Define expected key file paths
	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	pubKeyPath := filepath.Join(keyDir, fmt.Sprintf("public_%d.key", port))
	privKeyPath := filepath.Join(keyDir, fmt.Sprintf("private_%d.key", port))

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
	port := 8086 // Changed from 8083 to avoid conflict
	waitForPortRelease(port)

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

	// Ensure proper cleanup
	defer server.Shutdown()

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

func TestServerShutdown(t *testing.T) {
	port := 8083
	waitForPortRelease(port)

	server, err := newAegisServer(port, false)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Get the address before shutting down
	addr := server.localNode.Address.String()

	// Test shutdown
	if err := server.Shutdown(); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// Give the system a moment to fully release the port
	time.Sleep(100 * time.Millisecond)

	// Verify cleanup by attempting to connect to the address
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		conn.Close()
		t.Error("Server still accepting connections after shutdown")
	}
}

func TestTorServerShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Tor test in short mode")
	}

	port := 8084
	waitForPortRelease(port)

	server, err := newAegisServer(port, true)
	if err != nil {
		t.Fatalf("Failed to create Tor server: %v", err)
	}

	// Store the data directory path for verification
	torDataDir := server.torManager.DataDir

	// Test shutdown
	if err := server.Shutdown(); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// Verify Tor cleanup
	if _, err := os.Stat(torDataDir); !os.IsNotExist(err) {
		t.Error("Tor data directory not cleaned up after shutdown")
	}
}

func TestKeyPersistence(t *testing.T) {
	port := 8085
	waitForPortRelease(port)

	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	pubKeyPath := filepath.Join(keyDir, fmt.Sprintf("public_%d.key", port))
	privKeyPath := filepath.Join(keyDir, fmt.Sprintf("private_%d.key", port))

	// Clean up any existing keys
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)

	// Create server to generate keys
	srv1, err := newAegisServer(port, false)
	if err != nil {
		t.Fatalf("Failed to create first server: %v", err)
	}
	srv1.Shutdown()

	// Create second server to load existing keys
	srv2, err := newAegisServer(port, false)
	if err != nil {
		t.Fatalf("Failed to create second server: %v", err)
	}
	defer srv2.Shutdown()

	// Verify keys match
	if string(srv1.publicKey) != string(srv2.publicKey) {
		t.Error("Public keys don't match between server instances")
	}
	if string(srv1.privateKey) != string(srv2.privateKey) {
		t.Error("Private keys don't match between server instances")
	}

	// Clean up
	os.Remove(pubKeyPath)
	os.Remove(privKeyPath)
}
