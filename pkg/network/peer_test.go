// pkg/network/peer_test.go
package network

import (
    "testing"
    "net"
    "github.com/busybox42/Aegis/pkg/crypto"
    "time"
)

func TestNewPeer(t *testing.T) {
    kp, err := crypto.GenerateKeyPair()
    if err != nil {
        t.Fatalf("Failed to generate key pair: %v", err)
    }

    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
    peer := NewPeer(kp.PublicKey, addr)

    if peer == nil {
        t.Fatal("NewPeer returned nil")
    }

    if !peer.PublicKey.Equal(kp.PublicKey) {
        t.Error("Peer public key does not match input")
    }

    if peer.Address.String() != addr.String() {
        t.Errorf("Expected address %v, got %v", addr, peer.Address)
    }
}

func TestPeerConnection(t *testing.T) {
    // Create a test listener
    listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
    if err != nil {
        t.Fatalf("Failed to create listener: %v", err)
    }
    defer listener.Close()

    kp, _ := crypto.GenerateKeyPair()
    peer := NewPeer(kp.PublicKey, listener.Addr().(*net.TCPAddr))

    // Test connection
    errChan := make(chan error, 1)
    go func() {
        errChan <- peer.Connect()
    }()

    // Accept the connection on the listener side
    conn, err := listener.AcceptTCP()
    if err != nil {
        t.Fatalf("Failed to accept connection: %v", err)
    }
    defer conn.Close()

    // Wait for connection or timeout
    select {
    case err := <-errChan:
        if err != nil {
            t.Fatalf("Failed to connect: %v", err)
        }
    case <-time.After(time.Second):
        t.Fatal("Connection timeout")
    }

    if !peer.IsConnected() {
        t.Error("Peer should be connected")
    }

    // Test disconnection
    if err := peer.Disconnect(); err != nil {
        t.Errorf("Failed to disconnect: %v", err)
    }

    if peer.IsConnected() {
        t.Error("Peer should be disconnected")
    }
}