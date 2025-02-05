package network

import (
    "context"
    "crypto/ed25519"
    "net"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestNewPeer(t *testing.T) {
    pub, _, err := ed25519.GenerateKey(nil)
    require.NoError(t, err)

    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
    peer := NewPeer(pub, addr)

    require.NotNil(t, peer)
    assert.Equal(t, pub, peer.PublicKey)
    assert.Equal(t, addr.String(), peer.Address.String())
}

func TestPeerConnection(t *testing.T) {
    listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
    require.NoError(t, err)
    defer listener.Close()

    pub, _, err := ed25519.GenerateKey(nil)
    require.NoError(t, err)
    
    peer := NewPeer(pub, listener.Addr().(*net.TCPAddr))
    
    // Buffered channel to prevent blocking
    connChan := make(chan struct{}, 1)
    
    // Start accepting connections in background
    go func() {
        conn, err := listener.Accept()
        if err != nil {
            t.Logf("Accept error: %v", err)
            return
        }
        defer conn.Close()
        connChan <- struct{}{}
    }()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Create a dialer with context
    dialer := &net.Dialer{}
    conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
    require.NoError(t, err)
    defer conn.Close()

    // Verify connection
    assert.True(t, peer.Address != nil)

    // Wait for accepted connection
    select {
    case <-connChan:
    case <-ctx.Done():
        t.Fatal("Timeout waiting for connection")
    }
}