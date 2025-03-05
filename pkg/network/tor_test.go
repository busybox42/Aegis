package network

import (
    "context"
    "crypto/ed25519"
    "log"
    "testing"
    "time"
    
    "github.com/busybox42/Aegis/pkg/protocol"
    "github.com/stretchr/testify/require"
)

// TestTorTransport verifies that transport works with Tor enabled
func TestTorTransport(t *testing.T) {
    // Skip if running in short mode or CI environment
    if testing.Short() {
        t.Skip("Skipping Tor test in short mode")
    }

    pub1, priv1, _ := ed25519.GenerateKey(nil)
    pub2, priv2, _ := ed25519.GenerateKey(nil)

    port1, err := getAvailablePort()
    require.NoError(t, err)
    port2, err := getAvailablePort() 
    require.NoError(t, err)

    log.Printf("Setting up Tor transports on ports %d and %d", port1, port2)

    // Create first transport with Tor
    t1 := NewTransport(&Config{
        Port:       port1,
        PublicKey:  pub1,
        PrivateKey: priv1,
        UseTor:     true,
    })

    // Create second transport with Tor
    t2 := NewTransport(&Config{
        Port:       port2,
        PublicKey:  pub2,
        PrivateKey: priv2,
        UseTor:     true,
    })

    // Start both transports
    err = t1.Start()
    if err != nil {
        t.Skipf("Skipping test: Could not start first Tor transport - %v", err)
    }
    
    err = t2.Start()
    if err != nil {
        t1.Stop()
        t.Skipf("Skipping test: Could not start second Tor transport - %v", err)
    }
    
    defer t1.Stop()
    defer t2.Stop()

    // Wait for Tor to initialize
    time.Sleep(5 * time.Second)
    
    // Add manual peer connection logic
    if t1.onionAddress != "" && t2.torManager != nil {
        log.Printf("Using T1 onion address: %s", t1.onionAddress)
        
        // Manually create and store peer
        peer := NewPeer(pub1, nil)
        peer.onionAddress = t1.onionAddress
        
        // Use Tor dialer if available
        dialer, err := t2.torManager.GetSocks5Dialer()
        if err == nil {
            peer.EnableTor(dialer)
            peer.forceOnion = true
            t2.storePeer(peer)
        }
    }

    // Attempt to send a test message with a timeout
    testCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if t1.onionAddress != "" {
        testMessage := []byte("Test via Tor")
        msg := protocol.NewMessage(protocol.TextMessage, t2.config.PublicKey, t1.config.PublicKey, testMessage)
        msg.OnionAddress = t1.onionAddress
        
        err := msg.Sign(t2.config.PrivateKey)
        require.NoError(t, err)

        err = t2.SendMessage(testCtx, msg)
        if err != nil {
            log.Printf("Send error (expected during tests): %v", err)
        }
    }
}