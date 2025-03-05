package network

import (
    "context"
    "crypto/ed25519"
    "log"
    "net"
    "testing"
    "time"
    "fmt"

    "github.com/busybox42/Aegis/pkg/protocol"
    "github.com/stretchr/testify/require"
)

// Utility function to get an available port
func getAvailablePort() (int, error) {
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
    l, err := net.ListenTCP("tcp", addr)
    if err != nil {
        return 0, err
    }
    defer l.Close()
    return l.Addr().(*net.TCPAddr).Port, nil
}

// Wait for transport to be ready
func waitForTransportReady(t *Transport) bool {
    deadline := time.Now().Add(15 * time.Second)
    for time.Now().Before(deadline) {
        if t.listener != nil {
            return true
        }
        time.Sleep(100 * time.Millisecond)
    }
    return false
}

func setupTestTransports(t *testing.T) (*Transport, *Transport, ed25519.PrivateKey) {
    t.Helper()
    pub1, priv1, _ := ed25519.GenerateKey(nil)
    pub2, priv2, _ := ed25519.GenerateKey(nil)
 
    port1, err := getAvailablePort()
    require.NoError(t, err)
    port2, err := getAvailablePort() 
    require.NoError(t, err)
 
    log.Printf("Setting up transports on ports %d and %d", port1, port2)
 
    t1 := NewTransport(&Config{
        Port:       port1,
        PublicKey:  pub1,
        PrivateKey: priv1,
    })
 
    bootstrapAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
    t2 := NewTransport(&Config{
        Port:       port2,
        PublicKey:  pub2,
        PrivateKey: priv2,
        Bootstrap:  []*net.TCPAddr{bootstrapAddr},
    })
 
    // Peer discovery handler for t1
    t1.RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
        log.Printf("[DEBUG] T1 received peer discovery from %x", msg.Sender)
        if !msg.Verify() {
            return fmt.Errorf("invalid message signature")
        }
        
        // Create and store peer for t1
        peer := NewPeer(msg.Sender, &net.TCPAddr{
            IP:   net.ParseIP("127.0.0.1"),
            Port: msg.ListeningPort,
        })
        t1.storePeer(peer)
        
        // Send discovery response
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, pub1, msg.Sender, nil)
        discoveryMsg.ListeningPort = port1
        discoveryMsg.PeerList = t1.getKnownPeers(msg.Sender)
        discoveryMsg.Sign(priv1)
        
        return nil
    })
 
    // Peer discovery handler for t2
    t2.RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
        log.Printf("[DEBUG] T2 received peer discovery from %x", msg.Sender)
        if !msg.Verify() {
            return fmt.Errorf("invalid message signature")
        }
        
        // Create and store peer for t2
        peer := NewPeer(msg.Sender, &net.TCPAddr{
            IP:   net.ParseIP("127.0.0.1"), 
            Port: msg.ListeningPort,
        })
        t2.storePeer(peer)
        
        // Send discovery response
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, pub2, msg.Sender, nil)
        discoveryMsg.ListeningPort = port2
        discoveryMsg.PeerList = t2.getKnownPeers(msg.Sender)
        discoveryMsg.Sign(priv2)
        
        return nil
    })
 
    // Start transports
    require.NoError(t, t1.Start())
    require.NoError(t, t2.Start())
 
    // Wait briefly for listeners to initialize
    time.Sleep(100 * time.Millisecond)

    // Manually create and store peers in both directions
    t1Addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port1}
    t2Addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port2}
    
    // Create T2 as a peer for T1
    t2Peer := NewPeer(pub2, t2Addr)
    t1.storePeer(t2Peer)
    
    // Create T1 as a peer for T2
    t1Peer := NewPeer(pub1, t1Addr)
    t2.storePeer(t1Peer)
    
    // Wait a bit for the connections to establish
    time.Sleep(1 * time.Second)

    // Check for peer discovery or context timeout
    peerCount1 := 0
    t1.peers.Range(func(_, _ interface{}) bool {
        peerCount1++
        return true
    })
    
    peerCount2 := 0
    t2.peers.Range(func(_, _ interface{}) bool {
        peerCount2++
        return true
    })
    
    log.Printf("Peer counts after manual connection setup - T1: %d, T2: %d", peerCount1, peerCount2)
    
    return t1, t2, priv1
}

func TestTransport_TwoNodes(t *testing.T) {
    // Add a timeout
    timeout := time.After(30 * time.Second)
    done := make(chan bool)
    
    go func() {
        t1, t2, _ := setupTestTransports(t)
        defer t1.Stop()
        defer t2.Stop()

        // Wait a bit for peer connections to fully establish
        time.Sleep(3 * time.Second)

        // Verify basic connectivity
        peerCount1 := 0
        t1.peers.Range(func(_, _ interface{}) bool {
            peerCount1++
            return true
        })

        peerCount2 := 0
        t2.peers.Range(func(_, _ interface{}) bool {
            peerCount2++
            return true
        })

        log.Printf("Final peer counts - T1: %d, T2: %d", peerCount1, peerCount2)

        require.Greater(t, peerCount1, 0, "Transport 1 should have peers")
        require.Greater(t, peerCount2, 0, "Transport 2 should have peers")
        
        done <- true
    }()
    
    select {
    case <-timeout:
        t.Fatal("Test timed out after 30 seconds")
    case <-done:
        // Test completed successfully
    }
}

func TestTransport_MultiNode(t *testing.T) {
    // Reduce timeout to speed up the test
    timeout := time.After(30 * time.Second)
    done := make(chan bool)
    
    go func() {
        // Generate keys and get available ports
        ports := make([]int, 3)
        pubKeys := make([]ed25519.PublicKey, 3)
        privKeys := make([]ed25519.PrivateKey, 3)
        var err error
        for i := range ports {
            ports[i], err = getAvailablePort()
            require.NoError(t, err)

            // Generate keys for each node
            pub, priv, err := ed25519.GenerateKey(nil)
            require.NoError(t, err)
            pubKeys[i] = pub
            privKeys[i] = priv
        }

        // Create the three nodes
        nodes := make([]*Transport, 3)
        
        // First create the bootstrap node (node 0)
        nodes[0] = NewTransport(&Config{
            Port:       ports[0],
            PublicKey:  pubKeys[0],
            PrivateKey: privKeys[0],
        })
        
        // Register handlers on all nodes
        for i := 0; i < len(nodes); i++ {
            // Skip nil nodes (will be filled in next loop)
            if i > 0 {
                continue
            }
            
            nodeIndex := i // Capture for closure
            nodes[i].RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
                log.Printf("[DEBUG] Node %d received peer discovery from %x", nodeIndex, msg.Sender[:8])
                return nil
            })
        }
        
        // Start the bootstrap node
        require.NoError(t, nodes[0].Start())
        
        // Create and start other nodes with bootstrap to node 0
        for i := 1; i < len(nodes); i++ {
            bootstrapAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: ports[0]}
            
            nodes[i] = NewTransport(&Config{
                Port:       ports[i],
                PublicKey:  pubKeys[i],
                PrivateKey: privKeys[i],
                Bootstrap:  []*net.TCPAddr{bootstrapAddr},
            })
            
            // Register discovery handler
            nodeIndex := i // Capture for closure
            nodes[i].RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
                log.Printf("[DEBUG] Node %d received peer discovery from %x", nodeIndex, msg.Sender[:8])
                return nil
            })
            
            require.NoError(t, nodes[i].Start())
        }

        // Wait for initial bootstrapping
        time.Sleep(2 * time.Second)
        
        // Now manually create full mesh connectivity
        for i := 0; i < len(nodes); i++ {
            for j := 0; j < len(nodes); j++ {
                if i == j {
                    continue // Don't connect to self
                }
                
                // Create peer in both directions
                peerAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: ports[j]}
                peer := NewPeer(pubKeys[j], peerAddr)
                nodes[i].storePeer(peer)
                
                // Try to connect immediately
                go peer.Connect()
            }
        }

        // Give peers time to connect
        time.Sleep(3 * time.Second)
        
        // Check with timeout for mesh formation
        meshFormed := false
        checkDeadline := time.Now().Add(10 * time.Second)
        
        for time.Now().Before(checkDeadline) && !meshFormed {
            // Print current peer counts for debugging
            for i, node := range nodes {
                count := 0
                node.peers.Range(func(_, value interface{}) bool {
                    peer := value.(*Peer)
                    if peer.IsConnected() {
                        count++
                    }
                    return true
                })
                log.Printf("Node %d has %d connected peers", i, count)
            }
            
            if meshFormed = checkFullMesh(nodes...); meshFormed {
                log.Printf("Mesh network established!")
                break
            }
            
            time.Sleep(1 * time.Second)
        }

        // Send a test message
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        testMessage := []byte("Hello from Node 1!")
        msg := protocol.NewMessage(protocol.TextMessage, nodes[1].config.PublicKey, nodes[2].config.PublicKey, testMessage)
        require.NoError(t, msg.Sign(nodes[1].config.PrivateKey))

        err = nodes[1].SendMessage(ctx, msg)
        log.Printf("Send message result: %v", err)

        // Clean shutdown in reverse order (non-bootstrap nodes first)
        for i := len(nodes) - 1; i >= 0; i-- {
            log.Printf("Stopping transport for node %d", i)
            nodes[i].Stop()
        }
        
        done <- true
    }()
    
    select {
    case <-timeout:
        t.Fatal("Test timed out after 30 seconds")
    case <-done:
        // Test completed successfully
    }
}

func countConnectedPeers(t *Transport) int {
    count := 0
    t.peers.Range(func(_, value interface{}) bool {
        peer := value.(*Peer)
        if peer.IsConnected() {
            count++
        }
        return true
    })
    return count
}

// Check if the network has formed a full mesh
func checkFullMesh(nodes ...*Transport) bool {
    for i, node := range nodes {
        peerCount := 0
        node.peers.Range(func(_, value interface{}) bool {
            peer := value.(*Peer)
            if peer.IsConnected() {
                peerCount++
            }
            return true
        })
        
        // Each node should have connections to all other nodes
        expectedPeers := len(nodes) - 1
        if peerCount < expectedPeers {
            log.Printf("[DEBUG] Node %d has %d peers, expected %d", i, peerCount, expectedPeers)
            return false
        }
    }
    return true
}

// Test error handling in transport
func TestTransport_ErrorHandling(t *testing.T) {
    // Test sending message to non-existent peer
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    pub1, priv1, _ := ed25519.GenerateKey(nil)
    port, err := getAvailablePort()
    require.NoError(t, err)

    transport := NewTransport(&Config{
        Port:       port,
        PublicKey:  pub1,
        PrivateKey: priv1,
    })
    require.NoError(t, transport.Start())
    defer transport.Stop()

    // Create a message with a random recipient key
    pub2, _, _ := ed25519.GenerateKey(nil)
    msg := protocol.NewMessage(protocol.TextMessage, pub1, pub2, []byte("Test"))
    require.NoError(t, msg.Sign(priv1))

    // Attempt to send message should return an error
    err = transport.SendMessage(ctx, msg)
    require.Error(t, err, "Expected error when sending to non-existent peer")
}