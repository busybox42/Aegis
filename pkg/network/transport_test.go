package network

import (
        "bytes"
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

func getAvailablePort() (int, error) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

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
 
    t1.RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
        if !msg.Verify() {
            return fmt.Errorf("invalid message signature")
        }
        
        peer := NewPeer(msg.Sender, &net.TCPAddr{
            IP:   net.ParseIP("127.0.0.1"),
            Port: msg.ListeningPort,
        })
        peer.connected = true
        t1.peers.Store(string(msg.Sender), peer)
        
        // Force peer to share its peer list
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, pub1, msg.Sender, nil)
        discoveryMsg.ListeningPort = port1
        discoveryMsg.PeerList = t1.getKnownPeers(msg.Sender)
        discoveryMsg.Sign(priv1)
        peer.SendMessage(discoveryMsg)
        
        return nil
    })
 
    t2.RegisterHandler(protocol.PeerDiscovery, func(msg *protocol.Message) error {
        if !msg.Verify() {
            return fmt.Errorf("invalid message signature")
        }
        
        peer := NewPeer(msg.Sender, &net.TCPAddr{
            IP:   net.ParseIP("127.0.0.1"), 
            Port: msg.ListeningPort,
        })
        peer.connected = true
        t2.peers.Store(string(msg.Sender), peer)
        
        // Force peer to share its peer list
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, pub2, msg.Sender, nil)
        discoveryMsg.ListeningPort = port2
        discoveryMsg.PeerList = t2.getKnownPeers(msg.Sender)
        discoveryMsg.Sign(priv2)
        peer.SendMessage(discoveryMsg)
        
        // Connect to any new peers in received peer list
        for _, peerInfo := range msg.PeerList {
            if bytes.Equal(peerInfo.PublicKey, pub2) {
                continue
            }
            addr, err := net.ResolveTCPAddr("tcp", peerInfo.Address)
            if err != nil {
                continue 
            }
            newPeer := NewPeer(peerInfo.PublicKey, addr)
            t2.peers.Store(string(peerInfo.PublicKey), newPeer)
            go newPeer.Connect()
        }
        
        return nil
    })
 
    require.NoError(t, t1.Start())
    require.NoError(t, t2.Start())
 
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
 
    readyChan := make(chan struct{}, 2)
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                if t1.listener != nil && t2.listener != nil {
                    readyChan <- struct{}{}
                    readyChan <- struct{}{}
                    return
                }
                time.Sleep(100 * time.Millisecond)
            }
        }
    }()
 
    for i := 0; i < 2; i++ {
        select {
        case <-readyChan:
            continue
        case <-ctx.Done():
            t.Fatal("Transports failed to start within timeout")
        }
    }
 
    return t1, t2, priv1
}

func TestTransport_MultiNode(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    // Generate keys and get available ports
    ports := make([]int, 3)
    var err error
    for i := range ports {
        ports[i], err = getAvailablePort()
        require.NoError(t, err)
    }

    // Create the three nodes
    nodes := make([]*Transport, 3)
    for i := range nodes {
        pub, priv, err := ed25519.GenerateKey(nil)
        require.NoError(t, err)

        config := &Config{
            Port:       ports[i],
            PublicKey:  pub,
            PrivateKey: priv,
            Bootstrap:  []*net.TCPAddr{{IP: net.ParseIP("127.0.0.1"), Port: ports[0]}},
        }
        
        nodes[i] = NewTransport(config)
        require.NoError(t, nodes[i].Start())
    }

    // Create channel for message verification
    msgReceived := make(chan []byte, 1)

    // Register message handlers
    nodes[2].RegisterHandler(protocol.TextMessage, func(msg *protocol.Message) error {
        log.Printf("Node 3 received message: %s", string(msg.Content))
        msgReceived <- msg.Content
        return nil
    })

    // Wait for mesh network formation
    success := make(chan bool, 1)
    go func() {
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                if checkFullMesh(nodes...) {
                    success <- true
                    return
                }
            }
        }
    }()

    select {
    case <-success:
        log.Printf("Mesh network established")
    case <-ctx.Done():
        t.Fatal("Timeout waiting for mesh network")
    }

    // Test message delivery
    testMessage := []byte("Hello from Node 2!")
    msg := protocol.NewMessage(protocol.TextMessage, nodes[1].config.PublicKey, nodes[2].config.PublicKey, testMessage)
    require.NoError(t, msg.Sign(nodes[1].config.PrivateKey))

    log.Printf("Sending test message from Node 2 to Node 3")
    err = nodes[1].SendMessage(ctx, msg)
    require.NoError(t, err, "Failed to send test message")

    // Verify message receipt
    select {
    case received := <-msgReceived:
        require.Equal(t, testMessage, received, "Received message doesn't match sent message")
        log.Printf("Message delivery verified successfully")
    case <-time.After(5 * time.Second):
        t.Fatal("Timeout waiting for message receipt")
    }

    // Clean shutdown
    for _, node := range nodes {
        node.Stop()
    }
}

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
