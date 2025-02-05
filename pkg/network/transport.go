package network

import (
    "bytes"
    "context"
    "encoding/binary"
    "fmt"
    "io"
    "log"
    "net"
    "sync"
    "sync/atomic"
    "time"

    "github.com/busybox42/Aegis/pkg/dht"
    "github.com/busybox42/Aegis/pkg/protocol"
    "github.com/busybox42/Aegis/pkg/types"
)

type Transport struct {
    config          *Config
    listener        net.Listener
    dht             *dht.DHT
    peers           sync.Map
    handlers        sync.Map
    ctx             context.Context
    cancel          context.CancelFunc
    connectionCount int32
}

func NewTransport(cfg *Config) *Transport {
    ctx, cancel := context.WithCancel(context.Background())
    return &Transport{
        config: cfg,
        ctx:    ctx,
        cancel: cancel,
    }
}

func (t *Transport) Start() error {
    listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", t.config.Port))
    if err != nil {
        return fmt.Errorf("failed to start listener: %w", err)
    }
    t.listener = listener
    log.Printf("[DEBUG] Listener started on %v", listener.Addr())

    localNode := types.NewNode(t.config.PublicKey, t.listener.Addr().(*net.TCPAddr))
    t.dht = dht.NewDHT(localNode, t)
    log.Printf("[DEBUG] DHT initialized with local node %x", t.config.PublicKey)

    go t.acceptLoop()
    go t.startPeerRefresh()

    if len(t.config.Bootstrap) > 0 {
        go t.bootstrapNetwork()
    }

    return nil
}

func (t *Transport) bootstrapNetwork() {
    for _, addr := range t.config.Bootstrap {
        log.Printf("[DEBUG] Attempting to bootstrap with node at %v", addr)
        peer := NewPeer(nil, addr)
        
        if err := peer.Connect(); err != nil {
            log.Printf("[WARN] Bootstrap connection failed: %v", err)
            continue
        }

        // Send discovery message
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, nil, nil)
        discoveryMsg.Sign(t.config.PrivateKey)

        // Set message handler before sending discovery
        peer.SetMessageHandler(func(m *protocol.Message) error {
            if m.Type == protocol.PeerDiscovery {
                peer.PublicKey = m.Sender
                t.peers.Store(string(m.Sender), peer)
                log.Printf("[DEBUG] Stored peer with key %x", m.Sender)
            }
            if handler, ok := t.getHandler(m.Type); ok {
                return handler(m)
            }
            return nil
        })

        if err := peer.SendMessage(discoveryMsg); err != nil {
            log.Printf("[ERROR] Failed to send discovery: %v", err)
            peer.Disconnect()
            continue
        }
    }
}

// Add this helper function
func sendMessageToConn(conn net.Conn, msg *protocol.Message) error {
    data, err := msg.Serialize()
    if err != nil {
        return fmt.Errorf("serialization error: %w", err)
    }

    if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
        return fmt.Errorf("failed to write message length: %w", err)
    }

    if _, err := conn.Write(data); err != nil {
        return fmt.Errorf("failed to write message: %w", err)
    }

    return nil
}

func (t *Transport) startPeerRefresh() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            t.refreshPeers()
        case <-t.ctx.Done():
            return
        }
    }
}

func (t *Transport) refreshPeers() {
    var staleNodes []*types.Node
    t.peers.Range(func(key, value interface{}) bool {
        peer := value.(*Peer)
        if time.Since(peer.lastActive) > 15*time.Minute {
            staleNodes = append(staleNodes, types.NewNode(peer.PublicKey, peer.Address))
        }
        return true
    })

    for _, node := range staleNodes {
        t.dht.FindNode(context.Background(), node.PublicKey)
    }
}

func (t *Transport) Stop() error {
    log.Printf("Stopping transport")
    t.cancel()
    t.peers.Range(func(key, value interface{}) bool {
        if peer, ok := value.(*Peer); ok {
            peer.Disconnect()
        }
        return true
    })
    if t.listener != nil {
        return t.listener.Close()
    }
    return nil
}

func (t *Transport) acceptLoop() {
    connID := atomic.AddInt32(&t.connectionCount, 1)
    log.Printf("[%d] Starting accept loop", connID)

    for {
        select {
        case <-t.ctx.Done():
            log.Printf("[%d] Accept loop terminated", connID)
            return
        default:
            conn, err := t.listener.Accept()
            if err != nil {
                if t.ctx.Err() != nil {
                    return
                }
                log.Printf("[%d] Accept error: %v", connID, err)
                continue
            }
            log.Printf("[%d] Accepted new connection from %v", connID, conn.RemoteAddr())
            go t.handleConnection(conn)
        }
    }
}

func (t *Transport) handlePeerDiscovery(conn net.Conn, msg *protocol.Message) error {
    addr := conn.RemoteAddr().(*net.TCPAddr)
    
    // Create or update peer with full information
    peer := NewPeer(msg.Sender, addr)
    peer.conn = conn
    peer.connected = true

    // Store peer with complete information
    t.peers.Store(string(msg.Sender), peer)
    log.Printf("[DEBUG] Stored peer discovery from %x", msg.Sender)

    // Send response with local node information
    resp := protocol.NewMessage(
        protocol.PeerDiscovery, 
        t.config.PublicKey,  // Sender is local node 
        msg.Sender,          // Recipient is the original sender
        []byte(t.listener.Addr().String()), // Additional node info
    )
    resp.Sign(t.config.PrivateKey)

    // Set up message handler
    peer.SetMessageHandler(func(m *protocol.Message) error {
        if handler, ok := t.getHandler(m.Type); ok {
            return handler(m)
        }
        return nil
    })

    // Send response and start connection handling
    if err := peer.SendMessage(resp); err != nil {
        log.Printf("[ERROR] Failed to send discovery response: %v", err)
    }
    go peer.handleConnection(conn)

    return nil
}

func (t *Transport) RegisterHandler(msgType protocol.MessageType, handler MessageHandlerFunc) {
    t.handlers.Store(msgType, handler)
    log.Printf("Registered handler for message type %v", msgType)
}

func (t *Transport) getHandler(msgType protocol.MessageType) (MessageHandlerFunc, bool) {
    handler, ok := t.handlers.Load(msgType)
    if !ok {
        return nil, false
    }
    return handler.(MessageHandlerFunc), true
}

func (t *Transport) SendMessage(ctx context.Context, msg *protocol.Message) error {
    log.Printf("[DEBUG] Attempting to send message to %x", msg.Recipient)
    
    peerI, ok := t.peers.Load(string(msg.Recipient))
    if !ok || peerI == nil {
        // Log all known peers for debugging
        log.Printf("[DEBUG] Peer not found. Known peers:")
        t.peers.Range(func(key, value interface{}) bool {
            peer := value.(*Peer)
            log.Printf("[DEBUG]  - %x @ %v", peer.PublicKey, peer.Address)
            return true
        })
        return fmt.Errorf("peer not found: %x", msg.Recipient)
    }
    
    peer := peerI.(*Peer)
    log.Printf("[DEBUG] Found peer: %x @ %v", peer.PublicKey, peer.Address)

    if !peer.IsConnected() {
        log.Printf("[DEBUG] Peer not connected, attempting to connect")
        if err := peer.Connect(); err != nil {
            log.Printf("[ERROR] Failed to connect to peer: %v", err)
            return fmt.Errorf("failed to connect: %w", err)
        }
    }

    return peer.SendMessage(msg)
}

func (t *Transport) FindNode(ctx context.Context, node *types.Node, targetID []byte) ([]*types.Node, error) {
    // Local peer check remains the same
    var localNodes []*types.Node
    t.peers.Range(func(key, value interface{}) bool {
        peer := value.(*Peer)
        if bytes.Equal(peer.PublicKey, targetID) {
            localNodes = append(localNodes, types.NewNode(peer.PublicKey, peer.Address))
        }
        return true
    })

    if len(localNodes) > 0 {
        return localNodes, nil
    }

    // Try bootstrap node at 8080 explicitly
    bootstrapAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
    peer := NewPeer(nil, bootstrapAddr)
    
    if err := peer.Connect(); err != nil {
        return nil, fmt.Errorf("bootstrap connection failed: %v", err)
    }

    // Send discovery message to bootstrap node
    msg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, targetID, nil)
    msg.Sign(t.config.PrivateKey)

    if err := peer.SendMessage(msg); err != nil {
        peer.Disconnect()
        return nil, fmt.Errorf("failed to send discovery to bootstrap: %v", err)
    }

    // Wait and collect peers
    time.Sleep(1 * time.Second)
    
    var discoveredNodes []*types.Node
    t.peers.Range(func(key, value interface{}) bool {
        peer := value.(*Peer)
        if peer.PublicKey != nil {
            discoveredNodes = append(discoveredNodes, types.NewNode(peer.PublicKey, peer.Address))
        }
        return true
    })

    if len(discoveredNodes) > 0 {
        return discoveredNodes, nil
    }

    return nil, fmt.Errorf("no nodes found for target %x", targetID)
}

func (t *Transport) handleConnection(conn net.Conn) {
    connID := atomic.AddInt32(&t.connectionCount, 1)
    log.Printf("[%d] Handling new connection from %v", connID, conn.RemoteAddr())

    var msgLen uint32
    if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
        log.Printf("[%d] Error reading message length: %v", connID, err)
        return
    }

    msgData := make([]byte, msgLen)
    if _, err := io.ReadFull(conn, msgData); err != nil {
        log.Printf("[%d] Error reading message data: %v", connID, err)
        return
    }

    msg, err := protocol.DeserializeMessage(msgData)
    if err != nil {
        log.Printf("[%d] Error deserializing message: %v", connID, err)
        return
    }

    if !msg.Verify() {
        log.Printf("[%d] Message verification failed", connID)
        return
    }

    if msg.Type == protocol.PeerDiscovery {
        if err := t.handlePeerDiscovery(conn, msg); err != nil {
            log.Printf("[%d] Error handling discovery: %v", connID, err)
        }
        return
    }

    if handler, ok := t.getHandler(msg.Type); ok {
        if err := handler(msg); err != nil {
            log.Printf("[%d] Handler error for message type %v: %v", connID, msg.Type, err)
        }
    }
}