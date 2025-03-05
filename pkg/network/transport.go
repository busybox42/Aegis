package network

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/binary"
    "fmt"
    "io"
    "log"
    "net"
    "sync"
    "time"

    "github.com/busybox42/Aegis/pkg/dht"
    "github.com/busybox42/Aegis/pkg/protocol"
    "github.com/busybox42/Aegis/pkg/tor"
    "github.com/busybox42/Aegis/pkg/types"
)

type Transport struct {
    config          *Config
    listener        net.Listener
    dht             *dht.DHT
    peers           sync.Map
    peerConnections sync.Map
    handlers        sync.Map
    ctx             context.Context
    cancel          context.CancelFunc
    mu              sync.RWMutex
    torManager      *tor.TorManager   // Add TorManager
    useTor          bool              // Flag to enable/disable Tor
    onionAddress    string            // Store our .onion address
}

func NewTransport(cfg *Config) *Transport {
    ctx, cancel := context.WithCancel(context.Background())
    return &Transport{
        config:     cfg,
        ctx:        ctx,
        cancel:     cancel,
        useTor:     cfg.UseTor,
    }
}

func (t *Transport) Start() error {
    var err error
    
    if t.useTor {
        log.Printf("Starting transport with Tor on port %d", t.config.Port)
        t.torManager, err = tor.StartTorWithPort(t.config.Port)
        if err != nil {
            return fmt.Errorf("failed to start Tor: %w", err)
        }
        
        t.onionAddress = t.torManager.OnionAddress
        log.Printf("Tor Hidden Service address: %s", t.onionAddress)
        
        // Use a different port for the local listener when Tor is enabled
        // Find an available port
        localListener, err := net.Listen("tcp4", "127.0.0.1:0")
        if err != nil {
            t.torManager.StopTor()
            return fmt.Errorf("failed to start local listener: %w", err)
        }
        
        // Get the dynamically assigned port
        localPort := localListener.Addr().(*net.TCPAddr).Port
        log.Printf("Using local port %d for internal connections", localPort)
        t.listener = localListener
    } else {
        // Original non-Tor listener code
        listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", t.config.Port))
        if err != nil {
            return fmt.Errorf("failed to start listener: %w", err)
        }
        t.listener = listener
    }

    localNode := types.NewNode(t.config.PublicKey, t.listener.Addr().(*net.TCPAddr))
    t.dht = dht.NewDHT(localNode, t)

    go t.acceptLoop()

    // Initialize bootstrap connections after a short delay
    if len(t.config.Bootstrap) > 0 {
        go func() {
            time.Sleep(100 * time.Millisecond) // Allow listener to start
            t.bootstrapNetwork()
        }()
    }

    return nil
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
    
    if t.torManager != nil {
        if err := t.torManager.StopTor(); err != nil {
            log.Printf("Error stopping Tor: %v", err)
        }
    }
    
    if t.listener != nil {
        return t.listener.Close()
    }
    return nil
}

// Add a method to create a Tor-enabled peer
func (t *Transport) newPeer(publicKey ed25519.PublicKey, addr *net.TCPAddr, isOnion bool) *Peer {
    peer := NewPeer(publicKey, addr)
    
    if t.useTor && t.torManager != nil {
        dialer, err := t.torManager.GetSocks5Dialer()
        if err != nil {
            log.Printf("Failed to get Tor SOCKS5 dialer: %v", err)
        } else {
            peer.EnableTor(dialer)
            if isOnion {
                peer.forceOnion = true
            }
        }
    }
    
    return peer
}

func (t *Transport) storePeer(peer *Peer) {
    // Strict validation with detailed logging
    if peer == nil {
        log.Printf("[ERROR] Attempted to store nil peer")
        return
    }

    // Allow storing peers with nil PublicKey for bootstrap purposes
    if peer.PublicKey != nil && bytes.Equal(peer.PublicKey, t.config.PublicKey) {
        return
    }
    
    // Use a unique key if PublicKey is nil
    key := fmt.Sprintf("%x", peer.PublicKey)
    if peer.PublicKey == nil {
        key = fmt.Sprintf("%v", peer.Address)
    }
    
    t.mu.Lock()
    defer t.mu.Unlock()
    
    // Use LoadOrStore with a more robust update mechanism
    existing, loaded := t.peers.LoadOrStore(key, peer)
    if loaded {
        existingPeer := existing.(*Peer)
        
        // Safely update existing peer details
        if peer.Address != nil {
            existingPeer.Address = peer.Address
        }
        if peer.onionAddress != "" {
            existingPeer.onionAddress = peer.onionAddress
        }
    }

    // Attempt connection if possible
    go func() {
        if peer.Address != nil || peer.onionAddress != "" {
            peer.Connect()
        }
    }()
}

// Rest of the Transport implementation remains the same
func (t *Transport) SendMessage(ctx context.Context, msg *protocol.Message) error {
    if !msg.Verify() {
        return fmt.Errorf("invalid message signature")
    }

    var targetPeer *Peer
    t.peers.Range(func(key, value interface{}) bool {
        peer := value.(*Peer)
        if bytes.Equal(peer.PublicKey, msg.Recipient) {
            targetPeer = peer
            return false
        }
        return true
    })

    if targetPeer == nil {
        return fmt.Errorf("peer not found: %x", msg.Recipient)
    }

    if !targetPeer.IsConnected() {
        if err := targetPeer.Connect(); err != nil {
            return fmt.Errorf("connection failed: %w", err)
        }
    }

    if msg.Type == protocol.TextMessage {
        timestamp := time.Now().Format("2006-01-02 15:04:05")
        fmt.Printf("[%s] Sending message to %x\n", timestamp, targetPeer.PublicKey[:8])
    }

    sendCh := make(chan error, 1)
    go func() {
        sendCh <- targetPeer.SendMessage(msg)
    }()

    select {
    case err := <-sendCh:
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}

func (t *Transport) RegisterHandler(msgType protocol.MessageType, handler MessageHandlerFunc) {
    t.handlers.Store(msgType, handler)
    log.Printf("Registered handler for message type %v", msgType)
}

func (t *Transport) FindNode(ctx context.Context, node *types.Node, targetID []byte) ([]*types.Node, error) {
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

    bootstrapAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
    peer := NewPeer(nil, bootstrapAddr)
    
    if t.useTor && t.torManager != nil {
        dialer, err := t.torManager.GetSocks5Dialer()
        if err == nil {
            peer.EnableTor(dialer)
        }
    }
    
    if err := peer.Connect(); err != nil {
        return nil, fmt.Errorf("bootstrap connection failed: %v", err)
    }

    msg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, targetID, nil)
    msg.ListeningPort = t.config.Port
    
    if t.useTor {
        msg.OnionAddress = t.onionAddress
    }
    
    msg.Sign(t.config.PrivateKey)

    if err := peer.SendMessage(msg); err != nil {
        peer.Disconnect()
        return nil, fmt.Errorf("failed to send discovery to bootstrap: %v", err)
    }

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

func (t *Transport) getHandler(msgType protocol.MessageType) (MessageHandlerFunc, bool) {
    if handler, ok := t.handlers.Load(msgType); ok {
        return handler.(MessageHandlerFunc), true
    }
    return nil, false
}

func (t *Transport) handleMessage(msg *protocol.Message) error {
    if handler, ok := t.getHandler(msg.Type); ok {
        return handler(msg)
    }
    return nil
}

func (t *Transport) acceptLoop() {
    for {
        select {
        case <-t.ctx.Done():
            return
        default:
            conn, err := t.listener.Accept()
            if err != nil {
                if t.ctx.Err() != nil {
                    return
                }
                continue
            }
            go t.handleConnection(conn)
        }
    }
}

func (t *Transport) handleConnection(conn net.Conn) {
    defer conn.Close()

    for {
        conn.SetReadDeadline(time.Now().Add(readTimeout))
        
        var msgLen uint32
        if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
            return
        }

        if msgLen > maxMsgSize {
            return
        }

        msgData := make([]byte, msgLen)
        if _, err := io.ReadFull(conn, msgData); err != nil {
            return
        }

        conn.SetReadDeadline(time.Time{})

        msg, err := protocol.DeserializeMessage(msgData)
        if err != nil {
            continue
        }

        switch msg.Type {
        case protocol.PeerDiscovery:
            if err := t.handlePeerDiscovery(conn, msg); err != nil {
                log.Printf("Peer discovery error: %v", err)
            }
        default:
            if handler, ok := t.getHandler(msg.Type); ok {
                if err := handler(msg); err != nil {
                    log.Printf("Handler error: %v", err)
                } else if msg.Type == protocol.TextMessage {
                    //log.Printf("Handled message from peer %x", msg.Sender[:8])
                }
            }
        }
    }
}

func (t *Transport) handlePeerDiscovery(conn net.Conn, msg *protocol.Message) error {
    if !msg.Verify() {
        return fmt.Errorf("invalid message signature")
    }

    t.mu.Lock()
    remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    peerAddr := &net.TCPAddr{
        IP:   remoteAddr.IP,
        Port: msg.ListeningPort,
    }
    
    senderPeer := NewPeer(msg.Sender, peerAddr)
    
    // Store onion address if present
    if msg.OnionAddress != "" {
        senderPeer.onionAddress = msg.OnionAddress
    }
    
    t.mu.Unlock()

    t.storePeer(senderPeer)

    for _, peerInfo := range msg.PeerList {
        if bytes.Equal(peerInfo.PublicKey, t.config.PublicKey) {
            continue
        }
        
        addr, err := net.ResolveTCPAddr("tcp", peerInfo.Address)
        if err != nil {
            continue
        }
        
        newPeer := NewPeer(peerInfo.PublicKey, addr)
        
        // Store onion address if available
        if peerInfo.OnionAddress != "" {
            newPeer.onionAddress = peerInfo.OnionAddress
        }
        
        t.storePeer(newPeer)
    }

    t.mu.Lock()
    response := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, msg.Sender, nil)
    response.ListeningPort = t.config.Port
    
    // Add onion address if we're using Tor
    if t.useTor && t.onionAddress != "" {
        response.OnionAddress = t.onionAddress
    }
    
    response.PeerList = t.getKnownPeersLocked(msg.Sender)
    t.mu.Unlock()
    
    response.Sign(t.config.PrivateKey)
    return sendMessageToConn(conn, response)
}

func (t *Transport) bootstrapNetwork() {
    // First check if we're using Tor and have a bootstrap onion address
    if t.useTor && t.config.BootstrapOnion != "" {
        log.Printf("[DEBUG] Bootstrapping network with onion address: %s", t.config.BootstrapOnion)
        
        // Create a peer with the onion address
        peer := NewPeer(nil, nil) // No public key or TCP address yet
        peer.SetOnionAddress(t.config.BootstrapOnion)
        peer.SetForceOnion(true)
        
        // Get Tor SOCKS dialer
        if t.torManager != nil {
            dialer, err := t.torManager.GetSocks5Dialer()
            if err == nil {
                peer.EnableTor(dialer)
            } else {
                log.Printf("[ERROR] Failed to get Tor SOCKS dialer: %v", err)
                return
            }
        } else {
            log.Printf("[ERROR] Tor manager not available")
            return
        }
        
        // Create discovery message
        discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, nil, nil)
        discoveryMsg.ListeningPort = t.config.Port
        
        if t.onionAddress != "" {
            discoveryMsg.OnionAddress = t.onionAddress
        }
        
        discoveryMsg.Sign(t.config.PrivateKey)
        
        // Connect to the onion address
        if err := peer.Connect(); err != nil {
            log.Printf("[ERROR] Failed to connect to onion bootstrap: %v", err)
            return
        }
        
        // Store the peer
        t.storePeer(peer)
        
        // Send discovery message
        if err := peer.SendMessage(discoveryMsg); err != nil {
            log.Printf("[ERROR] Failed to send discovery to onion bootstrap: %v", err)
            peer.Disconnect()
            return
        }
        
        log.Printf("[DEBUG] Sent discovery message to onion bootstrap %s", t.config.BootstrapOnion)
        
        // Try to read response (no goroutine to avoid leaking)
        if peer.conn != nil {
            peer.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
            
            var respLen uint32
            if err := binary.Read(peer.conn, binary.BigEndian, &respLen); err != nil {
                log.Printf("[WARN] Failed to read response length from onion bootstrap: %v", err)
                return
            }
            
            // Validate response size
            if respLen > maxMsgSize {
                log.Printf("[WARN] Bootstrap response too large: %d bytes", respLen)
                return
            }
            
            respData := make([]byte, respLen)
            if _, err := io.ReadFull(peer.conn, respData); err != nil {
                log.Printf("[WARN] Failed to read response from onion bootstrap: %v", err)
                return
            }
            
            // Process response
            respMsg, err := protocol.DeserializeMessage(respData)
            if err != nil {
                log.Printf("[WARN] Failed to deserialize bootstrap response: %v", err)
                return
            }
            
            if respMsg.Type == protocol.PeerDiscovery {
                log.Printf("[DEBUG] Received peer discovery response from onion bootstrap with %d peers", 
                    len(respMsg.PeerList))
                
                // Update peer's public key if available
                if respMsg.Sender != nil {
                    peer.PublicKey = respMsg.Sender
                }
                
                // Process peer list from response
                for _, peerInfo := range respMsg.PeerList {
                    // Skip ourselves
                    if bytes.Equal(peerInfo.PublicKey, t.config.PublicKey) {
                        continue
                    }
                    
                    var newPeer *Peer
                    if peerInfo.OnionAddress != "" {
                        // Create onion peer
                        newPeer = NewPeer(peerInfo.PublicKey, nil)
                        newPeer.SetOnionAddress(peerInfo.OnionAddress)
                        if t.torManager != nil {
                            dialer, err := t.torManager.GetSocks5Dialer()
                            if err == nil {
                                newPeer.EnableTor(dialer)
                                newPeer.SetForceOnion(true)
                            }
                        }
                    } else if peerInfo.Address != "" {
                        // Create TCP peer
                        addr, err := net.ResolveTCPAddr("tcp", peerInfo.Address)
                        if err != nil {
                            log.Printf("[WARN] Failed to resolve peer address %s: %v", 
                                peerInfo.Address, err)
                            continue
                        }
                        newPeer = NewPeer(peerInfo.PublicKey, addr)
                    }
                    
                    if newPeer != nil {
                        t.storePeer(newPeer)
                    }
                }
            }
        }
        
        return
    }

    // Standard TCP bootstrapping
    if len(t.config.Bootstrap) == 0 {
        log.Println("[WARN] No bootstrap nodes configured")
        return
    }

    log.Printf("[DEBUG] Bootstrapping network with %d TCP nodes", len(t.config.Bootstrap))

    for _, addr := range t.config.Bootstrap {
        if addr == nil {
            log.Println("[WARN] Skipping nil bootstrap address")
            continue
        }

        // Determine if we should use Tor for this bootstrap node
        useTorForBootstrap := t.useTor
        if addr.IP.IsLoopback() || addr.IP.IsPrivate() {
            useTorForBootstrap = false
            log.Printf("[INFO] Using direct connection for local bootstrap node %v", addr)
        }

        // Attempt to connect and discover
        go func(bootstrapAddr *net.TCPAddr, useTor bool) {
            // Create discovery message
            discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, nil, nil)
            discoveryMsg.ListeningPort = t.config.Port
            
            // Include onion address if using Tor
            if t.useTor && t.onionAddress != "" {
                discoveryMsg.OnionAddress = t.onionAddress
            }
            
            discoveryMsg.Sign(t.config.PrivateKey)

            // Choose connection method
            var conn net.Conn
            var err error
            
            if useTor && t.torManager != nil {
                // If using Tor, connect through SOCKS proxy
                dialer, err := t.torManager.GetSocks5Dialer()
                if err == nil {
                    log.Printf("[DEBUG] Connecting to bootstrap node %v via Tor", bootstrapAddr)
                    conn, err = dialer.Dial("tcp", bootstrapAddr.String())
                } else {
                    log.Printf("[ERROR] Failed to get Tor SOCKS dialer: %v", err)
                    return
                }
            } else {
                // Direct connection
                log.Printf("[DEBUG] Connecting directly to bootstrap node %v", bootstrapAddr)
                conn, err = net.DialTimeout("tcp", bootstrapAddr.String(), 5*time.Second)
            }
            
            if err != nil {
                log.Printf("[ERROR] Failed to connect to bootstrap node %v: %v", bootstrapAddr, err)
                return
            }
            defer conn.Close()

            // Serialize and send discovery message
            msgData, err := discoveryMsg.Serialize()
            if err != nil {
                log.Printf("[ERROR] Failed to serialize discovery message: %v", err)
                return
            }

            // Write message length
            if err := binary.Write(conn, binary.BigEndian, uint32(len(msgData))); err != nil {
                log.Printf("[ERROR] Failed to write message length: %v", err)
                return
            }

            // Write message
            if _, err := conn.Write(msgData); err != nil {
                log.Printf("[ERROR] Failed to write discovery message: %v", err)
                return
            }

            log.Printf("[DEBUG] Sent discovery message to bootstrap node %v", bootstrapAddr)
            
            // Wait for and process response
            conn.SetReadDeadline(time.Now().Add(5 * time.Second))
            
            var respLen uint32
            if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
                log.Printf("[WARN] Failed to read response length from bootstrap: %v", err)
                return
            }
            
            // Validate response size
            if respLen > maxMsgSize {
                log.Printf("[WARN] Bootstrap response too large: %d bytes", respLen)
                return
            }

            respData := make([]byte, respLen)
            if _, err := io.ReadFull(conn, respData); err != nil {
                log.Printf("[WARN] Failed to read response from bootstrap: %v", err)
                return
            }

            // Process response
            respMsg, err := protocol.DeserializeMessage(respData)
            if err != nil {
                log.Printf("[WARN] Failed to deserialize bootstrap response: %v", err)
                return
            }

            if respMsg.Type == protocol.PeerDiscovery {
                log.Printf("[DEBUG] Received peer discovery response from bootstrap node with %d peers", len(respMsg.PeerList))
                
                // Store sender as peer
                peer := NewPeer(respMsg.Sender, bootstrapAddr)
                if respMsg.OnionAddress != "" {
                    peer.SetOnionAddress(respMsg.OnionAddress)
                }
                t.storePeer(peer)
                
                // Process peer list from response
                for _, peerInfo := range respMsg.PeerList {
                    // Skip ourselves
                    if bytes.Equal(peerInfo.PublicKey, t.config.PublicKey) {
                        continue
                    }
                    
                    addr, err := net.ResolveTCPAddr("tcp", peerInfo.Address)
                    if err != nil {
                        log.Printf("[WARN] Failed to resolve peer address %s: %v", peerInfo.Address, err)
                        continue
                    }
                    
                    newPeer := NewPeer(peerInfo.PublicKey, addr)
                    if peerInfo.OnionAddress != "" {
                        newPeer.SetOnionAddress(peerInfo.OnionAddress)
                    }
                    
                    t.storePeer(newPeer)
                }
            }
        }(addr, useTorForBootstrap)
    }
}

// GetTorManager returns the TorManager instance used by this transport
func (t *Transport) GetTorManager() *tor.TorManager {
    return t.torManager
}

// StorePeer adds or updates a peer in the transport's peer list
func (t *Transport) StorePeer(peer *Peer) {
    t.storePeer(peer)
}

// getKnownPeersLocked assumes the mutex is already held
func (t *Transport) getKnownPeersLocked(excludeKey []byte) []protocol.PeerInfo {
    var peers []protocol.PeerInfo
    seen := make(map[string]bool)

    t.peers.Range(func(_, value interface{}) bool {
        peer := value.(*Peer)
        if peer.PublicKey == nil || bytes.Equal(peer.PublicKey, excludeKey) || 
           bytes.Equal(peer.PublicKey, t.config.PublicKey) {
            return true
        }

        peerKey := fmt.Sprintf("%x", peer.PublicKey)
        if !seen[peerKey] {
            peerInfo := protocol.PeerInfo{
                PublicKey: peer.PublicKey,
                Address:   peer.Address.String(),
            }
            
            // Add onion address if available
            if peer.onionAddress != "" {
                peerInfo.OnionAddress = peer.onionAddress
            }
            
            peers = append(peers, peerInfo)
            seen[peerKey] = true
        }
        return true
    })
    return peers
}

// getKnownPeers acquires the mutex before getting peers
func (t *Transport) getKnownPeers(excludeKey []byte) []protocol.PeerInfo {
    t.mu.Lock()
    defer t.mu.Unlock()
    return t.getKnownPeersLocked(excludeKey)
}

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

func (t *Transport) RangePeers(f func(publicKey []byte, peer *Peer) bool) {
    t.peers.Range(func(key, value interface{}) bool {
        peer := value.(*Peer)
        return f(peer.PublicKey, peer)
    })
}

// GetOnionAddress returns the .onion address for this transport, if Tor is enabled
func (t *Transport) GetOnionAddress() string {
    return t.onionAddress
}