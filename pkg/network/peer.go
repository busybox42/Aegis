package network

import (
   "crypto/ed25519"
   "encoding/binary"
   "fmt"
   "io"
   "log"
   "net"
   "sync"
   "time"
   "strings"

   "golang.org/x/net/proxy"
   "github.com/busybox42/Aegis/pkg/protocol"
)

type MessageHandler func(*protocol.Message) error

type Peer struct {
    PublicKey    ed25519.PublicKey
    Address      *net.TCPAddr
    conn         net.Conn
    mu           sync.RWMutex
    handler      MessageHandler
    connected    bool
    lastActive   time.Time
    connecting   bool  
    useTor       bool         // Whether to use Tor for this peer
    torDialer    proxy.Dialer // Tor SOCKS dialer
    forceOnion   bool         // Force Tor even for non-onion addresses
    onionAddress string       // .onion address if available
}

func NewPeer(publicKey ed25519.PublicKey, addr *net.TCPAddr) *Peer {
   return &Peer{
       PublicKey: publicKey,
       Address:   addr,
       lastActive: time.Now(),
       useTor:    false, // Default to non-Tor
   }
}

func (p *Peer) EnableTor(dialer proxy.Dialer) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.useTor = true
    p.torDialer = dialer
}

func (p *Peer) Connect() error {
    // Comprehensive nil and state checks with detailed logging
    if p == nil {
        return fmt.Errorf("cannot connect to nil peer")
    }

    p.mu.Lock()
    if p.connected || p.connecting {
        p.mu.Unlock()
        return nil
    }
    p.connecting = true
    p.mu.Unlock()

    defer func() {
        p.mu.Lock()
        p.connecting = false
        p.mu.Unlock()
    }()

    // Set longer timeout for Tor connections (10 seconds instead of 3)
    timeout := 3 * time.Second
    if p.useTor {
        timeout = 10 * time.Second
    }
    dialer := net.Dialer{Timeout: timeout}
    
    // Log connection attempt details
    log.Printf("[PEER] Connection attempt - Tor: %v, Address: %v, Onion: %s", 
        p.useTor, p.Address, p.onionAddress)

    // Validate connection parameters
    if p.useTor && p.torDialer == nil {
        return fmt.Errorf("Tor enabled but no dialer available")
    }

    if p.Address == nil && p.onionAddress == "" {
        return fmt.Errorf("no address or onion address available")
    }

    var conn net.Conn
    var err error

    // Explicit connection logic with better error handling
    switch {
    case p.useTor && p.torDialer != nil && p.onionAddress != "":
        // Ensure onion address ends with .onion
        if !strings.HasSuffix(p.onionAddress, ".onion") {
            return fmt.Errorf("invalid onion address format: %s", p.onionAddress)
        }
        
        // Append default Tor hidden service port if needed
        onionAddr := p.onionAddress
        if !strings.Contains(onionAddr, ":") {
            onionAddr = fmt.Sprintf("%s:8080", onionAddr) // Use server's default port
        }
        log.Printf("[PEER] Connecting via Tor to onion address: %s", onionAddr)
        conn, err = p.torDialer.Dial("tcp", onionAddr)
    case p.useTor && p.torDialer != nil && p.Address != nil:
        log.Printf("[PEER] Connecting via Tor to address: %v", p.Address)
        conn, err = p.torDialer.Dial("tcp", p.Address.String())
    case p.Address != nil:
        log.Printf("[PEER] Connecting directly to address: %v", p.Address)
        conn, err = dialer.Dial("tcp", p.Address.String())
    default:
        return fmt.Errorf("unable to establish connection")
    }

    if err != nil {
        log.Printf("[ERROR] Connection failed: %v", err)
        p.mu.Lock()
        p.connected = false
        p.conn = nil
        p.mu.Unlock()
        return fmt.Errorf("connection failed: %w", err)
    }

    p.mu.Lock()
    // If we already connected in another goroutine
    if p.connected && p.conn != nil {
        conn.Close()
        p.mu.Unlock()
        return nil
    }

    p.conn = conn
    p.connected = true
    p.lastActive = time.Now()
    p.mu.Unlock()

    // Start connection handler in a separate goroutine
    go p.handleConnection(conn)
    
    // Log connection success with the correct address
    successAddr := "unknown"
    if p.onionAddress != "" {
        successAddr = p.onionAddress
    } else if p.Address != nil {
        successAddr = p.Address.String()
    }
    log.Printf("[PEER] Successfully connected to %s", successAddr)
    return nil
}

// SetOnionAddress sets the .onion address for this peer
func (p *Peer) SetOnionAddress(address string) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.onionAddress = address
}

// SetForceOnion sets whether to force Tor usage for this peer
func (p *Peer) SetForceOnion(force bool) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.forceOnion = force
}

func (p *Peer) Disconnect() error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.conn != nil {
        err := p.conn.Close()
        p.conn = nil
        p.connected = false
        return err
    }
    return nil
}

func (p *Peer) handleConnection(conn net.Conn) {
    defer func() {
        p.mu.Lock()
        p.connected = false
        if p.conn == conn {
            p.conn = nil
        }
        p.mu.Unlock()
        conn.Close()
    }()

    for {
        conn.SetReadDeadline(time.Now().Add(30 * time.Second))
        
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
        p.updateLastActive()
    }
}

func (p *Peer) IsConnected() bool {
   p.mu.RLock()
   defer p.mu.RUnlock()
   return p.connected && p.conn != nil
}

func (p *Peer) SetMessageHandler(handler MessageHandler) {
   p.mu.Lock()
   defer p.mu.Unlock()
   p.handler = handler
}

func (p *Peer) SendMessage(msg *protocol.Message) error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if !p.connected || p.conn == nil {
        return fmt.Errorf("peer not connected")
    }
    
    data, err := msg.Serialize()
    if err != nil {
        return fmt.Errorf("serialization error: %w", err)
    }

    if err := binary.Write(p.conn, binary.BigEndian, uint32(len(data))); err != nil {
        p.connected = false
        return fmt.Errorf("failed to write message length: %w", err)
    }

    if _, err := p.conn.Write(data); err != nil {
        p.connected = false
        return fmt.Errorf("failed to write message: %w", err)
    }

    p.lastActive = time.Now()
    return nil
}

func (p *Peer) updateLastActive() {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.lastActive = time.Now()
}

// GetOnionAddress returns the .onion address for this peer
func (p *Peer) GetOnionAddress() string {
    p.mu.RLock()
    defer p.mu.RUnlock()
    return p.onionAddress
}