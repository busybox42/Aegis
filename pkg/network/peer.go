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

   "github.com/busybox42/Aegis/pkg/protocol"
)

type MessageHandler func(*protocol.Message) error

type Peer struct {
    PublicKey   ed25519.PublicKey
    Address     *net.TCPAddr
    conn        net.Conn
    mu          sync.RWMutex
    handler     MessageHandler
    connected   bool
    lastActive  time.Time
    connecting  bool  // New field to prevent duplicate connection attempts
 }

func NewPeer(publicKey ed25519.PublicKey, addr *net.TCPAddr) *Peer {
   return &Peer{
       PublicKey: publicKey,
       Address:   addr,
       lastActive: time.Now(),
   }
}

func (p *Peer) Connect() error {
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

    // Use a shorter timeout for initial connection
    dialer := net.Dialer{Timeout: 3 * time.Second}
    conn, err := dialer.Dial("tcp", p.Address.String())
    if err != nil {
        return fmt.Errorf("connection failed: %w", err)
    }

    p.mu.Lock()
    if p.connected {
        conn.Close()
        p.mu.Unlock()
        return nil
    }

    p.conn = conn
    p.connected = true
    p.lastActive = time.Now()
    p.mu.Unlock()

    // Start connection handler
    go p.handleConnection(conn)
    return nil
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

    log.Printf("[DEBUG] Sending message type %v to peer %x", msg.Type, msg.Recipient)
    
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

func (t *Transport) handleMessage(msg *protocol.Message) error {
    if handler, ok := t.getHandler(msg.Type); ok {
        return handler(msg)
    }
    return nil
}

func (p *Peer) WaitForConnection(timeout time.Duration) bool {
   deadline := time.Now().Add(timeout)
   for time.Now().Before(deadline) {
       if p.IsConnected() {
           return true
       }
       time.Sleep(100 * time.Millisecond)
   }
   return false
}

func (p *Peer) ensureConnected() error {
    p.mu.RLock()
    if p.connected && p.conn != nil {
        p.mu.RUnlock()
        return nil
    }
    p.mu.RUnlock()
    
    return p.Connect()
}