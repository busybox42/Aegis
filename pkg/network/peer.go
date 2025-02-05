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
    defer p.mu.Unlock()

    if p.connected && p.conn != nil {
        return nil
    }

    dialer := net.Dialer{Timeout: connTimeout}
    conn, err := dialer.Dial("tcp", p.Address.String())
    if err != nil {
        p.connected = false
        p.conn = nil
        return fmt.Errorf("connection failed: %w", err)
    }

    p.conn = conn
    p.connected = true
    p.lastActive = time.Now()

    go p.handleConnection(conn)

    return nil
}

func (p *Peer) Disconnect() error {
   p.mu.Lock()
   defer p.mu.Unlock()

   if p.conn == nil {
       return nil
   }

   log.Printf("[DEBUG] Disconnecting from peer at %v", p.Address)
   err := p.conn.Close()
   p.conn = nil
   p.connected = false
   return err
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
        return fmt.Errorf("failed to write message length: %w", err)
    }

    if _, err := p.conn.Write(data); err != nil {
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

func (p *Peer) handleConnection(conn net.Conn) {
    p.mu.Lock()
    if p.conn != conn {
        p.mu.Unlock()
        return
    }
    p.connected = true
    p.mu.Unlock()

    // Use a WaitGroup to ensure read loop completes before closing
    var wg sync.WaitGroup
    wg.Add(1)

    // Create channel for coordinating shutdown
    done := make(chan struct{})

    // Read loop
    go func() {
        defer wg.Done()
        for {
            select {
            case <-done:
                return
            default:
                var msgLen uint32
                err := binary.Read(conn, binary.BigEndian, &msgLen)
                if err != nil {
                    return
                }

                if msgLen == 0 {
                    // Keep-alive packet
                    continue
                }

                if msgLen > maxMsgSize {
                    return
                }

                msgData := make([]byte, msgLen)
                if _, err := io.ReadFull(conn, msgData); err != nil {
                    return
                }

                msg, err := protocol.DeserializeMessage(msgData)
                if err != nil {
                    continue
                }

                p.mu.Lock()
                handler := p.handler
                p.mu.Unlock()

                if handler != nil {
                    handler(msg)
                }
                p.updateLastActive()
            }
        }
    }()

    // Keep-alive loop
    ticker := time.NewTicker(5 * time.Second)
    defer func() {
        ticker.Stop()
        close(done)
        wg.Wait()
        
        p.mu.Lock()
        if p.conn == conn {
            p.conn = nil
            p.connected = false
        }
        p.mu.Unlock()
        
        conn.Close()
    }()

    for {
        select {
        case <-ticker.C:
            p.mu.Lock()
            if !p.connected || p.conn != conn {
                p.mu.Unlock()
                return
            }
            // Send keep-alive
            if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
                p.mu.Unlock()
                return
            }
            p.mu.Unlock()
        }
    }
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