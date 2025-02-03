// pkg/network/peer.go
package network

import (
    "crypto/ed25519"
    "encoding/binary"
    "errors"
    "github.com/busybox42/Aegis/pkg/protocol"
    "io"
    "net"
    "sync"
)

type MessageHandler func(*protocol.Message) error

type Peer struct {
    PublicKey ed25519.PublicKey
    Address   *net.TCPAddr
    conn      net.Conn
    mu        sync.RWMutex
    handler   MessageHandler
}

func NewPeer(publicKey ed25519.PublicKey, addr *net.TCPAddr) *Peer {
    return &Peer{
        PublicKey: publicKey,
        Address:   addr,
    }
}

func (p *Peer) Connect() error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.conn != nil {
        return errors.New("peer already connected")
    }

    conn, err := net.DialTCP("tcp", nil, p.Address)
    if err != nil {
        return err
    }

    p.conn = conn
    return nil
}

func (p *Peer) Disconnect() error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.conn == nil {
        return nil
    }

    err := p.conn.Close()
    p.conn = nil
    return err
}

func (p *Peer) IsConnected() bool {
    p.mu.RLock()
    defer p.mu.RUnlock()
    return p.conn != nil
}

func (p *Peer) SetMessageHandler(handler MessageHandler) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.handler = handler
}

func (p *Peer) SendMessage(msg *protocol.Message) error {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if p.conn == nil {
        return errors.New("peer not connected")
    }

    // Serialize the message
    data, err := msg.Serialize()
    if err != nil {
        return err
    }

    // Send message length first
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
    if _, err := p.conn.Write(lenBuf); err != nil {
        return err
    }

    // Send message data
    _, err = p.conn.Write(data)
    return err
}

func (p *Peer) handleConnection(conn net.Conn) {
    p.mu.Lock()
    p.conn = conn
    p.mu.Unlock()

    defer func() {
        p.mu.Lock()
        p.conn = nil
        p.mu.Unlock()
        conn.Close()
    }()

    for {
        // Read message length
        lenBuf := make([]byte, 4)
        if _, err := io.ReadFull(conn, lenBuf); err != nil {
            return
        }
        msgLen := binary.BigEndian.Uint32(lenBuf)

        // Read message data
        msgBuf := make([]byte, msgLen)
        if _, err := io.ReadFull(conn, msgBuf); err != nil {
            return
        }

        // Deserialize and handle message
        msg, err := protocol.DeserializeMessage(msgBuf)
        if err != nil {
            continue
        }

        p.mu.RLock()
        handler := p.handler
        p.mu.RUnlock()

        if handler != nil {
            handler(msg)
        }
    }
}