package protocol

import (
    "crypto/ed25519"
    "crypto/rand"
    "time"
    "encoding/binary"
    "bytes"
    "io"
    "fmt"
)

type MessageType uint8

const (
    TextMessage MessageType = iota
    FileTransfer
    PeerDiscovery
    Handshake
)

type PeerInfo struct {
    PublicKey ed25519.PublicKey
    Address   string
}

type Message struct {
    ID        []byte            
    Type      MessageType       
    Sender    ed25519.PublicKey 
    Recipient ed25519.PublicKey 
    Content   []byte            
    PeerList  []PeerInfo       
    Timestamp time.Time         
    Signature []byte
    ListeningPort int             
}

func NewMessage(msgType MessageType, sender, recipient ed25519.PublicKey, content []byte) *Message {
    id := make([]byte, 16)
    rand.Read(id)

    return &Message{
        ID:        id,
        Type:      msgType,
        Sender:    sender,
        Recipient: recipient,
        Content:   content,
        Timestamp: time.Now().UTC(),
        PeerList:  make([]PeerInfo, 0),
    }
}

func (m *Message) Sign(privateKey ed25519.PrivateKey) error {
    digest := m.createDigest()
    m.Signature = ed25519.Sign(privateKey, digest)
    return nil
}

func (m *Message) Verify() bool {
    // Handle PeerDiscovery messages separately
    if m.Type == PeerDiscovery {
        digest := m.createDigest()
        return ed25519.Verify(m.Sender, digest, m.Signature)
    }
    
    if len(m.Signature) != ed25519.SignatureSize {
        return false
    }
    
    digest := m.createDigest()
    return ed25519.Verify(m.Sender, digest, m.Signature)
}

func (m *Message) createDigest() []byte {
    buf := new(bytes.Buffer)
    
    buf.Write(m.ID)
    binary.Write(buf, binary.BigEndian, uint8(m.Type))
    buf.Write(m.Sender)
    
    // For PeerDiscovery type
    if m.Type != PeerDiscovery {
        buf.Write(m.Recipient)
    }
    
    binary.Write(buf, binary.BigEndian, uint32(len(m.Content)))
    buf.Write(m.Content)
    binary.Write(buf, binary.BigEndian, uint16(m.ListeningPort))
    
    return buf.Bytes()
}


func (m *Message) Serialize() ([]byte, error) {
    buf := new(bytes.Buffer)
 
    buf.Write(m.ID)
    
    if err := binary.Write(buf, binary.BigEndian, m.Type); err != nil {
        return nil, fmt.Errorf("failed to write message type: %w", err)
    }
 
    if len(m.Sender) == 0 {
        m.Sender = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(m.Sender)
 
    if len(m.Recipient) == 0 {
        m.Recipient = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(m.Recipient)
 
    contentLen := uint32(len(m.Content))
    if err := binary.Write(buf, binary.BigEndian, contentLen); err != nil {
        return nil, fmt.Errorf("failed to write content length: %w", err)
    }
    
    if contentLen > 0 {
        buf.Write(m.Content)
    }
 
    // Write PeerList
    if err := binary.Write(buf, binary.BigEndian, uint16(len(m.PeerList))); err != nil {
        return nil, fmt.Errorf("failed to write peer list length: %w", err)
    }
 
    for _, peer := range m.PeerList {
        buf.Write(peer.PublicKey)
        addrBytes := []byte(peer.Address)
        if err := binary.Write(buf, binary.BigEndian, uint16(len(addrBytes))); err != nil {
            return nil, fmt.Errorf("failed to write address length: %w", err)
        }
        buf.Write(addrBytes)
    }
 
    if err := binary.Write(buf, binary.BigEndian, m.Timestamp.Unix()); err != nil {
        return nil, fmt.Errorf("failed to write timestamp: %w", err)
    }
 
    // Write ListeningPort
    if err := binary.Write(buf, binary.BigEndian, uint16(m.ListeningPort)); err != nil {
        return nil, fmt.Errorf("failed to write listening port: %w", err)
    }
 
    if m.Signature != nil && len(m.Signature) > 0 {
        buf.Write(m.Signature)
    }
 
    return buf.Bytes(), nil
 }
 
 func DeserializeMessage(data []byte) (*Message, error) {
    buf := bytes.NewReader(data)
    msg := &Message{
        PeerList: make([]PeerInfo, 0),
    }
 
    msg.ID = make([]byte, 16)
    if _, err := io.ReadFull(buf, msg.ID); err != nil {
        return nil, fmt.Errorf("failed to read ID: %w", err)
    }
 
    if err := binary.Read(buf, binary.BigEndian, &msg.Type); err != nil {
        return nil, fmt.Errorf("failed to read message type: %w", err)
    }
 
    msg.Sender = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Sender); err != nil {
        return nil, fmt.Errorf("failed to read sender: %w", err)
    }
 
    msg.Recipient = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Recipient); err != nil {
        return nil, fmt.Errorf("failed to read recipient: %w", err)
    }
 
    var contentLen uint32
    if err := binary.Read(buf, binary.BigEndian, &contentLen); err != nil {
        return nil, fmt.Errorf("failed to read content length: %w", err)
    }
 
    msg.Content = make([]byte, contentLen)
    if _, err := io.ReadFull(buf, msg.Content); err != nil {
        return nil, fmt.Errorf("failed to read content: %w", err)
    }
 
    // Read PeerList
    var peerListLen uint16
    if err := binary.Read(buf, binary.BigEndian, &peerListLen); err != nil {
        return nil, fmt.Errorf("failed to read peer list length: %w", err)
    }
 
    for i := uint16(0); i < peerListLen; i++ {
        pubKey := make([]byte, ed25519.PublicKeySize)
        if _, err := io.ReadFull(buf, pubKey); err != nil {
            return nil, fmt.Errorf("failed to read peer public key: %w", err)
        }
 
        var addrLen uint16
        if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
            return nil, fmt.Errorf("failed to read address length: %w", err)
        }
 
        addrBytes := make([]byte, addrLen)
        if _, err := io.ReadFull(buf, addrBytes); err != nil {
            return nil, fmt.Errorf("failed to read address: %w", err)
        }
 
        msg.PeerList = append(msg.PeerList, PeerInfo{
            PublicKey: pubKey,
            Address:   string(addrBytes),
        })
    }
 
    var timestamp int64
    if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
        return nil, fmt.Errorf("failed to read timestamp: %w", err)
    }
    msg.Timestamp = time.Unix(timestamp, 0)
 
    // Read ListeningPort
    var port uint16
    if err := binary.Read(buf, binary.BigEndian, &port); err != nil {
        return nil, fmt.Errorf("failed to read listening port: %w", err)
    }
    msg.ListeningPort = int(port)
 
    if buf.Len() == ed25519.SignatureSize {
        msg.Signature = make([]byte, ed25519.SignatureSize)
        if _, err := io.ReadFull(buf, msg.Signature); err != nil {
            return nil, fmt.Errorf("failed to read signature: %w", err)
        }
    }
 
    return msg, nil
 }