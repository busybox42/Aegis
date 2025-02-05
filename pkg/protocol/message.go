// pkg/protocol/message.go
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

// Message represents a basic message in the P2P system
type Message struct {
    ID        []byte            // Unique message identifier
    Type      MessageType       // Type of the message
    Sender    ed25519.PublicKey // Sender's public key
    Recipient ed25519.PublicKey // Recipient's public key
    Content   []byte            // Encrypted message content
    Timestamp time.Time         // Message timestamp
    Signature []byte            // Message signature
}

// NewMessage creates a new message with the given parameters
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
    }
}

// Sign signs the message using the sender's private key
func (m *Message) Sign(privateKey ed25519.PrivateKey) error {
    digest := m.createDigest()
    m.Signature = ed25519.Sign(privateKey, digest)
    return nil
}

// Verify verifies the message signature
func (m *Message) Verify() bool {
    // Special handling for PeerDiscovery messages which may have empty recipient
    if m.Type == PeerDiscovery && len(m.Recipient) == 0 {
        // Use temporary empty recipient for verification
        origRecipient := m.Recipient
        m.Recipient = make([]byte, ed25519.PublicKeySize)
        digest := m.createDigest()
        m.Recipient = origRecipient
        return ed25519.Verify(m.Sender, digest, m.Signature)
    }
    
    digest := m.createDigest()
    return ed25519.Verify(m.Sender, digest, m.Signature)
}

// createDigest creates a digest of the message for signing
func (m *Message) createDigest() []byte {
    buf := new(bytes.Buffer)
    
    // Ensure consistent representation of fields
    buf.Write(m.ID)
    
    // Write Type as a fixed-size byte
    binary.Write(buf, binary.BigEndian, uint8(m.Type))
    
    // Ensure consistent key sizes
    senderKey := m.Sender
    if len(senderKey) == 0 {
        senderKey = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(senderKey)
    
    recipientKey := m.Recipient
    if len(recipientKey) == 0 {
        recipientKey = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(recipientKey)
    
    // Write content
    binary.Write(buf, binary.BigEndian, uint32(len(m.Content)))
    buf.Write(m.Content)
    
    // Write timestamp as int64
    binary.Write(buf, binary.BigEndian, m.Timestamp.Unix())
    
    return buf.Bytes()
}

// Serialize converts the message to bytes for transmission
func (m *Message) Serialize() ([]byte, error) {
    buf := new(bytes.Buffer)

    // Write all fields
    buf.Write(m.ID)
    
    // Ensure Type is always written
    if err := binary.Write(buf, binary.BigEndian, m.Type); err != nil {
        return nil, fmt.Errorf("failed to write message type: %w", err)
    }

    // Ensure Sender is written
    if len(m.Sender) == 0 {
        m.Sender = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(m.Sender)

    // Ensure Recipient is written
    if len(m.Recipient) == 0 {
        m.Recipient = make([]byte, ed25519.PublicKeySize)
    }
    buf.Write(m.Recipient)

    // Write content length and content
    contentLen := uint32(len(m.Content))
    if err := binary.Write(buf, binary.BigEndian, contentLen); err != nil {
        return nil, fmt.Errorf("failed to write content length: %w", err)
    }
    
    if contentLen > 0 {
        buf.Write(m.Content)
    }

    // Write timestamp
    if err := binary.Write(buf, binary.BigEndian, m.Timestamp.Unix()); err != nil {
        return nil, fmt.Errorf("failed to write timestamp: %w", err)
    }

    // Write optional signature
    if m.Signature != nil && len(m.Signature) > 0 {
        buf.Write(m.Signature)
    }

    return buf.Bytes(), nil
}

// DeserializeMessage converts bytes back into a Message
func DeserializeMessage(data []byte) (*Message, error) {
    buf := bytes.NewReader(data)
    msg := &Message{}

    // Read ID
    msg.ID = make([]byte, 16)
    if _, err := io.ReadFull(buf, msg.ID); err != nil {
        return nil, fmt.Errorf("failed to read ID: %w", err)
    }

    // Read Type
    if err := binary.Read(buf, binary.BigEndian, &msg.Type); err != nil {
        return nil, fmt.Errorf("failed to read message type: %w", err)
    }

    // Read Sender
    msg.Sender = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Sender); err != nil {
        return nil, fmt.Errorf("failed to read sender: %w", err)
    }

    // Read Recipient
    msg.Recipient = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Recipient); err != nil {
        return nil, fmt.Errorf("failed to read recipient: %w", err)
    }

    // Read Content length and Content
    var contentLen uint32
    if err := binary.Read(buf, binary.BigEndian, &contentLen); err != nil {
        return nil, fmt.Errorf("failed to read content length: %w", err)
    }

    msg.Content = make([]byte, contentLen)
    if _, err := io.ReadFull(buf, msg.Content); err != nil {
        return nil, fmt.Errorf("failed to read content: %w", err)
    }

    // Read Timestamp
    var timestamp int64
    if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
        return nil, fmt.Errorf("failed to read timestamp: %w", err)
    }
    msg.Timestamp = time.Unix(timestamp, 0)

    // Safely read signature if remaining data is sufficient
    if buf.Len() == ed25519.SignatureSize {
        msg.Signature = make([]byte, ed25519.SignatureSize)
        if _, err := io.ReadFull(buf, msg.Signature); err != nil {
            return nil, fmt.Errorf("failed to read signature: %w", err)
        }
    }

    return msg, nil
}