// pkg/protocol/message.go
package protocol

import (
    "crypto/ed25519"
    "crypto/rand"
    "time"
    "encoding/binary"
    "bytes"
    "io"
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
    digest := m.createDigest()
    return ed25519.Verify(m.Sender, digest, m.Signature)
}

// createDigest creates a digest of the message for signing
func (m *Message) createDigest() []byte {
    buf := new(bytes.Buffer)
    
    // Write all fields that should be part of the signature
    buf.Write(m.ID)
    binary.Write(buf, binary.BigEndian, m.Type)
    buf.Write(m.Sender)
    buf.Write(m.Recipient)
    buf.Write(m.Content)
    binary.Write(buf, binary.BigEndian, m.Timestamp.Unix())
    
    return buf.Bytes()
}

// Serialize converts the message to bytes for transmission
func (m *Message) Serialize() ([]byte, error) {
    buf := new(bytes.Buffer)

    // Write all fields
    buf.Write(m.ID)
    binary.Write(buf, binary.BigEndian, m.Type)
    buf.Write(m.Sender)
    buf.Write(m.Recipient)
    binary.Write(buf, binary.BigEndian, uint32(len(m.Content)))
    buf.Write(m.Content)
    binary.Write(buf, binary.BigEndian, m.Timestamp.Unix())
    if m.Signature != nil {
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
        return nil, err
    }

    // Read Type
    if err := binary.Read(buf, binary.BigEndian, &msg.Type); err != nil {
        return nil, err
    }

    // Read Sender
    msg.Sender = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Sender); err != nil {
        return nil, err
    }

    // Read Recipient
    msg.Recipient = make([]byte, ed25519.PublicKeySize)
    if _, err := io.ReadFull(buf, msg.Recipient); err != nil {
        return nil, err
    }

    // Read Content length and Content
    var contentLen uint32
    if err := binary.Read(buf, binary.BigEndian, &contentLen); err != nil {
        return nil, err
    }

    msg.Content = make([]byte, contentLen)
    if _, err := io.ReadFull(buf, msg.Content); err != nil {
        return nil, err
    }

    // Read Timestamp
    var timestamp int64
    if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
        return nil, err
    }
    msg.Timestamp = time.Unix(timestamp, 0)

    // Read Signature if present
    msg.Signature = make([]byte, ed25519.SignatureSize)
    if _, err := io.ReadFull(buf, msg.Signature); err != nil {
        if err != io.EOF {
            return nil, err
        }
    }

    return msg, nil
}