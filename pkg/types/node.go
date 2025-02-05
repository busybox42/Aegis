// pkg/types/node.go
package types

import (
	"crypto/ed25519"
	"crypto/sha1"
	"net"
	"time"
)

type Node struct {
	ID        []byte
	PublicKey ed25519.PublicKey
	Address   *net.TCPAddr
	LastSeen  time.Time
}

func NewNode(publicKey ed25519.PublicKey, addr *net.TCPAddr) *Node {
	// Generate node ID using SHA-1 hash of public key
	var hash [20]byte
	if publicKey != nil {
		hash = sha1.Sum(publicKey)
	}
	return &Node{
		ID:        hash[:],
		PublicKey: publicKey,
		Address:   addr,
		LastSeen:  time.Now(),
	}
}