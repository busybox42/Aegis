package network

import (
	"crypto/ed25519"
	"net"

	"github.com/busybox42/Aegis/pkg/protocol"
)

type MessageHandlerFunc func(*protocol.Message) error

type MessageRouter interface {
	Route(msg *protocol.Message) error
	RegisterHandler(msgType protocol.MessageType, handler MessageHandlerFunc)
}

type Config struct {
	Port       int
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Bootstrap  []*net.TCPAddr
}