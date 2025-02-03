// pkg/dht/message.go
package dht

import (
    "github.com/busybox42/Aegis/pkg/types"
)

type MessageType uint8

const (
    FindNode MessageType = iota
    Store
    FindValue
    Ping
)

type Message struct {
    Type      MessageType
    Sender    *types.Node
    TargetID  []byte
    Value     []byte
    Neighbors []*types.Node
}

type DHTProtocol interface {
    // FindNode looks for nodes close to targetID
    FindNode(targetID []byte) ([]*types.Node, error)
    
    // Store stores a value in the DHT
    Store(key []byte, value []byte) error
    
    // FindValue retrieves a stored value
    FindValue(key []byte) ([]byte, error)
    
    // Ping checks if a node is alive
    Ping(node *types.Node) error
}