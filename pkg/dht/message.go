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
