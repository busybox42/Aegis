// pkg/dht/handler.go
package dht

import (
    "context"
    "errors"
    "github.com/busybox42/Aegis/pkg/types"
    "sync"
)

// Storage interface for the DHT
type Storage interface {
    Store(key []byte, value []byte) error
    Retrieve(key []byte) ([]byte, error)
}

// MessageHandler handles DHT protocol messages
type MessageHandler struct {
    dht     *DHT
    storage Storage
    mu      sync.RWMutex
    node    *types.Node  // Add this to make use of the types package
}

func NewMessageHandler(dht *DHT, storage Storage) *MessageHandler {
    return &MessageHandler{
        dht:     dht,
        storage: storage,
        node:    dht.routingTable.self,
    }
}

func (h *MessageHandler) HandleMessage(ctx context.Context, msg *Message) (*Message, error) {
    switch msg.Type {
    case FindNode:
        return h.handleFindNode(msg)
    case Store:
        return h.handleStore(msg)
    case FindValue:
        return h.handleFindValue(msg)
    case Ping:
        return h.handlePing(msg)
    default:
        return nil, errors.New("unknown message type")
    }
}

func (h *MessageHandler) handleFindNode(msg *Message) (*Message, error) {
    if len(msg.TargetID) == 0 {
        return nil, errors.New("target ID is required for FindNode")
    }

    // Find K closest nodes to target
    closest := h.dht.routingTable.GetClosestNodes(msg.TargetID, K)

    // Create response message
    response := &Message{
        Type:      FindNode,
        Sender:    h.dht.routingTable.self,
        Neighbors: closest,
    }

    return response, nil
}

func (h *MessageHandler) handleStore(msg *Message) (*Message, error) {
    if len(msg.Value) == 0 {
        return nil, errors.New("value is required for Store")
    }

    // Store the value
    err := h.storage.Store(msg.TargetID, msg.Value)
    if err != nil {
        return nil, err
    }

    // Create response message
    response := &Message{
        Type:   Store,
        Sender: h.dht.routingTable.self,
    }

    return response, nil
}

func (h *MessageHandler) handleFindValue(msg *Message) (*Message, error) {
    if len(msg.TargetID) == 0 {
        return nil, errors.New("key is required for FindValue")
    }

    // Try to retrieve the value
    value, err := h.storage.Retrieve(msg.TargetID)
    
    response := &Message{
        Type:   FindValue,
        Sender: h.dht.routingTable.self,
    }

    if err == nil {
        // Value found, return it
        response.Value = value
    } else {
        // Value not found, return closest nodes instead
        response.Neighbors = h.dht.routingTable.GetClosestNodes(msg.TargetID, K)
    }

    return response, nil
}

func (h *MessageHandler) handlePing(msg *Message) (*Message, error) {
    // Update the sender's last seen time in routing table
    if msg.Sender != nil {
        h.dht.routingTable.AddNode(msg.Sender)
    }

    // Create response message
    response := &Message{
        Type:   Ping,
        Sender: h.dht.routingTable.self,
    }

    return response, nil
}