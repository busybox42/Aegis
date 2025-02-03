// pkg/dht/handler_test.go
package dht

import (
    "context"
    "errors"
    "testing"
    "github.com/busybox42/Aegis/pkg/types"
    "crypto/ed25519"
    "net"
)
	
// Mock storage implementation for testing
type mockStorage struct {
    data map[string][]byte
}

func newMockStorage() *mockStorage {
    return &mockStorage{
        data: make(map[string][]byte),
    }
}

func (m *mockStorage) Store(key []byte, value []byte) error {
    m.data[string(key)] = value
    return nil
}

func (m *mockStorage) Retrieve(key []byte) ([]byte, error) {
    if value, ok := m.data[string(key)]; ok {
        return value, nil
    }
    return nil, errors.New("value not found")
}

func TestMessageHandler(t *testing.T) {
    // Create test node
    pub, _, _ := ed25519.GenerateKey(nil)
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
    self := types.NewNode(pub, addr)

    // Create DHT and handler
    dht := NewDHT(self, nil)
    storage := newMockStorage()
    handler := NewMessageHandler(dht, storage)

    // Test cases
    tests := []struct {
        name    string
        msg     *Message
        wantErr bool
    }{
        {
            name: "Find node request",
            msg: &Message{
                Type:     FindNode,
                Sender:   self,
                TargetID: make([]byte, 20),
            },
            wantErr: false,
        },
        {
            name: "Store request",
            msg: &Message{
                Type:     Store,
                Sender:   self,
                TargetID: make([]byte, 20),
                Value:    []byte("test value"),
            },
            wantErr: false,
        },
        {
            name: "Find value request",
            msg: &Message{
                Type:     FindValue,
                Sender:   self,
                TargetID: make([]byte, 20),
            },
            wantErr: false,
        },
        {
            name: "Ping request",
            msg: &Message{
                Type:   Ping,
                Sender: self,
            },
            wantErr: false,
        },
    }

    ctx := context.Background()
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            response, err := handler.HandleMessage(ctx, tt.msg)
            if (err != nil) != tt.wantErr {
                t.Errorf("HandleMessage() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && response == nil {
                t.Error("Expected response message, got nil")
            }
        })
    }
}