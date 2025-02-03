// pkg/dht/message_test.go
package dht

import (
    "testing"
    "github.com/busybox42/Aegis/pkg/types"
    "crypto/ed25519"
    "net"
)

func TestDHTMessageTypes(t *testing.T) {
    // Create test nodes
    pub, _, _ := ed25519.GenerateKey(nil)
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
    node := types.NewNode(pub, addr)

    testCases := []struct {
        name     string
        msg      Message
        msgType  MessageType
        hasValue bool
    }{
        {
            name: "FindNode message",
            msg: Message{
                Type:     FindNode,
                Sender:   node,
                TargetID: make([]byte, 20),
            },
            msgType:  FindNode,
            hasValue: false,
        },
        {
            name: "Store message",
            msg: Message{
                Type:   Store,
                Sender: node,
                Value:  []byte("test value"),
            },
            msgType:  Store,
            hasValue: true,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            if tc.msg.Type != tc.msgType {
                t.Errorf("Expected message type %v, got %v", tc.msgType, tc.msg.Type)
            }

            if tc.hasValue && len(tc.msg.Value) == 0 {
                t.Error("Expected value to be present")
            }

            if !tc.hasValue && len(tc.msg.Value) > 0 {
                t.Error("Expected no value to be present")
            }

            if tc.msg.Sender != node {
                t.Error("Sender node mismatch")
            }
        })
    }
}