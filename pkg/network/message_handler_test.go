// pkg/network/message_handler_test.go
package network

import (
    "testing"
    "github.com/busybox42/Aegis/pkg/crypto"
    "github.com/busybox42/Aegis/pkg/protocol"
    "net"
    "time"
)

func TestMessageSendReceive(t *testing.T) {
    // Create listener
    listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
    if err != nil {
        t.Fatalf("Failed to create listener: %v", err)
    }
    defer listener.Close()

    // Create peers
    senderKP, _ := crypto.GenerateKeyPair()
    receiverKP, _ := crypto.GenerateKeyPair()

    sender := NewPeer(senderKP.PublicKey, listener.Addr().(*net.TCPAddr))
    receiver := NewPeer(receiverKP.PublicKey, listener.Addr().(*net.TCPAddr))

    // Setup message handling
    msgChan := make(chan *protocol.Message, 1)
    receiver.SetMessageHandler(func(msg *protocol.Message) error {
        msgChan <- msg
        return nil
    })

    // Start receiver
    go func() {
        conn, err := listener.AcceptTCP()
        if err != nil {
            t.Errorf("Failed to accept connection: %v", err)
            return
        }
        receiver.handleConnection(conn)
    }()

    // Connect sender
    if err := sender.Connect(); err != nil {
        t.Fatalf("Failed to connect sender: %v", err)
    }
    defer sender.Disconnect()

    // Create and send test message
    testMsg := protocol.NewMessage(
        protocol.TextMessage,
        senderKP.PublicKey,
        receiverKP.PublicKey,
        []byte("Hello, P2P world!"),
    )
    if err := testMsg.Sign(senderKP.PrivateKey); err != nil {
        t.Fatalf("Failed to sign message: %v", err)
    }

    if err := sender.SendMessage(testMsg); err != nil {
        t.Fatalf("Failed to send message: %v", err)
    }

    // Wait for message reception
    select {
    case receivedMsg := <-msgChan:
        if !receivedMsg.Verify() {
            t.Error("Received message failed verification")
        }
        if string(receivedMsg.Content) != "Hello, P2P world!" {
            t.Errorf("Expected content 'Hello, P2P world!', got '%s'", string(receivedMsg.Content))
        }
    case <-time.After(time.Second):
        t.Fatal("Timeout waiting for message")
    }
}