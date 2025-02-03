// cmd/server/main.go
package main

import (
    "crypto/ed25519"
    "flag"
    "fmt"
    "log"
    "net"
    "context"
    "github.com/busybox42/Aegis/pkg/types"
    "github.com/busybox42/Aegis/pkg/dht"
    "github.com/busybox42/Aegis/pkg/network"
    "github.com/busybox42/Aegis/internal/store"
)

func main() {
    // Command line flags
    port := flag.Int("port", 8080, "Port to listen on")
    flag.Parse()

    // Generate node keys
    pub, _, err := ed25519.GenerateKey(nil) // Remove priv since we're not using it yet
    if err != nil {
        log.Fatalf("Failed to generate keys: %v", err)
    }

    // Create local node
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: *port}
    localNode := types.NewNode(pub, addr)

    // Create DHT
	networkTransport := network.NewTransport(*port)
	node := dht.NewDHT(localNode, networkTransport)
 
	// Create storage
	storage := store.NewLocal()

    // Create message handler and start handling messages
    handler := dht.NewMessageHandler(node, storage)
    go handleMessages(handler)

    fmt.Printf("Node started on port %d\n", *port)
    fmt.Printf("Node ID: %x\n", localNode.ID)

    // Start listening for connections
    if err := networkTransport.Listen(); err != nil {
        log.Fatalf("Failed to start network: %v", err)
    }

    // Keep the main goroutine running
    select {}
}

func handleMessages(handler *dht.MessageHandler) {
    ctx := context.Background()
    // TODO: Implement message handling loop
    for {
        // This is a placeholder for actual message handling
        select {
        case <-ctx.Done():
            return
        }
    }
}