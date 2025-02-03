// pkg/dht/node_test.go
package dht

import (
    "crypto/ed25519"
    "net"
    "testing"
    "github.com/busybox42/Aegis/pkg/types"
    "crypto/rand"
    "time"
)

func TestNewNode(t *testing.T) {
    pub, _, _ := ed25519.GenerateKey(nil)
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
    
    node := types.NewNode(pub, addr)
    
    if node == nil {
        t.Fatal("NewNode returned nil")
    }
    
    if len(node.ID) != 20 {
        t.Errorf("Expected node ID length 20, got %d", len(node.ID))
    }
    
    if node.Address.String() != addr.String() {
        t.Errorf("Expected address %s, got %s", addr, node.Address)
    }
}

func TestBucketOperations(t *testing.T) {
    bucket := &Bucket{}
    
    // Create test nodes
    nodes := make([]*types.Node, K+1)
    for i := range nodes {
        pub, _, _ := ed25519.GenerateKey(nil)
        addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000 + i}
        nodes[i] = types.NewNode(pub, addr)
    }
    
    // Test adding nodes
    for i := 0; i < K; i++ {
        err := bucket.addNode(nodes[i])
        if err != nil {
            t.Errorf("Failed to add node %d: %v", i, err)
        }
    }
    
    // Test bucket full condition
    err := bucket.addNode(nodes[K])
    if err == nil {
        t.Error("Expected error when adding node to full bucket")
    }
    
    // Test node removal
    bucket.removeNode(nodes[0].ID)
    if len(bucket.nodes) != K-1 {
        t.Errorf("Expected %d nodes after removal, got %d", K-1, len(bucket.nodes))
    }
}

func TestRoutingTableOperations(t *testing.T) {
    // Create self node
    selfPub, _, _ := ed25519.GenerateKey(nil)
    selfAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
    self := types.NewNode(selfPub, selfAddr)
    
    rt := NewRoutingTable(self)
    
    // Test adding nodes with distributed IDs
    for i := 0; i < 50; i++ {
        // Generate random ID to ensure better distribution
        id := make([]byte, 20)
        rand.Read(id)
        
        pub, _, _ := ed25519.GenerateKey(nil)
        addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8001 + i}
        node := &types.Node{
            ID:        id,
            PublicKey: pub,
            Address:   addr,
            LastSeen:  time.Now().UTC(),  // Changed from types.Now() to time.Now().UTC()
        }
        
        err := rt.AddNode(node)
        if err != nil {
            t.Logf("Info: Failed to add node %d: %v", i, err)
        }
    }
    
    // Test closest nodes lookup
    target := make([]byte, 20)
    rand.Read(target)
    closest := rt.GetClosestNodes(target, K)
    
    if len(closest) > K {
        t.Errorf("Expected at most %d closest nodes, got %d", K, len(closest))
    }
    
    // Test bucket distribution
    bucketCounts := make(map[int]int)
    for i := range rt.buckets {
        count := len(rt.buckets[i].nodes)
        if count > 0 {
            bucketCounts[i] = count
        }
    }
    
    if len(bucketCounts) < 2 {
        t.Error("Expected nodes to be distributed across multiple buckets")
    }
}