package dht

import (
        "context"
        "errors"
        "log"
        "sync"
        "time"
        "fmt"

        "github.com/busybox42/Aegis/pkg/types"
)

// Network-wide constants
const (
        ALPHA = 3  // Number of parallel lookups
        K     = 20 // Maximum size of node lists
)

type NetworkFinder interface {
        FindNode(ctx context.Context, target *types.Node, targetID []byte) ([]*types.Node, error)
}

type DHT struct {
        routingTable *RoutingTable
        network      NetworkFinder
        mu           sync.RWMutex
        self         *types.Node
}

type Option func(*DHT)

func NewDHT(self *types.Node, network NetworkFinder, opts ...Option) *DHT {
        dht := &DHT{
                routingTable: NewRoutingTable(self),
                network:      network,
                self:         self,
        }

        for _, opt := range opts {
                opt(dht)
        }

        return dht
}

func (dht *DHT) Bootstrap(bootstrapNodes []*types.Node) error {
        log.Printf("Starting DHT bootstrap with %d nodes", len(bootstrapNodes))
        
        for _, node := range bootstrapNodes {
                if err := dht.routingTable.AddNode(node); err != nil {
                        log.Printf("Failed to add bootstrap node %v: %v", node.Address, err)
                        continue
                }
                log.Printf("Added bootstrap node: %v", node.Address)
        }

        log.Printf("Starting initial node discovery with own ID: %x", dht.self.PublicKey)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        nodes, err := dht.FindNode(ctx, dht.self.PublicKey)
        if err != nil {
                log.Printf("Initial node discovery failed: %v", err)
        } else {
                log.Printf("Found %d nodes during bootstrap", len(nodes))
                for _, node := range nodes {
                        if err := dht.routingTable.AddNode(node); err != nil {
                                log.Printf("Failed to add discovered node: %v", err)
                        }
                }
        }
        
        return nil
}

func (dht *DHT) FindNode(ctx context.Context, targetID []byte) ([]*types.Node, error) {
    closest := dht.routingTable.GetClosestNodes(targetID, ALPHA)
    if len(closest) == 0 {
        return nil, errors.New("no nodes available")
    }

    visited := make(map[string]bool)
    results := make([]*types.Node, 0)
    
    for _, node := range closest {
        if ctx.Err() != nil {
            break
        }

        nodes, err := dht.network.FindNode(ctx, node, targetID)
        if err != nil {
            continue
        }

        for _, n := range nodes {
            nodeKey := string(n.PublicKey)
            if !visited[nodeKey] {
                visited[nodeKey] = true
                results = append(results, n)
                dht.routingTable.AddNode(n)
            }
        }
    }

    if len(results) > 0 {
        return results, nil
    }
    return nil, fmt.Errorf("node not found: %x", targetID)
}

func (dht *DHT) AddNode(node *types.Node) error {
        return dht.routingTable.AddNode(node)
}