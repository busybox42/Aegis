// pkg/dht/dht.go
package dht

import (
    "context"
    "errors"
    "github.com/busybox42/Aegis/pkg/types"
    "sync"
)

// NetworkFinder defines the interface for node lookup
type NetworkFinder interface {
    FindNode(ctx context.Context, target *types.Node, targetID []byte) ([]*types.Node, error)
}

type DHT struct {
    routingTable *RoutingTable
    network      NetworkFinder
    mu           sync.RWMutex
}

func NewDHT(self *types.Node, network NetworkFinder) *DHT {
    return &DHT{
        routingTable: NewRoutingTable(self),
        network:      network,
    }
}

func (dht *DHT) Bootstrap(bootstrapNodes []*types.Node) error {
    for _, node := range bootstrapNodes {
        if err := dht.routingTable.AddNode(node); err != nil {
            continue
        }
    }

    // Perform node lookups for random targets to populate routing table
    for i := 0; i < 3; i++ {
        randomID := make([]byte, 20)
        dht.FindNode(context.Background(), randomID)
    }

    return nil
}

func (dht *DHT) FindNode(ctx context.Context, targetID []byte) ([]*types.Node, error) {
    visited := make(map[string]bool)
    results := make([]*types.Node, 0, K)

    // Get initial closest nodes
    closest := dht.routingTable.GetClosestNodes(targetID, ALPHA)
    if len(closest) == 0 {
        return nil, errors.New("no nodes available")
    }

    // Create channels for concurrent lookups
    resultChan := make(chan []*types.Node, ALPHA)
    doneChan := make(chan struct{})

    // Start concurrent lookups
    for _, node := range closest {
        go func(n *types.Node) {
            nodes, err := dht.network.FindNode(ctx, n, targetID)
            if err != nil {
                resultChan <- nil
                return
            }
            resultChan <- nodes
        }(node)
    }

    // Collect results
    go func() {
        for {
            select {
            case nodes := <-resultChan:
                if nodes == nil {
                    continue
                }

                for _, node := range nodes {
                    nodeKey := string(node.ID)
                    if !visited[nodeKey] {
                        visited[nodeKey] = true
                        results = append(results, node)
                        dht.routingTable.AddNode(node)
                    }
                }

                if len(results) >= K {
                    close(doneChan)
                    return
                }

            case <-ctx.Done():
                close(doneChan)
                return
            }
        }
    }()

    <-doneChan
    return results, nil
}