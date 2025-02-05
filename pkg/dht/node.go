package dht

import (
    "bytes"
    "encoding/binary"
    "errors"
    "github.com/busybox42/Aegis/pkg/types"
    "math/bits"
    "sync"
)

const (
    BUCKET_SIZE = 160 // Number of buckets (SHA-1 size in bits)
)

type Bucket struct {
    nodes []*types.Node
    mu    sync.RWMutex
}

func (b *Bucket) addNode(node *types.Node) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    for i, n := range b.nodes {
        if bytes.Equal(n.ID, node.ID) {
            b.nodes[i] = node
            return nil
        }
    }

    if len(b.nodes) < K {
        b.nodes = append(b.nodes, node)
        return nil
    }

    return errors.New("bucket full")
}

func (b *Bucket) removeNode(nodeID []byte) {
    b.mu.Lock()
    defer b.mu.Unlock()

    for i, node := range b.nodes {
        if bytes.Equal(node.ID, nodeID) {
            b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
            return
        }
    }
}

func (b *Bucket) getNodes() []*types.Node {
    b.mu.RLock()
    defer b.mu.RUnlock()
    
    nodes := make([]*types.Node, len(b.nodes))
    copy(nodes, b.nodes)
    return nodes
}

type RoutingTable struct {
    buckets [BUCKET_SIZE]*Bucket
    self    *types.Node
    mu      sync.RWMutex
}

func NewRoutingTable(self *types.Node) *RoutingTable {
    rt := &RoutingTable{
        self: self,
    }
    
    for i := range rt.buckets {
        rt.buckets[i] = &Bucket{}
    }
    
    return rt
}

func (rt *RoutingTable) AddNode(node *types.Node) error {
    if bytes.Equal(node.ID, rt.self.ID) {
        return errors.New("cannot add self to routing table")
    }

    bucketIndex := rt.getBucketIndex(node.ID)
    return rt.buckets[bucketIndex].addNode(node)
}

func (rt *RoutingTable) RemoveNode(nodeID []byte) {
    bucketIndex := rt.getBucketIndex(nodeID)
    rt.buckets[bucketIndex].removeNode(nodeID)
}

func (rt *RoutingTable) GetClosestNodes(target []byte, count int) []*types.Node {
    targetInt := binary.BigEndian.Uint64(target[:8])
    distances := make(map[*types.Node]uint64)
    
    rt.mu.RLock()
    defer rt.mu.RUnlock()

    for _, bucket := range rt.buckets {
        for _, node := range bucket.getNodes() {
            nodeInt := binary.BigEndian.Uint64(node.ID[:8])
            distance := targetInt ^ nodeInt
            distances[node] = distance
        }
    }

    closest := make([]*types.Node, 0, count)
    for len(closest) < count && len(distances) > 0 {
        var minNode *types.Node
        var minDist uint64 = ^uint64(0)

        for node, dist := range distances {
            if dist < minDist {
                minDist = dist
                minNode = node
            }
        }

        if minNode != nil {
            closest = append(closest, minNode)
            delete(distances, minNode)
        }
    }

    return closest
}

func (rt *RoutingTable) getBucketIndex(nodeID []byte) int {
    distance := xorDistance(rt.self.ID, nodeID)
    
    for i := 0; i < len(distance); i++ {
        if distance[i] == 0 {
            continue
        }
        return i*8 + bits.LeadingZeros8(distance[i]) % BUCKET_SIZE
    }
    
    return BUCKET_SIZE - 1
}

func xorDistance(a, b []byte) []byte {
    dist := make([]byte, len(a))
    for i := range a {
        dist[i] = a[i] ^ b[i]
    }
    return dist
}