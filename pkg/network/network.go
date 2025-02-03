// pkg/network/network.go
package network

import (
    "context"
    "github.com/busybox42/Aegis/pkg/types"
)

type Network interface {
    FindNode(ctx context.Context, target *types.Node, targetID []byte) ([]*types.Node, error)
}