# Aegis

Aegis is a secure P2P messaging system written in Go, implementing a Distributed Hash Table (DHT) for peer discovery and message routing.

## Components

### Core Packages
- `pkg/crypto` - Cryptographic utilities for key generation and signing
- `pkg/dht` - Distributed Hash Table implementation with k-bucket management
- `pkg/network` - Network transport layer and peer connections
- `pkg/protocol` - Message protocol definitions and handlers
- `pkg/types` - Shared type definitions

### Internal Packages
- `internal/store` - Storage implementations for DHT values

### Command Line Interface
- `cmd/server` - Main DHT node server implementation

## Current Features
- Ed25519 key pair generation and management
- DHT k-bucket implementation for peer management
- Basic network transport layer
- Local storage implementation
- Message type definitions and handling
- Testing coverage for core components

## Build
```bash
go build -o aegis-node cmd/server/main.go