package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/busybox42/Aegis/internal/store"
	"github.com/busybox42/Aegis/pkg/dht"
	"github.com/busybox42/Aegis/pkg/network"
	"github.com/busybox42/Aegis/pkg/protocol"
	"github.com/busybox42/Aegis/pkg/types"
)

type AegisCLI struct {
	storage     *store.Local
	transport   *network.Transport
	dht         *dht.DHT
	localNode   *types.Node
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
}

func newAegisCLI() *AegisCLI {
	storage := store.NewLocal()
	return &AegisCLI{
		storage: storage,
	}
}

func (cli *AegisCLI) initializeKeys(port int) error {
    keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
    os.MkdirAll(keyDir, 0700)
    
    pubKeyPath := filepath.Join(keyDir, fmt.Sprintf("public_%d.key", port))
    privKeyPath := filepath.Join(keyDir, fmt.Sprintf("private_%d.key", port))

    if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
        pub, priv, err := ed25519.GenerateKey(nil)
        if err != nil {
            return fmt.Errorf("failed to generate keys: %w", err)
        }

        if err := os.WriteFile(pubKeyPath, pub, 0600); err != nil {
            return err
        }
        if err := os.WriteFile(privKeyPath, priv, 0600); err != nil {
            return err
        }

        cli.publicKey = pub
        cli.privateKey = priv
    } else {
        pubBytes, err := os.ReadFile(pubKeyPath)
        if err != nil {
            return err
        }
        privBytes, err := os.ReadFile(privKeyPath)
        if err != nil {
            return err
        }

        cli.publicKey = pubBytes
        cli.privateKey = privBytes
    }

    return nil
}

func (cli *AegisCLI) initializeNetwork(port int) error {
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
    cli.localNode = types.NewNode(cli.publicKey, addr)

    // Always bootstrap from default port 8080
    bootstrapAddr := &net.TCPAddr{
        IP:   net.ParseIP("127.0.0.1"), 
        Port: 8080,
    }

    networkConfig := &network.Config{
        Port:       port,
        PublicKey:  cli.publicKey,
        PrivateKey: cli.privateKey,
        Bootstrap:  []*net.TCPAddr{bootstrapAddr},
    }
    
    cli.transport = network.NewTransport(networkConfig)
    
    // Register peer discovery handler
    cli.transport.RegisterHandler(protocol.TextMessage, func(msg *protocol.Message) error {
		log.Printf("[DEBUG] Received text message from %x", msg.Sender)
		log.Printf("[DEBUG] Message content: %s", string(msg.Content))
		return nil
	})

    cli.dht = dht.NewDHT(cli.localNode, cli.transport)

    return cli.transport.Start()
}

func (cli *AegisCLI) bootstrapNode(address string) error {
    log.Printf("[DEBUG] Attempting to bootstrap with node: %s", address)
    
    addr, err := net.ResolveTCPAddr("tcp", address)
    if err != nil {
        log.Printf("[ERROR] Failed to resolve address: %v", err)
        return fmt.Errorf("invalid address: %v", err)
    }
    
    // Stop existing transport
    if err := cli.transport.Stop(); err != nil {
        log.Printf("[ERROR] Failed to stop transport: %v", err)
        return fmt.Errorf("failed to stop transport: %v", err)
    }
    
    networkConfig := &network.Config{
        Port:       cli.localNode.Address.Port,
        PublicKey:  cli.publicKey,
        PrivateKey: cli.privateKey,
        Bootstrap:  []*net.TCPAddr{addr},
    }
    
    cli.transport = network.NewTransport(networkConfig)
    cli.dht = dht.NewDHT(cli.localNode, cli.transport)
    
    if err := cli.transport.Start(); err != nil {
        log.Printf("[ERROR] Failed to start transport: %v", err)
        return err
    }
    
    log.Printf("[DEBUG] Successfully bootstrapped with node: %s", address)
    return nil
}

func (cli *AegisCLI) sendMessage(recipientKey []byte, message string) error {
	msg := protocol.NewMessage(
		protocol.TextMessage, 
		cli.publicKey, 
		recipientKey, 
		[]byte(message),
	)
	
	if err := msg.Sign(cli.privateKey); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return cli.transport.SendMessage(ctx, msg)
}

func (cli *AegisCLI) findNodes(targetKey string) ([]*types.Node, error) {
    targetBytes, err := hex.DecodeString(targetKey)
    if err != nil {
        return nil, fmt.Errorf("invalid target key: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    return cli.transport.FindNode(ctx, nil, targetBytes)
}

func (cli *AegisCLI) startInteractiveCLI(port int) error {
	// Initialize network
	if err := cli.initializeNetwork(port); err != nil {
		return fmt.Errorf("failed to initialize network: %v", err)
	}

	// Print local node info
	fmt.Printf("Local Node Public Key: %x\n", cli.publicKey)

	// Start interactive prompt
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("aegis> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		
		// Trim whitespace
		input = strings.TrimSpace(input)
		
		// Split input into command and arguments
		parts := strings.SplitN(input, " ", 2)
		command := parts[0]
		var args string
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
		}

		switch command {
		case "bootstrap":
			if args == "" {
				fmt.Println("Usage: bootstrap <ip>:<port>")
				continue
			}
			
			if err := cli.bootstrapNode(args); err != nil {
				fmt.Printf("Failed to bootstrap node: %v\n", err)
			} else {
				fmt.Printf("Bootstrapped with node: %s\n", args)
			}

		case "send":
			if args == "" {
				fmt.Println("Usage: send <recipient_key> <message>")
				continue
			}
			sendParts := strings.SplitN(args, " ", 2)
			if len(sendParts) < 2 {
				fmt.Println("Usage: send <recipient_key> <message>")
				continue
			}
			recipientKey := sendParts[0]
			message := sendParts[1]
			
			recipientBytes, err := hex.DecodeString(recipientKey)
			if err != nil {
				fmt.Printf("Invalid recipient key: %v\n", err)
				continue
			}

			if err := cli.sendMessage(recipientBytes, message); err != nil {
				fmt.Printf("Failed to send message: %v\n", err)
			} else {
				fmt.Println("Message sent successfully")
			}

		case "find":
			if args == "" {
				fmt.Println("Usage: find <target_key>")
				continue
			}
			
			nodes, err := cli.findNodes(args)
			if err != nil {
				fmt.Printf("Failed to find nodes: %v\n", err)
				continue
			}

			fmt.Printf("Found %d nodes:\n", len(nodes))
			for _, node := range nodes {
				fmt.Printf("Node: %x @ %v\n", node.PublicKey, node.Address)
			}

		case "mykey":
			fmt.Printf("Local Public Key: %x\n", cli.publicKey)

		case "exit":
			return nil

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  bootstrap <ip:port>        - Add a bootstrap node to discover peers")
			fmt.Println("  send <recipient_key> <message>  - Send a message to a recipient")
			fmt.Println("  find <target_key>               - Find nodes with a specific key")
			fmt.Println("  mykey                          - Show local node's public key")
			fmt.Println("  help                           - Show this help message")
			fmt.Println("  exit                           - Exit the application")

		default:
			fmt.Printf("Unknown command: %s. Type 'help' for usage.\n", command)
		}
	}
}

func main() {
    cli := newAegisCLI()

    // Command-line flags
    port := flag.Int("port", 8080, "Port to listen on")
    bootstrapPort := flag.Int("bootstrap", 8080, "Bootstrap node port")
    flag.Parse()

    // Initialize keys with port
    if err := cli.initializeKeys(*port); err != nil {
        log.Fatalf("Failed to initialize keys: %v", err)
    }

    // Add bootstrap configuration
    bootstrapAddr := &net.TCPAddr{
        IP:   net.ParseIP("127.0.0.1"), 
        Port: *bootstrapPort,
    }

    networkConfig := &network.Config{
        Port:       *port,
        PublicKey:  cli.publicKey,
        PrivateKey: cli.privateKey,
        Bootstrap:  []*net.TCPAddr{bootstrapAddr},
    }
    cli.transport = network.NewTransport(networkConfig)
    cli.dht = dht.NewDHT(cli.localNode, cli.transport)

    // Start interactive CLI
    if err := cli.startInteractiveCLI(*port); err != nil {
        log.Fatalf("CLI error: %v", err)
    }
}