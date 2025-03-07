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
	"sync"
	"time"

	"github.com/busybox42/Aegis/internal/store"
	"github.com/busybox42/Aegis/pkg/dht"
	"github.com/busybox42/Aegis/pkg/network"
	"github.com/busybox42/Aegis/pkg/protocol"
	"github.com/busybox42/Aegis/pkg/tor"
	"github.com/busybox42/Aegis/pkg/types"
)

type MessageRecord struct {
	Timestamp time.Time
	Sender    string
	Recipient string
	Content   string
	Status    string
}

type AegisCLI struct {
	storage        *store.Local
	transport      *network.Transport
	dht            *dht.DHT
	localNode      *types.Node
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	messageHistory []MessageRecord
	historyMu      sync.RWMutex
	torManager     *tor.TorManager
	useTor         bool
}

func newAegisCLI() *AegisCLI {
	storage := store.NewLocal()
	return &AegisCLI{
		storage:        storage,
		messageHistory: make([]MessageRecord, 0),
	}
}

func (cli *AegisCLI) addToHistory(record MessageRecord) {
	cli.historyMu.Lock()
	defer cli.historyMu.Unlock()
	cli.messageHistory = append(cli.messageHistory, record)
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

func (cli *AegisCLI) initializeTor() error {
	torManager, err := tor.StartTor()
	if err != nil {
		return fmt.Errorf("failed to start Tor: %w", err)
	}
	cli.torManager = torManager
	return nil
}

func (cli *AegisCLI) initializeNetwork(port int, bootstrapIP string, bootstrapPort int) error {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	cli.localNode = types.NewNode(cli.publicKey, addr)

	bootstrapAddr := &net.TCPAddr{
		IP:   net.ParseIP(bootstrapIP),
		Port: bootstrapPort,
	}

	networkConfig := &network.Config{
		Port:       port,
		PublicKey:  cli.publicKey,
		PrivateKey: cli.privateKey,
		Bootstrap:  []*net.TCPAddr{bootstrapAddr},
		UseTor:     cli.useTor,
		TorManager: cli.torManager,
	}

	cli.transport = network.NewTransport(networkConfig)

	// Register message handler
	cli.transport.RegisterHandler(protocol.TextMessage, func(msg *protocol.Message) error {
		timestamp := time.Now().Format("2006-01-02 15:04:05")

		// Clear the current line
		fmt.Print("\r")

		// Print the message with timestamp
		fmt.Printf("\n[%s] Received message from %x: %s\n", timestamp, msg.Sender[:8], string(msg.Content))

		// Reprint the prompt
		fmt.Print("aegis> ")

		// Record received message in history
		cli.addToHistory(MessageRecord{
			Timestamp: time.Now(),
			Sender:    hex.EncodeToString(msg.Sender),
			Recipient: hex.EncodeToString(cli.publicKey),
			Content:   string(msg.Content),
			Status:    "received",
		})
		return nil
	})

	if !cli.useTor {
		cli.dht = dht.NewDHT(cli.localNode, cli.transport)
	}

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

	err := cli.transport.SendMessage(ctx, msg)

	// Record in history
	status := "sent"
	if err != nil {
		status = "failed"
	}

	cli.addToHistory(MessageRecord{
		Timestamp: time.Now(),
		Sender:    hex.EncodeToString(cli.publicKey),
		Recipient: hex.EncodeToString(recipientKey),
		Content:   message,
		Status:    status,
	})

	return err
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

// Add new method for sending Tor messages
func (cli *AegisCLI) sendTorMessage(onionAddress string, message string) error {
	// Validate onion address format
	if !strings.HasSuffix(onionAddress, ".onion") {
		return fmt.Errorf("invalid onion address: must end with .onion")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use the transport's SendTorMessage method
	err := cli.transport.SendTorMessage(ctx, onionAddress, []byte(message))

	// Record in history
	status := "sent"
	if err != nil {
		status = "failed"
	}

	cli.addToHistory(MessageRecord{
		Timestamp: time.Now(),
		Sender:    cli.torManager.OnionAddress,
		Recipient: onionAddress,
		Content:   message,
		Status:    status,
	})

	return err
}

func (cli *AegisCLI) startInteractiveCLI(port int, bootstrapIP string, bootstrapPort int, isServer bool) error {
	// Initialize network
	if err := cli.initializeNetwork(port, bootstrapIP, bootstrapPort); err != nil {
		return fmt.Errorf("failed to initialize network: %v", err)
	}

	nodeType := "client"
	if isServer {
		nodeType = "server"
	}

	// Print local node info
	fmt.Printf("Local Node (%s) Public Key: %x\n", nodeType, cli.publicKey)
	fmt.Printf("Listening on port: %d\n", port)
	if cli.useTor {
		fmt.Printf("Tor enabled - Onion address: %s\n", cli.torManager.OnionAddress)
	} else {
		fmt.Printf("DHT mode - Bootstrapping to: %s:%d\n", bootstrapIP, bootstrapPort)
	}

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
				if cli.useTor {
					fmt.Println("Usage: send <onion_address> <message>")
				} else {
					fmt.Println("Usage: send <recipient_key> <message>")
				}
				continue
			}
			sendParts := strings.SplitN(args, " ", 2)
			if len(sendParts) < 2 {
				if cli.useTor {
					fmt.Println("Usage: send <onion_address> <message>")
				} else {
					fmt.Println("Usage: send <recipient_key> <message>")
				}
				continue
			}
			recipient := sendParts[0]
			message := sendParts[1]

			if cli.useTor {
				if err := cli.sendTorMessage(recipient, message); err != nil {
					fmt.Printf("Failed to send message: %v\n", err)
				} else {
					fmt.Println("Message sent successfully")
				}
			} else {
				recipientBytes, err := hex.DecodeString(recipient)
				if err != nil {
					fmt.Printf("Invalid recipient key: %v\n", err)
					continue
				}

				if err := cli.sendMessage(recipientBytes, message); err != nil {
					fmt.Printf("Failed to send message: %v\n", err)
				} else {
					fmt.Println("Message sent successfully")
				}
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

		case "list":
			fmt.Println("Connected peers:")
			cli.transport.RangePeers(func(publicKey []byte, peer *network.Peer) bool {
				fmt.Printf("Peer %x @ %v (connected: %v)\n",
					publicKey[:8],
					peer.Address,
					peer.IsConnected())
				return true
			})

		case "status":
			fmt.Println("Network Status:")
			fmt.Printf("Local Node: %x\n", cli.publicKey)
			fmt.Printf("Listening Port: %d\n", cli.localNode.Address.Port)
			fmt.Printf("Node Type: %s\n", nodeType)

			var connected, total int
			cli.transport.RangePeers(func(publicKey []byte, peer *network.Peer) bool {
				total++
				if peer.IsConnected() {
					connected++
				}
				return true
			})
			fmt.Printf("Connected Peers: %d/%d\n", connected, total)

		case "history":
			cli.historyMu.RLock()
			if len(cli.messageHistory) == 0 {
				fmt.Println("No message history")
			} else {
				for _, record := range cli.messageHistory {
					fmt.Printf("[%s] %s -> %s: %s (%s)\n",
						record.Timestamp.Format("15:04:05"),
						record.Sender[:8],
						record.Recipient[:8],
						record.Content,
						record.Status)
				}
			}
			cli.historyMu.RUnlock()

		case "mykey":
			fmt.Printf("Local Public Key: %x\n", cli.publicKey)

		case "exit":
			return nil

		case "help":
			fmt.Println("Available commands:")
			if cli.useTor {
				fmt.Println("  send <onion_address> <message>   - Send a message to a Tor hidden service")
			} else {
				fmt.Println("  send <recipient_key> <message>   - Send a message to a recipient")
				fmt.Println("  find <target_key>                - Find nodes with a specific key")
				fmt.Println("  bootstrap <ip:port>              - Add a bootstrap node to discover peers")
			}
			fmt.Println("  list                           - List all connected peers")
			fmt.Println("  status                         - Show network status")
			fmt.Println("  history                        - Show message history")
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
	port := flag.Int("port", 0, "Port to listen on (random high port if not specified)")
	bootstrapIP := flag.String("bootstrap-ip", "127.0.0.1", "Bootstrap node IP address")
	bootstrapPort := flag.Int("bootstrap-port", 8080, "Bootstrap node port")
	useTor := flag.Bool("tor", false, "Use Tor network instead of DHT")
	flag.Parse()

	// Determine port
	if *port == 0 {
		// Get random available port
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("Failed to find available port: %v", err)
		}
		*port = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}

	// Initialize keys with port
	if err := cli.initializeKeys(*port); err != nil {
		log.Fatalf("Failed to initialize keys: %v", err)
	}

	// Initialize Tor if requested
	cli.useTor = *useTor
	if cli.useTor {
		if err := cli.initializeTor(); err != nil {
			log.Fatalf("Failed to initialize Tor: %v", err)
		}
		defer cli.torManager.StopTor()
	}

	log.Printf("Starting Aegis client on port %d (Mode: %s)", *port,
		map[bool]string{true: "Tor", false: "DHT"}[cli.useTor])

	if err := cli.startInteractiveCLI(*port, *bootstrapIP, *bootstrapPort, false); err != nil {
		log.Fatalf("CLI error: %v", err)
	}
}
