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
	"github.com/busybox42/Aegis/pkg/types"
	"github.com/busybox42/Aegis/pkg/tor"
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
	useTor         bool
	torManager     *tor.TorManager
	onionAddress   string
	bootstrapOnion string
}

func newAegisCLI() *AegisCLI {
	storage := store.NewLocal()
	return &AegisCLI{
		storage:        storage,
		messageHistory: make([]MessageRecord, 0),
		useTor:         true, // Default to using Tor
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

func (cli *AegisCLI) bootstrapToTorHiddenService(onionAddr string) error {
	log.Printf("[DEBUG] Creating peer for onion address: %s", onionAddr)
	
	// Verify Tor dialer is available
	if cli.transport.GetTorManager() == nil {
		return fmt.Errorf("Tor manager not available")
	}
	
	// Get Tor SOCKS5 dialer
	dialer, err := cli.transport.GetTorManager().GetSocks5Dialer()
	if err != nil {
		return fmt.Errorf("Failed to get Tor SOCKS dialer: %v", err)
	}
	
	// Create a peer for the hidden service
	peer := network.NewPeer(nil, nil) // We don't know the public key yet
	peer.SetOnionAddress(onionAddr)
	peer.EnableTor(dialer)
	peer.SetForceOnion(true)
	
	// Add the peer
	cli.transport.StorePeer(peer)
	log.Printf("[DEBUG] Stored peer, attempting connection...")
	
	// Attempt connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Try to connect
	connChan := make(chan error, 1)
	go func() {
		connChan <- peer.Connect()
	}()
	
	// Wait for connection or timeout
	select {
	case err := <-connChan:
		if err != nil {
			return fmt.Errorf("Failed to connect to onion address: %v", err)
		}
	case <-ctx.Done():
		return fmt.Errorf("Connection timeout")
	}
	
	log.Printf("Successfully connected to onion service: %s", onionAddr)
	return nil
}

func (cli *AegisCLI) initializeNetwork(port int, bootstrapPort int) error {
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
    cli.localNode = types.NewNode(cli.publicKey, addr)

    networkConfig := &network.Config{
        Port:       port,
        PublicKey:  cli.publicKey,
        PrivateKey: cli.privateKey,
        UseTor:     cli.useTor,
    }
    
    // Only set bootstrap TCP address if not using onion address
    if cli.bootstrapOnion == "" {
        bootstrapAddr := &net.TCPAddr{
            IP:   net.ParseIP("127.0.0.1"),
            Port: bootstrapPort,
        }
        networkConfig.Bootstrap = []*net.TCPAddr{bootstrapAddr}
    } else {
        // Use onion bootstrap instead
        networkConfig.BootstrapOnion = cli.bootstrapOnion
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

    cli.dht = dht.NewDHT(cli.localNode, cli.transport)

    if err := cli.transport.Start(); err != nil {
        return err
    }

    if cli.useTor {
        cli.onionAddress = cli.transport.GetOnionAddress()
        cli.torManager = cli.transport.GetTorManager()
        if cli.onionAddress != "" {
            log.Printf("Tor Hidden Service address: %s", cli.onionAddress)
        }
    }

    // If we have a bootstrap onion, try to connect to it
    if cli.bootstrapOnion != "" && cli.useTor {
        if err := cli.bootstrapToTorHiddenService(cli.bootstrapOnion); err != nil {
            log.Printf("Warning: Failed to bootstrap to onion service: %v", err)
        }
    }

    return nil
}

func (cli *AegisCLI) bootstrapNode(address string) error {
    // Check if it's an onion address
    isOnion := strings.HasSuffix(address, ".onion")
    
    var addr *net.TCPAddr
    var err error
    
    if !isOnion {
        addr, err = net.ResolveTCPAddr("tcp", address)
        if err != nil {
            return fmt.Errorf("invalid address: %v", err)
        }
    }

    // Stop existing transport
    if err := cli.transport.Stop(); err != nil {
        return fmt.Errorf("failed to stop transport: %v", err)
    }

    networkConfig := &network.Config{
        Port:       cli.localNode.Address.Port,
        PublicKey:  cli.publicKey,
        PrivateKey: cli.privateKey,
        UseTor:     cli.useTor,
    }
    
    // If it's not an onion address, add it as bootstrap TCP address
    if !isOnion && addr != nil {
        networkConfig.Bootstrap = []*net.TCPAddr{addr}
    }
    
    // If it's an onion address, store it for later use
    if isOnion {
        networkConfig.BootstrapOnion = address
    }

    cli.transport = network.NewTransport(networkConfig)
    cli.dht = dht.NewDHT(cli.localNode, cli.transport)

    if err := cli.transport.Start(); err != nil {
        return err
    }

    if cli.useTor {
        cli.onionAddress = cli.transport.GetOnionAddress()
        cli.torManager = cli.transport.GetTorManager()
    }

    // If we have a bootstrap onion, try to connect to it
    if isOnion && cli.useTor {
        if err := cli.bootstrapToTorHiddenService(address); err != nil {
            return fmt.Errorf("failed to bootstrap to onion service: %v", err)
        }
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

	if cli.useTor && cli.onionAddress != "" {
		msg.OnionAddress = cli.onionAddress
	}

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

func (cli *AegisCLI) startInteractiveCLI(port int, bootstrapPort int, isServer bool) error {
	// Initialize network
	if err := cli.initializeNetwork(port, bootstrapPort); err != nil {
		return fmt.Errorf("failed to initialize network: %v", err)
	}

	nodeType := "client"
	if isServer {
		nodeType = "server"
	}
	
	// Print local node info
	fmt.Printf("Local Node (%s) Public Key: %x\n", nodeType, cli.publicKey)
	fmt.Printf("Listening on port: %d\n", port)
	
	if cli.bootstrapOnion != "" {
		fmt.Printf("Bootstrapping to onion: %s\n", cli.bootstrapOnion)
	} else if !isServer {
		fmt.Printf("Bootstrapping to: 127.0.0.1:%d\n", bootstrapPort)
	}
	
	if cli.useTor && cli.onionAddress != "" {
		fmt.Printf("Tor Hidden Service address: %s\n", cli.onionAddress)
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
				fmt.Println("Usage: bootstrap <ip:port> or <onion-address>")
				continue
			}

			if err := cli.bootstrapNode(args); err != nil {
				fmt.Printf("Failed to bootstrap node: %v\n", err)
			} else {
				fmt.Printf("Bootstrapped with node: %s\n", args)
			}

		case "tor":
			if cli.useTor {
				fmt.Printf("Tor is enabled, onion address: %s\n", cli.onionAddress)
			} else {
				fmt.Println("Tor is currently disabled")
			}

			if args == "on" {
				if !cli.useTor {
					fmt.Println("Restarting with Tor enabled (requires restart)")
					cli.useTor = true
					// Restart network with Tor enabled
					if err := cli.bootstrapNode(fmt.Sprintf("127.0.0.1:%d", bootstrapPort)); err != nil {
						fmt.Printf("Failed to enable Tor: %v\n", err)
					}
				}
			} else if args == "off" {
				if cli.useTor {
					fmt.Println("Disabling Tor (requires restart)")
					cli.useTor = false
					// Restart network with Tor disabled
					if err := cli.bootstrapNode(fmt.Sprintf("127.0.0.1:%d", bootstrapPort)); err != nil {
						fmt.Printf("Failed to disable Tor: %v\n", err)
					}
				}
			}

		case "connect":
			if args == "" {
				fmt.Println("Usage: connect <peer_public_key> <onion_address>")
				continue
			}
			
			connectParts := strings.SplitN(args, " ", 2)
			if len(connectParts) < 2 {
				fmt.Println("Usage: connect <peer_public_key> <onion_address>")
				continue
			}
			
			peerKey := connectParts[0]
			onionAddress := connectParts[1]
			
			// Verify onion address format
			if !strings.HasSuffix(onionAddress, ".onion") {
				fmt.Println("Invalid onion address: must end with .onion")
				continue
			}
			
			peerBytes, err := hex.DecodeString(peerKey)
			if err != nil {
				fmt.Printf("Invalid peer key: %v\n", err)
				continue
			}
			
			peer := network.NewPeer(peerBytes, nil)
			peer.SetOnionAddress(onionAddress)
			peer.SetForceOnion(true)
			
			if cli.useTor {
				dialer, err := cli.transport.GetTorManager().GetSocks5Dialer()
				if err != nil {
					fmt.Printf("Failed to get Tor SOCKS dialer: %v\n", err)
					continue
				}
				peer.EnableTor(dialer)
			}
			
			cli.transport.StorePeer(peer)
			
			// Actively attempt connection
			fmt.Printf("Attempting connection to %s...\n", onionAddress)
			err = peer.Connect()
			if err != nil {
				fmt.Printf("Connection failed: %v\n", err)
			} else {
				fmt.Printf("Successfully connected to peer via %s\n", onionAddress)
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
               // Check if it's an onion address instead
               if strings.HasSuffix(recipientKey, ".onion") {
                	// Find peer by onion address
                	var foundPeer *network.Peer
        			cli.transport.RangePeers(func(publicKey []byte, peer *network.Peer) bool {
                		if peer.GetOnionAddress() == recipientKey {
                    		foundPeer = peer
                    		recipientBytes = peer.PublicKey
                    		return false
                		}
                		return true
            		})
            
            		if foundPeer == nil {
                		fmt.Printf("No peer found with onion address: %s\n", recipientKey)
                		continue
            		}
        		} else {
            		fmt.Printf("Invalid recipient key: %v\n", err)
            		continue
        		}
            }
            
            // Now send the message
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

		case "list":
			fmt.Println("Connected peers:")
			peerCount := 0
			cli.transport.RangePeers(func(publicKey []byte, peer *network.Peer) bool {
				peerCount++
				var onionInfo string
				onionAddr := peer.GetOnionAddress()
				if onionAddr != "" {
					onionInfo = fmt.Sprintf(" (.onion: %s)", onionAddr)
				}
				
				var pubKeyDisplay string
				if publicKey == nil || len(publicKey) < 8 {
					pubKeyDisplay = "<unknown>"
				} else {
					pubKeyDisplay = fmt.Sprintf("%x", publicKey[:8])
				}
				
				fmt.Printf("Peer %s @ %v%s (connected: %v)\n",
					pubKeyDisplay,
					peer.Address,
					onionInfo,
					peer.IsConnected())
				return true
			})
			
			if peerCount == 0 {
				fmt.Println("No peers found")
			}

		case "status":
			fmt.Println("Network Status:")
			fmt.Printf("Local Node: %x\n", cli.publicKey)
			fmt.Printf("Listening Port: %d\n", cli.localNode.Address.Port)
			fmt.Printf("Node Type: %s\n", nodeType)
			fmt.Printf("Tor Enabled: %v\n", cli.useTor)
			if cli.useTor && cli.onionAddress != "" {
				fmt.Printf("Onion Address: %s\n", cli.onionAddress)
			}

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
			if cli.useTor && cli.onionAddress != "" {
				fmt.Printf("Onion Address: %s\n", cli.onionAddress)
			}

		case "exit":
			return nil

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  bootstrap <ip:port>|<onion>     - Add a bootstrap node to discover peers")
			fmt.Println("  connect <peer_key> <onion>      - Connect to a peer via its onion address")
			fmt.Println("  tor <on|off>                    - Enable or disable Tor networking")
			fmt.Println("  send <recipient_key> <message>  - Send a message to a recipient")
			fmt.Println("  find <target_key>               - Find nodes with a specific key")
			fmt.Println("  list                            - List all connected peers")
			fmt.Println("  status                          - Show network status")
			fmt.Println("  history                         - Show message history")
			fmt.Println("  mykey                           - Show local node's public key")
			fmt.Println("  help                            - Show this help message")
			fmt.Println("  exit                            - Exit the application")

		default:
			fmt.Printf("Unknown command: %s. Type 'help' for usage.\n", command)
		}
	}
}

func main() {
    cli := newAegisCLI()

    // Command-line flags
    port := flag.Int("port", 0, "Port to listen on (random high port if not specified)")
    bootstrapOnion := flag.String("bootstrap-onion", "", "Bootstrap node .onion address")
    bootstrapIP := flag.String("bootstrap-ip", "127.0.0.1", "Bootstrap node IP address")
    bootstrapPort := flag.Int("bootstrap-port", 8080, "Bootstrap node port")
    useTor := flag.Bool("tor", true, "Use Tor for networking (default: true)")
    flag.Parse()

    cli.useTor = *useTor

    // Check if bootstrap-onion is provided
    if *bootstrapOnion != "" {
        cli.bootstrapOnion = *bootstrapOnion
        log.Printf("Using Tor bootstrap onion address: %s", cli.bootstrapOnion)
    }

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

    // Log startup information
    if cli.bootstrapOnion != "" {
        log.Printf("Starting Aegis client on port %d, bootstrapping to onion address %s (Tor: %v)", 
            *port, cli.bootstrapOnion, cli.useTor)
    } else {
        log.Printf("Starting Aegis client on port %d, bootstrapping to %s:%d (Tor: %v)", 
            *port, *bootstrapIP, *bootstrapPort, cli.useTor)
    }
        
    if err := cli.startInteractiveCLI(*port, *bootstrapPort, false); err != nil {
        log.Fatalf("CLI error: %v", err)
    }
}