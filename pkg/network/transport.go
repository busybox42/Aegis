package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/busybox42/Aegis/pkg/dht"
	"github.com/busybox42/Aegis/pkg/protocol"
	"github.com/busybox42/Aegis/pkg/tor"
	"github.com/busybox42/Aegis/pkg/types"
	"golang.org/x/net/proxy"
)

type Transport struct {
	config          *Config
	listener        net.Listener
	dht             *dht.DHT
	peers           sync.Map
	peerConnections sync.Map
	handlers        sync.Map
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	torDialer       proxy.Dialer
	torManager      *tor.TorManager
}

func NewTransport(cfg *Config) *Transport {
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	if cfg.UseTor {
		log.Printf("Initializing transport with Tor configuration")
		t.torManager = cfg.TorManager
		if t.torManager == nil {
			log.Printf("WARNING: TorManager is nil despite UseTor being true")
		} else {
			log.Printf("TorManager initialized with SOCKS port: %d", t.torManager.GetSocksPort())
		}
	}

	return t
}

func (t *Transport) Start() error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", t.config.Port))
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	t.listener = listener

	localNode := types.NewNode(t.config.PublicKey, t.listener.Addr().(*net.TCPAddr))
	t.dht = dht.NewDHT(localNode, t)

	go t.acceptLoop()

	// Initialize bootstrap connections after a short delay
	if len(t.config.Bootstrap) > 0 {
		go func() {
			time.Sleep(100 * time.Millisecond) // Allow listener to start
			t.bootstrapNetwork()
		}()
	}

	return nil
}

func (t *Transport) Stop() error {
	log.Printf("Stopping transport")
	t.cancel()
	t.peers.Range(func(key, value interface{}) bool {
		if peer, ok := value.(*Peer); ok {
			peer.Disconnect()
		}
		return true
	})
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *Transport) SendMessage(ctx context.Context, msg *protocol.Message) error {
	if !msg.Verify() {
		return fmt.Errorf("invalid message signature")
	}

	var targetPeer *Peer
	t.peers.Range(func(key, value interface{}) bool {
		peer := value.(*Peer)
		if bytes.Equal(peer.PublicKey, msg.Recipient) {
			targetPeer = peer
			return false
		}
		return true
	})

	if targetPeer == nil {
		return fmt.Errorf("peer not found: %x", msg.Recipient)
	}

	if !targetPeer.IsConnected() {
		if err := targetPeer.Connect(); err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
	}

	if msg.Type == protocol.TextMessage {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("[%s] Sending message to %x\n", timestamp, targetPeer.PublicKey[:8])
	}

	sendCh := make(chan error, 1)
	go func() {
		sendCh <- targetPeer.SendMessage(msg)
	}()

	select {
	case err := <-sendCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Transport) RegisterHandler(msgType protocol.MessageType, handler MessageHandlerFunc) {
	t.handlers.Store(msgType, handler)
	log.Printf("Registered handler for message type %v", msgType)
}

func (t *Transport) FindNode(ctx context.Context, node *types.Node, targetID []byte) ([]*types.Node, error) {
	var localNodes []*types.Node
	t.peers.Range(func(key, value interface{}) bool {
		peer := value.(*Peer)
		if bytes.Equal(peer.PublicKey, targetID) {
			localNodes = append(localNodes, types.NewNode(peer.PublicKey, peer.Address))
		}
		return true
	})

	if len(localNodes) > 0 {
		return localNodes, nil
	}

	bootstrapAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	peer := NewPeer(nil, bootstrapAddr)

	if err := peer.Connect(); err != nil {
		return nil, fmt.Errorf("bootstrap connection failed: %v", err)
	}

	msg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, targetID, nil)
	msg.Sign(t.config.PrivateKey)

	if err := peer.SendMessage(msg); err != nil {
		peer.Disconnect()
		return nil, fmt.Errorf("failed to send discovery to bootstrap: %v", err)
	}

	time.Sleep(1 * time.Second)

	var discoveredNodes []*types.Node
	t.peers.Range(func(key, value interface{}) bool {
		peer := value.(*Peer)
		if peer.PublicKey != nil {
			discoveredNodes = append(discoveredNodes, types.NewNode(peer.PublicKey, peer.Address))
		}
		return true
	})

	if len(discoveredNodes) > 0 {
		return discoveredNodes, nil
	}

	return nil, fmt.Errorf("no nodes found for target %x", targetID)
}

func (t *Transport) acceptLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			conn, err := t.listener.Accept()
			if err != nil {
				if t.ctx.Err() != nil {
					return
				}
				continue
			}
			go t.handleConnection(conn)
		}
	}
}

func (t *Transport) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))

		var msgLen uint32
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return
		}

		if msgLen > maxMsgSize {
			return
		}

		msgData := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgData); err != nil {
			return
		}

		conn.SetReadDeadline(time.Time{})

		msg, err := protocol.DeserializeMessage(msgData)
		if err != nil {
			continue
		}

		switch msg.Type {
		case protocol.PeerDiscovery:
			if err := t.handlePeerDiscovery(conn, msg); err != nil {
				log.Printf("Peer discovery error: %v", err)
			}
		default:
			if handler, ok := t.getHandler(msg.Type); ok {
				if err := handler(msg); err != nil {
					log.Printf("Handler error: %v", err)
				} else if msg.Type == protocol.TextMessage {
					//log.Printf("Handled message from peer %x", msg.Sender[:8])
				}
			}
		}
	}
}

func (t *Transport) getHandler(msgType protocol.MessageType) (MessageHandlerFunc, bool) {
	if handler, ok := t.handlers.Load(msgType); ok {
		return handler.(MessageHandlerFunc), true
	}
	return nil, false
}

func (t *Transport) handlePeerDiscovery(conn net.Conn, msg *protocol.Message) error {
	if !msg.Verify() {
		return fmt.Errorf("invalid message signature")
	}

	t.mu.Lock()
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	peerAddr := &net.TCPAddr{
		IP:   remoteAddr.IP,
		Port: msg.ListeningPort,
	}

	senderPeer := NewPeer(msg.Sender, peerAddr)
	t.mu.Unlock()

	t.storePeer(senderPeer)

	for _, peerInfo := range msg.PeerList {
		if bytes.Equal(peerInfo.PublicKey, t.config.PublicKey) {
			continue
		}

		addr, err := net.ResolveTCPAddr("tcp", peerInfo.Address)
		if err != nil {
			continue
		}

		newPeer := NewPeer(peerInfo.PublicKey, addr)
		t.storePeer(newPeer)
	}

	t.mu.Lock()
	response := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, msg.Sender, nil)
	response.ListeningPort = t.config.Port
	response.PeerList = t.getKnownPeersLocked(msg.Sender)
	t.mu.Unlock()

	response.Sign(t.config.PrivateKey)
	return sendMessageToConn(conn, response)
}

func (t *Transport) bootstrapNetwork() {
	for _, addr := range t.config.Bootstrap {
		discoveryMsg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, nil, nil)
		discoveryMsg.ListeningPort = t.config.Port
		discoveryMsg.Sign(t.config.PrivateKey)

		peer := NewPeer(nil, addr)
		if err := peer.Connect(); err != nil {
			continue
		}

		t.storePeer(peer)
		peer.SendMessage(discoveryMsg)
	}
}

func (t *Transport) storePeer(peer *Peer) {
	if peer.PublicKey == nil || bytes.Equal(peer.PublicKey, t.config.PublicKey) {
		return
	}

	key := fmt.Sprintf("%x", peer.PublicKey)

	t.mu.Lock()
	defer t.mu.Unlock() // Ensure mutex is unlocked when we're done

	if existing, loaded := t.peers.LoadOrStore(key, peer); loaded {
		existingPeer := existing.(*Peer)
		if peer.Address != nil {
			existingPeer.Address = peer.Address
		}
	} else {
		// Create a new goroutine with copied data to avoid race conditions
		peerCopy := *peer // Make a copy of the peer
		go func() {
			if err := peer.Connect(); err == nil {
				t.mu.Lock()
				msg := protocol.NewMessage(protocol.PeerDiscovery, t.config.PublicKey, peerCopy.PublicKey, nil)
				msg.ListeningPort = t.config.Port
				peerList := t.getKnownPeersLocked(peerCopy.PublicKey) // Use locked version
				t.mu.Unlock()

				msg.PeerList = peerList
				if err := msg.Sign(t.config.PrivateKey); err == nil {
					peer.SendMessage(msg)
				}
			}
		}()
	}
}

// getKnownPeersLocked assumes the mutex is already held
func (t *Transport) getKnownPeersLocked(excludeKey []byte) []protocol.PeerInfo {
	var peers []protocol.PeerInfo
	seen := make(map[string]bool)

	t.peers.Range(func(_, value interface{}) bool {
		peer := value.(*Peer)
		if peer.PublicKey == nil || bytes.Equal(peer.PublicKey, excludeKey) ||
			bytes.Equal(peer.PublicKey, t.config.PublicKey) {
			return true
		}

		peerKey := fmt.Sprintf("%x", peer.PublicKey)
		if !seen[peerKey] {
			peers = append(peers, protocol.PeerInfo{
				PublicKey: peer.PublicKey,
				Address:   peer.Address.String(),
			})
			seen[peerKey] = true
		}
		return true
	})
	return peers
}

// getKnownPeers acquires the mutex before getting peers
func (t *Transport) getKnownPeers(excludeKey []byte) []protocol.PeerInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getKnownPeersLocked(excludeKey)
}

func sendMessageToConn(conn net.Conn, msg *protocol.Message) error {
	data, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("serialization error: %w", err)
	}

	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func (t *Transport) RangePeers(f func(publicKey []byte, peer *Peer) bool) {
	t.peers.Range(func(key, value interface{}) bool {
		peer := value.(*Peer)
		return f(peer.PublicKey, peer)
	})
}

func (t *Transport) dialWithTor(addr string) (net.Conn, error) {
	if t.config.UseTor && t.torDialer != nil {
		return t.torDialer.Dial("tcp", addr)
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	return dialer.Dial("tcp", addr)
}

func (t *Transport) GetListenerPort() int {
	if t.listener == nil {
		return 0
	}
	return t.listener.Addr().(*net.TCPAddr).Port
}

func (t *Transport) GetTorManager() *tor.TorManager {
	return t.torManager
}

func (t *Transport) SendTorMessage(ctx context.Context, onionAddress string, content []byte) error {
	if !t.config.UseTor {
		return fmt.Errorf("tor not enabled in config")
	}

	if t.torManager == nil {
		return fmt.Errorf("torManager is nil")
	}

	socksPort := t.torManager.GetSocksPort()
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	log.Printf("Connecting to Tor SOCKS proxy at %s", socksAddr)

	// Create a SOCKS5 dialer through the Tor proxy
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	// Connect to the onion service using port 8080 instead of 80
	targetAddr := onionAddress + ":8080" // Changed from port 80 to 8080
	log.Printf("Attempting to connect to onion service: %s", targetAddr)

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to onion service: %v", err)
	}
	defer conn.Close()

	// Create a protocol message for Tor communication
	msg := &protocol.Message{
		Type:      protocol.TextMessage,
		Content:   content,
		Timestamp: time.Now(),
		Sender:    []byte(t.torManager.OnionAddress),
	}

	// Serialize the message
	data, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	// Write message length first
	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		return fmt.Errorf("failed to write message length: %v", err)
	}

	// Send the message
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	log.Printf("Successfully sent message to %s", onionAddress)
	return nil
}
