package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"net"

	"crypto/ed25519"

	"github.com/sirupsen/logrus"
	"github.com/busybox42/Aegis/internal/store"
	"github.com/busybox42/Aegis/pkg/dht"
	"github.com/busybox42/Aegis/pkg/network"
	"github.com/busybox42/Aegis/pkg/types"
	"github.com/busybox42/Aegis/pkg/tor"
)

var log = logrus.New()

func initLogger() {
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

type AegisServer struct {
	storage      *store.Local
	transport    *network.Transport
	dht          *dht.DHT
	localNode    *types.Node
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	useTor       bool
	torManager   *tor.TorManager
	onionAddress string
}

func newAegisServer(port int, useTor bool) (*AegisServer, error) {
	log.Infof("Initializing Aegis server on port %d (Tor: %v)", port, useTor)
	storage := store.NewLocal()
	srv := &AegisServer{
		storage: storage,
		useTor:  useTor,
	}

	if err := srv.initializeKeys(port); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	if err := srv.initializeNetwork(port); err != nil {
		return nil, fmt.Errorf("failed to initialize network: %w", err)
	}

	log.Info("Aegis server initialized successfully")
	return srv, nil
}

func (srv *AegisServer) initializeKeys(port int) error {
	log.Info("Initializing keys")
	keyDir := filepath.Join(os.Getenv("HOME"), ".aegis")
	os.MkdirAll(keyDir, 0700)

	pubKeyPath := filepath.Join(keyDir, fmt.Sprintf("public_%d.key", port))
	privKeyPath := filepath.Join(keyDir, fmt.Sprintf("private_%d.key", port))

	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		log.Info("Generating new keys")
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("failed to generate keys: %w", err)
		}
		os.WriteFile(pubKeyPath, pub, 0600)
		os.WriteFile(privKeyPath, priv, 0600)
		srv.publicKey = pub
		srv.privateKey = priv
	} else {
		log.Info("Loading existing keys")
		pubBytes, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return err
		}
		privBytes, err := os.ReadFile(privKeyPath)
		if err != nil {
			return err
		}
		srv.publicKey = pubBytes
		srv.privateKey = privBytes
	}

	log.Info("Keys initialized successfully")
	return nil
}

func (srv *AegisServer) initializeNetwork(port int) error {
    log.Infof("Initializing network on port %d (Tor: %v)", port, srv.useTor)
    addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
    srv.localNode = types.NewNode(srv.publicKey, addr)

    networkConfig := &network.Config{
        Port:       port,
        PublicKey:  srv.publicKey,
        PrivateKey: srv.privateKey,
        UseTor:     srv.useTor,
    }

    srv.transport = network.NewTransport(networkConfig)
    
    // Get the torManager reference from the transport if it exists
    if srv.useTor {
        // You'll need to add a GetTorManager method to the Transport struct
        srv.torManager = srv.transport.GetTorManager()
    }
    
    srv.dht = dht.NewDHT(srv.localNode, srv.transport)

    if err := srv.transport.Start(); err != nil {
        log.Errorf("Failed to start transport: %v", err)
        return err
    }

    if srv.useTor {
        srv.onionAddress = srv.transport.GetOnionAddress()
        if srv.onionAddress != "" {
            log.Infof("Tor Hidden Service address: %s", srv.onionAddress)
        } else {
            log.Warn("Tor enabled but no onion address available")
        }
    }

    log.Info("Network initialized successfully")
    return nil
}

func (srv *AegisServer) Stop() {
    if srv.transport != nil {
        srv.transport.Stop()
    }
    
    // Explicitly shut down Tor
    if srv.torManager != nil {
        srv.torManager.StopTor()
    }
}

func main() {
	initLogger()
	port := flag.Int("port", 8080, "Port to listen on")
	useTor := flag.Bool("tor", true, "Use Tor for networking (default: true)")
	flag.Parse()

	log.Infof("Starting Aegis server on port %d (Tor: %v)", *port, *useTor)
	
	srv, err := newAegisServer(*port, *useTor)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	if *useTor && srv.onionAddress != "" {
		log.Infof("Tor Hidden Service address: %s", srv.onionAddress)
	}

	log.Info("Aegis server is running")
	// Keep running
	select {}
}