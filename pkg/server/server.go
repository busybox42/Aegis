package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"crypto/ed25519"

	"github.com/busybox42/Aegis/internal/store"
	"github.com/busybox42/Aegis/pkg/dht"
	"github.com/busybox42/Aegis/pkg/network"
	"github.com/busybox42/Aegis/pkg/tor"
	"github.com/busybox42/Aegis/pkg/types"
	"github.com/sirupsen/logrus"
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
	storage    *store.Local
	transport  *network.Transport
	dht        *dht.DHT
	localNode  *types.Node
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	torManager *tor.TorManager
	useTor     bool
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

	if useTor {
		if err := srv.initializeTor(); err != nil {
			return nil, fmt.Errorf("failed to initialize Tor: %w", err)
		}
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

func (srv *AegisServer) initializeTor() error {
	log.Info("Initializing Tor")
	torManager, err := tor.StartTor()
	if err != nil {
		return fmt.Errorf("failed to start Tor: %w", err)
	}
	srv.torManager = torManager
	log.Infof("Tor initialized successfully. Onion address: %s", torManager.OnionAddress)
	return nil
}

func (srv *AegisServer) initializeNetwork(port int) error {
	log.Infof("Initializing network on port %d", port)
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	srv.localNode = types.NewNode(srv.publicKey, addr)

	networkConfig := &network.Config{
		Port:       port,
		PublicKey:  srv.publicKey,
		PrivateKey: srv.privateKey,
		UseTor:     srv.useTor,
		TorManager: srv.torManager,
	}

	srv.transport = network.NewTransport(networkConfig)
	srv.dht = dht.NewDHT(srv.localNode, srv.transport)

	if err := srv.transport.Start(); err != nil {
		log.Errorf("Failed to start transport: %v", err)
		return err
	}

	log.Info("Network initialized successfully")
	return nil
}

func (srv *AegisServer) Shutdown() error {
	if srv.torManager != nil {
		if err := srv.torManager.StopTor(); err != nil {
			log.Errorf("Error stopping Tor: %v", err)
		}
	}
	if srv.transport != nil {
		if err := srv.transport.Stop(); err != nil {
			log.Errorf("Error stopping transport: %v", err)
		}
	}
	return nil
}

func main() {
	initLogger()
	port := flag.Int("port", 8080, "Port to listen on")
	useTor := flag.Bool("tor", false, "Use Tor network")
	flag.Parse()

	log.Infof("Starting Aegis server on port %d (Tor: %v)", *port, *useTor)
	srv, err := newAegisServer(*port, *useTor)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Shutdown()

	log.Info("Aegis server is running")
	// Keep running
	select {}
}
