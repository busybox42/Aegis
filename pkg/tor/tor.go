package tor

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
	"log"

	"github.com/cretz/bine/tor"
	"golang.org/x/net/proxy"
)

// TorManager manages an embedded Tor instance and Hidden Service.
type TorManager struct {
	TorInstance  *tor.Tor
	OnionAddress string
	SocksPort    int
	DataDir      string
}

// StartTor initializes the embedded Tor process and sets up a Hidden Service on the default port (8080).
func StartTor() (*TorManager, error) {
	return StartTorWithPort(8080) // Default Aegis peer port
}

// StartTorWithPort initializes the embedded Tor process with a SOCKS5 proxy on a random high port.
func StartTorWithPort(port int) (*TorManager, error) {
    // More comprehensive logging and error handling
    log.Printf("[Tor] Initializing Tor with target port %d", port)

    // Existing Tor instance check
    existingPort := checkForRunningTor()
    if existingPort > 0 {
        log.Printf("[Tor] Existing Tor instance found on port %d", existingPort)
        
        // Create a TorManager that uses the existing instance
        // The caller will need to establish its own hidden service
        return &TorManager{
            SocksPort:    existingPort,
            OnionAddress: "", // Can't determine the .onion address here
        }, nil
    }
    
    log.Printf("[Tor] Starting new embedded Tor instance on port %d", port)

    // Generate a random high port for SOCKS5
    socksPort := getRandomHighPort()

    // Create a temporary Tor data directory
    dataDir, err := os.MkdirTemp("", "tor-data-*")
    if err != nil {
        return nil, fmt.Errorf("failed to create temporary Tor data directory: %w", err)
    }

    // Use a dynamically assigned SOCKS5 port and store the data dir for cleanup
    torConfig := &tor.StartConf{
        ProcessCreator: nil,     // Default process creator
        TorrcFile:      "",      // No custom torrc file
        DataDir:        dataDir, // Set temp directory for Tor data
        DebugWriter:    nil,     // No debug output
        ExtraArgs:      []string{"--SocksPort", strconv.Itoa(socksPort)}, // Use generated SOCKS5 port
    }

    // Start embedded Tor instance with the configuration
    t, err := tor.Start(context.Background(), torConfig)
    if err != nil {
        os.RemoveAll(dataDir) // Cleanup on failure
        return nil, fmt.Errorf("failed to start embedded Tor: %w", err)
    }

    // Enable networking through control port
    fmt.Println("[Tor] Enabling network...")
    if err := t.EnableNetwork(context.Background(), true); err != nil {
        t.Close()
        os.RemoveAll(dataDir)
        return nil, fmt.Errorf("failed to enable network: %w", err)
    }

    // Ensure Tor is fully initialized before setting up the service
    fmt.Println("[Tor] Waiting for Tor to initialize...")
    time.Sleep(10 * time.Second)

    // Ensure SOCKS5 proxy is actually available before continuing
    socksAddress := fmt.Sprintf("127.0.0.1:%d", socksPort)
    if !waitForSocks5Proxy(socksAddress, 10*time.Second) {
        t.Close()
        os.RemoveAll(dataDir)
        return nil, fmt.Errorf("SOCKS5 proxy did not start on %s", socksAddress)
    }

    // Create a Hidden Service on the specified port
    fmt.Println("[Tor] Creating Hidden Service...")
    hs, err := t.Listen(context.Background(), &tor.ListenConf{
        LocalPort:   port,
        RemotePorts: []int{port},
        Version3:    true,
    })
    if err != nil {
        t.Close()
        os.RemoveAll(dataDir)
        return nil, fmt.Errorf("failed to start hidden service: %w", err)
    }

    // Return the Tor instance and .onion address
    fmt.Printf("[Tor] Hidden Service Address: %s.onion\n", hs.ID)
    return &TorManager{
        TorInstance:  t,
        OnionAddress: hs.ID + ".onion",
        SocksPort:    socksPort, // Store the dynamically assigned SOCKS5 port
        DataDir:      dataDir,   // Store data dir for cleanup
    }, nil
}

func checkForRunningTor() int {
    // Check common Tor SOCKS ports
    commonPorts := []int{9050, 9150}
    
    // Also check for standard Tor Browser ports
    if os.Getenv("TOR_SOCKS_PORT") != "" {
        if port, err := strconv.Atoi(os.Getenv("TOR_SOCKS_PORT")); err == nil {
            commonPorts = append(commonPorts, port)
        }
    }
    
    for _, port := range commonPorts {
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
        if err == nil {
            conn.Close()
            return port
        }
    }
    
    return 0
}

// getRandomHighPort generates a random available high port (49152-65535).
func getRandomHighPort() int {
    for attempt := 0; attempt < 100; attempt++ {
        port := rand.Intn(16383) + 49152 // Random port in range 49152-65535
        
        listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
        if err == nil {
            listener.Close()
            return port
        }
        
        log.Printf("[Tor] Port %d already in use, trying another", port)
    }
    
    log.Printf("[ERROR] Could not find available port after 100 attempts")
    return 0
}

// waitForSocks5Proxy checks if the SOCKS5 proxy is ready before proceeding.
func waitForSocks5Proxy(address string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", address)
		if err == nil {
			conn.Close()
			return true // SOCKS5 is up
		}
		time.Sleep(500 * time.Millisecond) // Retry every 500ms
	}
	return false
}

// GetSocks5Dialer returns a SOCKS5 dialer for outgoing connections via Tor.
func (tm *TorManager) GetSocks5Dialer() (proxy.Dialer, error) {
	socksAddress := fmt.Sprintf("127.0.0.1:%d", tm.SocksPort)
	fmt.Printf("[Tor] Setting up SOCKS5 dialer on %s...\n", socksAddress)
	dialer, err := proxy.SOCKS5("tcp", socksAddress, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}
	return dialer, nil
}

// StopTor shuts down the embedded Tor instance and cleans up the temp data directory.
func (tm *TorManager) StopTor() error {
	fmt.Println("[Tor] Stopping Tor...")
	if tm.TorInstance != nil {
		err := tm.TorInstance.Close()
		if err != nil {
			return err
		}
	}

	// Clean up the Tor data directory
	if tm.DataDir != "" {
		fmt.Printf("[Tor] Cleaning up data directory: %s\n", tm.DataDir)
		os.RemoveAll(tm.DataDir)
	}

	return nil
}
