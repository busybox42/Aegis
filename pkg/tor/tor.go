package tor

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

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

// StartTor initializes the embedded Tor process and sets up a Hidden Service on a random available port.
func StartTor() (*TorManager, error) {
	// Find a random available port for the Hidden Service
	port := getRandomHighPort()
	return StartTorWithPort(port)
}

// StartTorWithPort initializes the embedded Tor process with a SOCKS5 proxy on a random high port.
func StartTorWithPort(port int) (*TorManager, error) {
	fmt.Println("[Tor] Starting embedded Tor...")

	// Retry logic: If Tor fails to bind, try a new port up to 3 times
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Generate a random high port for SOCKS5
		socksPort := getRandomHighPort()

		// Create a temporary Tor data directory
		dataDir, err := os.MkdirTemp("", "tor-data-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary Tor data directory: %w", err)
		}

		// Use a dynamically assigned SOCKS5 port and store the data dir for cleanup
		torConfig := &tor.StartConf{
			ProcessCreator: nil,                                              // Default process creator
			TorrcFile:      "",                                               // No custom torrc file
			DataDir:        dataDir,                                          // Set temp directory for Tor data
			DebugWriter:    nil,                                              // No debug output
			ExtraArgs:      []string{"--SocksPort", strconv.Itoa(socksPort)}, // Use generated SOCKS5 port
		}

		// 🔹 Ensure previous Tor instance is fully stopped before starting a new one
		waitForPortRelease(socksPort)

		// Start embedded Tor instance with the configuration
		t, err := tor.Start(context.Background(), torConfig)
		if err != nil {
			os.RemoveAll(dataDir) // Cleanup on failure
			fmt.Printf("[Tor] Attempt %d failed to start Tor on port %d: %v\n", attempt, socksPort, err)
			continue // Try a new port
		}

		// 🔹 Wait before enabling network to avoid immediate conflicts
		fmt.Println("[Tor] Waiting before enabling network...")
		time.Sleep(3 * time.Second)

		// Enable networking through control port
		fmt.Println("[Tor] Enabling network...")
		if err := t.EnableNetwork(context.Background(), true); err != nil {
			t.Close()
			os.RemoveAll(dataDir)
			fmt.Printf("[Tor] Attempt %d failed: Could not enable network: %v\n", attempt, err)
			continue // Try a new port
		}

		// Ensure Tor is fully initialized before setting up the service
		fmt.Println("[Tor] Waiting for Tor to initialize...")
		time.Sleep(10 * time.Second)

		// Ensure SOCKS5 proxy is actually available before continuing
		socksAddress := fmt.Sprintf("127.0.0.1:%d", socksPort)
		if !waitForSocks5Proxy(socksAddress, 10*time.Second) {
			t.Close()
			os.RemoveAll(dataDir)
			fmt.Printf("[Tor] Attempt %d failed: SOCKS5 proxy did not start on %s\n", attempt, socksAddress)
			continue // Try a new port
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
			fmt.Printf("[Tor] Attempt %d failed: Could not create hidden service: %v\n", attempt, err)
			continue // Try a new port
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

	return nil, fmt.Errorf("failed to start Tor after %d attempts", maxRetries)
}

func waitForPortRelease(port int) {
	fmt.Printf("[Tor] Ensuring port %d is fully released before starting...\n", port)

	for i := 0; i < 10; i++ {
		if isPortAvailable(port) {
			fmt.Printf("[Tor] Port %d is free to use\n", port)
			return
		}
		time.Sleep(500 * time.Millisecond) // Wait 500ms before retrying
	}

	fmt.Printf("[Tor] Warning: Port %d may still be in use, proceeding with caution\n", port)
}

func waitForTorBinding(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			// If we can't listen, it means Tor has already bound to the port
			return true
		}
		ln.Close()
		time.Sleep(500 * time.Millisecond) // Retry every 500ms
	}
	fmt.Printf("[Tor] Warning: Port %d still appears free, but may be in use internally\n", port)
	return false
}

// isPortAvailable checks if a port is available for use
func isPortAvailable(port int) bool {
	var cmd *exec.Cmd

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd = exec.Command("lsof", "-i", fmt.Sprintf(":%d", port))
	} else if runtime.GOOS == "windows" {
		cmd = exec.Command("netstat", "-ano")
	} else {
		// Fallback to Go's net.Listen if OS is unknown
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		ln.Close()
		return true
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	// If `lsof` or `netstat` finds an active process, return false (port in use)
	return err != nil
}

// getRandomHighPort generates a random available high port (49152-65535).
func getRandomHighPort() int {
	rand.Seed(time.Now().UnixNano())

	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		port := rand.Intn(16383) + 49152 // Random port in range 49152-65535

		// Log every attempted port selection
		fmt.Printf("[Tor] Checking Port Availability: %d\n", port)

		if isPortAvailable(port) {
			fmt.Printf("[Tor] Selected Available Port: %d\n", port)
			return port
		}
	}

	// If we can't find an available port after max attempts, try sequential ports
	for port := 49152; port <= 65535; port++ {
		if isPortAvailable(port) {
			fmt.Printf("[Tor] Selected Sequential Available Port: %d\n", port)
			return port
		}
	}

	return 0 // This should never happen unless the system is extremely busy
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

	// 🔹 Wait until the ports are truly released before continuing
	for i := 0; i < 10; i++ {
		if isPortAvailable(tm.SocksPort) {
			break // Port is fully free
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("[Tor] Fully stopped and ports released.")
	return nil
}

// GetSocksPort returns the SOCKS5 port used by the TorManager
func (tm *TorManager) GetSocksPort() int {
	return tm.SocksPort
}
