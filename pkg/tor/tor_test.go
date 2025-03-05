package tor_test

import (
	"testing"
	"time"

	"github.com/busybox42/Aegis/pkg/tor"
)

// TestTorManager ensures that embedded Tor starts and creates a Hidden Service.
func TestTorManager(t *testing.T) {
	t.Log("[Test] Starting embedded Tor...")

	// Start the embedded Tor instance
	torManager, err := tor.StartTor()
	if err != nil {
		t.Fatalf("Failed to start embedded Tor: %v", err)
	}
	defer torManager.StopTor()

	// Wait for Tor to initialize
	time.Sleep(5 * time.Second)

	// Check if a valid .onion address is created
	if torManager.OnionAddress == "" {
		t.Fatalf("Tor Hidden Service address is empty")
	}
	t.Logf("[Test] Tor Hidden Service started at: %s", torManager.OnionAddress)
}

// TestSocks5Dialer ensures that the SOCKS5 proxy is working.
func TestSocks5Dialer(t *testing.T) {
	t.Log("[Test] Checking SOCKS5 proxy...")

	// Use a different port for the second test to avoid conflicts
	altPort := 9090

	// Start Tor if it's not already running
	torManager, err := tor.StartTorWithPort(altPort)
	if err != nil {
		t.Skipf("Tor not available, skipping test: %v", err)
	}
	defer torManager.StopTor()

	// Wait for Tor to initialize
	time.Sleep(5 * time.Second)

	// Get SOCKS5 dialer
	dialer, err := torManager.GetSocks5Dialer()
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	// Test a connection through Tor's SOCKS5 proxy
	conn, err := dialer.Dial("tcp", "check.torproject.org:80")
	if err != nil {
		t.Fatalf("Failed to connect via Tor SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	t.Log("[Test] Successfully connected to check.torproject.org via Tor")
}
