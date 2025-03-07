package tor

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// 🔹 Declare mutex to prevent parallel test execution
var torTestMutex sync.Mutex

func TestTorManager(t *testing.T) {
	torTestMutex.Lock() // Ensure tests don't run in parallel
	defer torTestMutex.Unlock()

	fmt.Println("[Test] Starting embedded Tor...")

	// Start the Tor manager
	torManager, err := StartTor()
	require.NoError(t, err, "Failed to start embedded Tor")

	// Ensure the Tor manager started correctly
	require.NotNil(t, torManager, "TorManager should not be nil")
	require.NotEmpty(t, torManager.OnionAddress, "TorManager should have an Onion address")
	fmt.Printf("[Test] Tor Hidden Service started at: %s\n", torManager.OnionAddress)

	// Stop Tor after test
	defer func() {
		err := torManager.StopTor()
		require.NoError(t, err, "Failed to stop embedded Tor")
	}()

	// Wait a bit to ensure Tor is fully initialized
	time.Sleep(5 * time.Second)
}

func TestSocks5Dialer(t *testing.T) {
	torTestMutex.Lock() // Ensure tests don't run in parallel
	defer torTestMutex.Unlock()

	fmt.Println("[Test] Checking SOCKS5 proxy...")

	// Start a fresh Tor instance with a random available port
	torManager, err := StartTor()
	require.NoError(t, err, "Failed to start embedded Tor")
	defer torManager.StopTor()

	// Ensure SOCKS5 proxy is available
	dialer, err := torManager.GetSocks5Dialer()
	require.NoError(t, err, "Failed to get SOCKS5 dialer")

	// Test connecting through Tor to a known service
	testAddr := "check.torproject.org:80"
	conn, err := dialer.Dial("tcp", testAddr)
	if err != nil {
		t.Skipf("Tor not available, skipping test: %v", err)
		return
	}
	defer conn.Close()

	fmt.Println("[Test] Successfully connected to check.torproject.org via Tor")
}
