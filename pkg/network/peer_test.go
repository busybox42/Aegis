package network

import (
	"crypto/ed25519"
	"net"
	"testing"

	"github.com/busybox42/Aegis/pkg/tor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPeer(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	peer := NewPeer(pub, addr)

	require.NotNil(t, peer)
	assert.Equal(t, pub, peer.PublicKey)
	assert.Equal(t, addr.String(), peer.Address.String())
}

func TestPeerConnection(t *testing.T) {
	tests := []struct {
		name    string
		useTor  bool
		wantErr bool
	}{
		{
			name:    "Regular TCP connection",
			useTor:  false,
			wantErr: false,
		},
		{
			name:    "Tor connection",
			useTor:  true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.useTor && testing.Short() {
				t.Skip("Skipping Tor test in short mode")
			}

			pub, priv, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)

			var torManager *tor.TorManager
			if tt.useTor {
				torManager, err = tor.StartTor()
				require.NoError(t, err)
				defer torManager.StopTor()
			}

			config := &Config{
				Port:       0,
				PublicKey:  pub,
				PrivateKey: priv,
				UseTor:     tt.useTor,
				TorManager: torManager,
			}

			transport := NewTransport(config)
			err = transport.Start()
			require.NoError(t, err)
			defer transport.Stop()

			// Create a peer
			addr := transport.listener.Addr().(*net.TCPAddr)
			peer := NewPeer(pub, addr)

			// Test connection
			err = peer.Connect()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, peer.IsConnected())

			// Test disconnection
			err = peer.Disconnect()
			require.NoError(t, err)
			require.False(t, peer.IsConnected())
		})
	}
}
