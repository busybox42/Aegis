// pkg/crypto/keys.go
package crypto

import (
    "crypto/ed25519"
    "crypto/rand"
)

// KeyPair represents a public/private key pair for signing and verification
type KeyPair struct {
    PublicKey  ed25519.PublicKey
    PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a new Ed25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }

    return &KeyPair{
        PublicKey:  publicKey,
        PrivateKey: privateKey,
    }, nil
}

// Sign creates a signature for the given message using the private key
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
    return ed25519.Sign(kp.PrivateKey, message), nil
}

// Verify checks if the signature is valid for the given message
func (kp *KeyPair) Verify(message, signature []byte) bool {
    return ed25519.Verify(kp.PublicKey, message, signature)
}