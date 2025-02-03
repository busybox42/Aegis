// pkg/crypto/keys_test.go
package crypto

import (
    "testing"
)

func TestGenerateKeyPair(t *testing.T) {
    tests := []struct {
        name    string
        wantErr bool
    }{
        {
            name:    "Successful key generation",
            wantErr: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            kp, err := GenerateKeyPair()
            if (err != nil) != tt.wantErr {
                t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if kp == nil {
                t.Error("Expected KeyPair, got nil")
                return
            }
            if len(kp.PublicKey) == 0 {
                t.Error("Public key is empty")
            }
            if len(kp.PrivateKey) == 0 {
                t.Error("Private key is empty")
            }
        })
    }
}

func TestKeyPairSignVerify(t *testing.T) {
    message := []byte("test message")
    
    kp, err := GenerateKeyPair()
    if err != nil {
        t.Fatalf("Failed to generate key pair: %v", err)
    }

    signature, err := kp.Sign(message)
    if err != nil {
        t.Fatalf("Failed to sign message: %v", err)
    }

    if !kp.Verify(message, signature) {
        t.Error("Failed to verify valid signature")
    }

    // Test invalid signature
    invalidMessage := []byte("different message")
    if kp.Verify(invalidMessage, signature) {
        t.Error("Verified invalid signature")
    }
}