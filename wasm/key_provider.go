// +build js,wasm

package wasm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
)

// MemoryKeyProvider provides API keys from memory (for WASM environment)
type MemoryKeyProvider struct {
	publicKey  string
	privateKey string
}

// NewMemoryKeyProvider creates a new memory-based key provider
func NewMemoryKeyProvider(publicKey, privateKey string) *MemoryKeyProvider {
	return &MemoryKeyProvider{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// GetAPIKey implements api.KeyProvider interface
func (m *MemoryKeyProvider) GetAPIKey(ctx context.Context) (*api.TurnkeyAPIKey, error) {
	// Parse private key from hex string
	privateKeyBytes, err := hex.DecodeString(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	// Create ECDSA private key
	curve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: new(big.Int).SetBytes(privateKeyBytes),
	}

	// Calculate public key point
	privateKey.X, privateKey.Y = curve.ScalarBaseMult(privateKeyBytes)

	return &api.TurnkeyAPIKey{
		PublicKey:  m.publicKey,
		PrivateKey: privateKey,
	}, nil
}
