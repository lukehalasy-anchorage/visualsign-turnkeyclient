// Package crypto provides cryptographic operations for signing and verification.
//
// This package provides:
//   - ECDSA P-256 signing and verification
//   - DER encoding/decoding of ECDSA signatures
//   - Public key extraction from signatures
//   - SHA256 hashing
//
// # Signing
//
// Sign data using ECDSA P-256:
//
//	signature, err := crypto.SignWithECDSA(privateKey, data)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Verification
//
// Verify ECDSA signatures:
//
//	valid := crypto.VerifyECDSASignature(publicKey, data, signature)
//
// # Serialization
//
// Marshal ECDSA signatures to DER format:
//
//	derSig, err := crypto.MarshalECDSASignatureDER(r, s)
//	if err != nil {
//		log.Fatal(err)
//	}
package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ECDSASignature represents an ECDSA signature for ASN.1 encoding
type ECDSASignature struct {
	R, S *big.Int
}

// SignWithECDSA signs data with an ECDSA private key using SHA256
func SignWithECDSA(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign the hash using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	// Convert to DER format
	return MarshalECDSASignatureDER(r, s)
}

// MarshalECDSASignatureDER converts ECDSA signature components to DER format
func MarshalECDSASignatureDER(r, s *big.Int) ([]byte, error) {
	signature := ECDSASignature{R: r, S: s}
	return asn1.Marshal(signature)
}

// VerifyECDSASignature verifies an ECDSA signature
func VerifyECDSASignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Parse signature (r || s format, 64 bytes total)
	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify the signature
	return ecdsa.Verify(publicKey, hash[:], r, s)
}
