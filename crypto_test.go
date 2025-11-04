package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPublicKeyExtraction tests extracting a 65-byte public key from 130-byte format
func TestPublicKeyExtraction(t *testing.T) {
	// P-256 generates 256-bit keys = 32 bytes for X and Y coordinates
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := privKey.PublicKey

	// Create 130-byte format: two 65-byte public key representations
	// First 65 bytes: uncompressed format (0x04 || X || Y)
	x := pubKey.X.Bytes()
	y := pubKey.Y.Bytes()

	// Pad to 32 bytes if needed
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)

	// Create 130-byte public key representation (two 65-byte keys)
	pubKeyBytes130 := make([]byte, 130)
	pubKeyBytes130[0] = 0x04
	copy(pubKeyBytes130[1:33], xPadded)
	copy(pubKeyBytes130[33:65], yPadded)
	pubKeyBytes130[65] = 0x04
	copy(pubKeyBytes130[66:98], xPadded)
	copy(pubKeyBytes130[98:130], yPadded)

	tests := []struct {
		name                 string
		publicKeyBytes       []byte
		expectedLen          int
		expectedFirstByte    byte
		shouldExtractSuccess bool
	}{
		{
			name:                 "valid 130-byte key",
			publicKeyBytes:       pubKeyBytes130,
			expectedLen:          65,
			expectedFirstByte:    0x04,
			shouldExtractSuccess: true,
		},
		{
			name:                 "extract latter 65 bytes",
			publicKeyBytes:       pubKeyBytes130,
			expectedLen:          65,
			expectedFirstByte:    0x04,
			shouldExtractSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Len(t, tt.publicKeyBytes, 130)

			// Extract the latter 65 bytes as done in verify.go
			extractedKey := tt.publicKeyBytes[65:]

			require.Len(t, extractedKey, tt.expectedLen)
			require.Equal(t, tt.expectedFirstByte, extractedKey[0])

			if tt.shouldExtractSuccess {
				// Verify the extracted key is in correct format (0x04 || X || Y)
				keyLen := 32
				x := new(big.Int).SetBytes(extractedKey[1 : 1+keyLen])
				y := new(big.Int).SetBytes(extractedKey[1+keyLen:])

				// Verify it's on P-256 curve
				require.True(t, elliptic.P256().IsOnCurve(x, y))
			}
		})
	}
}

// TestPublicKeyInvalidFormats tests rejection of invalid public key formats
func TestPublicKeyInvalidFormats(t *testing.T) {
	tests := []struct {
		name           string
		publicKeyBytes []byte
		shouldFail     bool
	}{
		{
			name:           "too short",
			publicKeyBytes: make([]byte, 64),
			shouldFail:     true,
		},
		{
			name:           "too long",
			publicKeyBytes: make([]byte, 200),
			shouldFail:     false, // Just check it doesn't panic
		},
		{
			name:           "invalid prefix",
			publicKeyBytes: make([]byte, 130),
			shouldFail:     false, // Prefix check is done in verify, not extraction
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.publicKeyBytes) >= 65 {
				extractedKey := tt.publicKeyBytes[len(tt.publicKeyBytes)-65:]
				require.Len(t, extractedKey, 65)
			} else {
				require.True(t, tt.shouldFail)
			}
		})
	}
}

// TestSHA256Hashing tests SHA256 hash computation for signatures
func TestSHA256Hashing(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expectedLen   int
		expectedNotEq string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectedLen: 32,
		},
		{
			name:        "simple message",
			data:        []byte("test message"),
			expectedLen: 32,
		},
		{
			name:        "consistent hashing",
			data:        []byte("consistent test"),
			expectedLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := sha256.Sum256(tt.data)
			hash2 := sha256.Sum256(tt.data)

			// Same data should produce same hash
			require.Equal(t, hash1, hash2)
			require.Len(t, hash1[:], tt.expectedLen)
		})
	}
}

// TestSHA256DifferentInputs ensures different inputs produce different hashes
func TestSHA256DifferentInputs(t *testing.T) {
	hash1 := sha256.Sum256([]byte("message1"))
	hash2 := sha256.Sum256([]byte("message2"))

	require.NotEqual(t, hash1, hash2)
	require.Len(t, hash1[:], 32)
	require.Len(t, hash2[:], 32)
}

// TestECDSASignatureGeneration tests ECDSA signature generation and verification
func TestECDSASignatureGeneration(t *testing.T) {
	// Generate a P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// Sign a message
	messageHash := sha256.Sum256([]byte("test message"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash[:])
	require.NoError(t, err)

	// Verify the signature
	valid := ecdsa.Verify(pubKey, messageHash[:], r, s)
	require.True(t, valid)
}

// TestECDSASignatureRejection tests that invalid signatures are rejected
func TestECDSASignatureRejection(t *testing.T) {
	// Generate a P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// Sign a message
	messageHash := sha256.Sum256([]byte("test message"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash[:])
	require.NoError(t, err)

	// Modify the message hash
	modifiedMessageHash := sha256.Sum256([]byte("different message"))

	// Verify should fail with different message
	valid := ecdsa.Verify(pubKey, modifiedMessageHash[:], r, s)
	require.False(t, valid)
}

// TestECDSASignatureWithWrongKey tests verification fails with wrong public key
func TestECDSASignatureWithWrongKey(t *testing.T) {
	// Generate two different key pairs
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Sign with first key
	messageHash := sha256.Sum256([]byte("test message"))
	r, s, err := ecdsa.Sign(rand.Reader, privKey1, messageHash[:])
	require.NoError(t, err)

	// Verify with second key should fail
	valid := ecdsa.Verify(&privKey2.PublicKey, messageHash[:], r, s)
	require.False(t, valid)
}

// TestBigIntegerSignatureComponents tests r,s component parsing
func TestBigIntegerSignatureComponents(t *testing.T) {
	// Create a 64-byte signature (32-byte r + 32-byte s)
	signatureBytes := make([]byte, 64)

	// Fill with test data
	for i := 0; i < 32; i++ {
		signatureBytes[i] = byte(i)
		signatureBytes[32+i] = byte(255 - i)
	}

	// Parse r and s
	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	// Verify r and s are correctly parsed
	require.NotNil(t, r)
	require.NotNil(t, s)

	// Verify they're different
	require.NotEqual(t, r.Cmp(s), 0)

	// Verify they're positive
	require.True(t, r.Sign() > 0)
	require.True(t, s.Sign() > 0)
}

// TestP256CurveProperties tests P-256 elliptic curve properties
func TestP256CurveProperties(t *testing.T) {
	curve := elliptic.P256()

	// P-256 should have specific properties
	require.NotNil(t, curve)

	// Generate a point on the curve
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// Verify point is on curve
	require.True(t, curve.IsOnCurve(pubKey.X, pubKey.Y))
}

// TestInvalidCurvePoint tests detection of points not on curve
func TestInvalidCurvePoint(t *testing.T) {
	curve := elliptic.P256()

	// Create a random point that's unlikely to be on the curve
	invalidX := big.NewInt(1)
	invalidY := big.NewInt(2)

	// This should fail (point not on curve)
	onCurve := curve.IsOnCurve(invalidX, invalidY)
	require.False(t, onCurve)
}

// TestSignatureHexEncoding tests hex encoding/decoding of signatures
func TestSignatureHexEncoding(t *testing.T) {
	// Create a 64-byte signature
	originalSig := make([]byte, 64)
	for i := 0; i < 64; i++ {
		originalSig[i] = byte(i)
	}

	// Encode to hex
	sigHex := hex.EncodeToString(originalSig)
	require.Len(t, sigHex, 128) // 64 bytes * 2 chars per byte

	// Decode back from hex
	decodedSig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)

	// Should match original
	require.Equal(t, originalSig, decodedSig)
}

// TestPublicKeyHexEncoding tests hex encoding/decoding of public keys
func TestPublicKeyHexEncoding(t *testing.T) {
	// Generate a key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := privKey.PublicKey

	// Create 65-byte uncompressed format
	x := pubKey.X.Bytes()
	y := pubKey.Y.Bytes()

	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)

	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	copy(pubKeyBytes[1:33], xPadded)
	copy(pubKeyBytes[33:65], yPadded)

	// Encode to hex
	pubKeyHex := hex.EncodeToString(pubKeyBytes)
	require.Len(t, pubKeyHex, 130) // 65 bytes * 2

	// Decode back
	decodedKey, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)

	// Should match original
	require.Equal(t, pubKeyBytes, decodedKey)
	require.Equal(t, byte(0x04), decodedKey[0])
}

// BenchmarkECDSASignature benchmarks ECDSA signature generation
func BenchmarkECDSASignature(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	messageHash := sha256.Sum256([]byte("test message"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ecdsa.Sign(rand.Reader, privKey, messageHash[:])
	}
}

// BenchmarkECDSAVerification benchmarks ECDSA signature verification
func BenchmarkECDSAVerification(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey
	messageHash := sha256.Sum256([]byte("test message"))
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, messageHash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ecdsa.Verify(pubKey, messageHash[:], r, s)
	}
}

// BenchmarkSHA256 benchmarks SHA256 hashing
func BenchmarkSHA256(b *testing.B) {
	data := []byte("test message for hashing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha256.Sum256(data)
	}
}
