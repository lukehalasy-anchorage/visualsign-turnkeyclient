package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixed test key for deterministic tests
func getTestKey() *ecdsa.PrivateKey {
	// Fixed P-256 private key for testing (NOT FOR PRODUCTION USE)
	// Using NIST P-256 test vector
	d, _ := new(big.Int).SetString("c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357", 16)
	x, _ := new(big.Int).SetString("d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f", 16)
	y, _ := new(big.Int).SetString("9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f", 16)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}
}

func TestSignWithECDSA(t *testing.T) {
	key := getTestKey()
	data := []byte("test data")

	t.Run("successful signing", func(t *testing.T) {
		signature, err := SignWithECDSA(key, data)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		// Verify DER format
		var sig ECDSASignature
		_, err = asn1.Unmarshal(signature, &sig)
		assert.NoError(t, err)
	})

	t.Run("nil key panics", func(t *testing.T) {
		// SignWithECDSA doesn't handle nil key gracefully, it will panic
		require.Panics(t, func() {
			_, _ = SignWithECDSA(nil, data)
		})
	})

	t.Run("empty data succeeds", func(t *testing.T) {
		signature, err := SignWithECDSA(key, []byte{})
		assert.NoError(t, err)
		assert.NotEmpty(t, signature)
	})
}

func TestMarshalECDSASignatureDER(t *testing.T) {
	tests := []struct {
		name    string
		r, s    *big.Int
		wantErr bool
	}{
		{"valid values", big.NewInt(12345), big.NewInt(67890), false},
		{"zero values", big.NewInt(0), big.NewInt(0), false},
		{"large values", new(big.Int).SetBytes(make([]byte, 32)), new(big.Int).SetBytes(make([]byte, 32)), false},
		{"nil values", nil, nil, true}, // ASN.1 can't marshal nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derSig, err := MarshalECDSASignatureDER(tt.r, tt.s)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, derSig)

			// Verify unmarshal works
			var sig ECDSASignature
			_, err = asn1.Unmarshal(derSig, &sig)
			assert.NoError(t, err)
		})
	}
}

func TestVerifyECDSASignature(t *testing.T) {
	key := getTestKey()
	data := []byte("test data")

	// Create valid signature
	sig, err := SignWithECDSA(key, data)
	require.NoError(t, err)

	var ecdsaSig ECDSASignature
	_, err = asn1.Unmarshal(sig, &ecdsaSig)
	require.NoError(t, err)

	validSig := make([]byte, 64)
	ecdsaSig.R.FillBytes(validSig[:32])
	ecdsaSig.S.FillBytes(validSig[32:])

	t.Run("valid signature", func(t *testing.T) {
		assert.True(t, VerifyECDSASignature(&key.PublicKey, data, validSig))
	})

	t.Run("wrong data", func(t *testing.T) {
		assert.False(t, VerifyECDSASignature(&key.PublicKey, []byte("wrong"), validSig))
	})

	t.Run("wrong key", func(t *testing.T) {
		// Different fixed key
		otherKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(1),
				Y:     big.NewInt(2),
			},
			D: big.NewInt(3),
		}
		assert.False(t, VerifyECDSASignature(&otherKey.PublicKey, data, validSig))
	})

	t.Run("corrupted signature", func(t *testing.T) {
		badSig := make([]byte, 64)
		copy(badSig, validSig)
		badSig[0] ^= 0xFF
		assert.False(t, VerifyECDSASignature(&key.PublicKey, data, badSig))
	})

	t.Run("wrong signature length", func(t *testing.T) {
		assert.False(t, VerifyECDSASignature(&key.PublicKey, data, []byte("short")))
		assert.False(t, VerifyECDSASignature(&key.PublicKey, data, make([]byte, 65)))
	})

	t.Run("nil public key panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = VerifyECDSASignature(nil, data, validSig)
		})
	})
}

func TestSignAndVerifyIntegration(t *testing.T) {
	key := getTestKey()
	testData := [][]byte{
		{},
		[]byte("Hello, World!"),
		make([]byte, 1000),
	}

	for _, data := range testData {
		// Sign
		derSig, err := SignWithECDSA(key, data)
		require.NoError(t, err)

		// Convert to r||s format
		var sig ECDSASignature
		_, err = asn1.Unmarshal(derSig, &sig)
		require.NoError(t, err)

		rsSig := make([]byte, 64)
		sig.R.FillBytes(rsSig[:32])
		sig.S.FillBytes(rsSig[32:])

		// Verify
		assert.True(t, VerifyECDSASignature(&key.PublicKey, data, rsSig))
		assert.False(t, VerifyECDSASignature(&key.PublicKey, append(data, 'x'), rsSig))
	}
}

func TestVerifyWithHexEncodedSignature(t *testing.T) {
	// Test with hex-encoded signature like those from API responses
	key := getTestKey()
	data := []byte("test data")

	// Create signature and hex encode it
	sig, err := SignWithECDSA(key, data)
	require.NoError(t, err)

	var ecdsaSig ECDSASignature
	_, err = asn1.Unmarshal(sig, &ecdsaSig)
	require.NoError(t, err)

	// Create r||s format
	rsSig := make([]byte, 64)
	ecdsaSig.R.FillBytes(rsSig[:32])
	ecdsaSig.S.FillBytes(rsSig[32:])

	// Test hex encoding/decoding
	hexSig := hex.EncodeToString(rsSig)
	decodedSig, err := hex.DecodeString(hexSig)
	require.NoError(t, err)

	assert.True(t, VerifyECDSASignature(&key.PublicKey, data, decodedSig))
}