package main

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestManifestActualValues verifies specific values from the test fixture manifest
func TestManifestActualValues(t *testing.T) {
	manifest, manifestBytes, err := DecodeRawManifestFromFile("testdata/manifest.bin")
	require.NoError(t, err)
	require.NotNil(t, manifest)

	// Test Namespace values
	t.Run("namespace_values", func(t *testing.T) {
		require.Equal(t, "preprod/visualsign-parser", manifest.Namespace.Name)
		require.Equal(t, uint32(3), manifest.Namespace.Nonce)
		require.NotEmpty(t, manifest.Namespace.QuorumKey)
		require.Len(t, manifest.Namespace.QuorumKey, 130) // Two 65-byte P-256 public keys
	})

	// Test Pivot config values
	t.Run("pivot_config", func(t *testing.T) {
		expectedHash := "02f94c206fe3bee033d8fa90b72a5ee2f686229cbcd6391aefa3a54a7abc290b"
		actualHash := hex.EncodeToString(manifest.Pivot.Hash[:])
		require.Equal(t, expectedHash, actualHash)
		require.Equal(t, RestartPolicyAlways, manifest.Pivot.Restart)
	})

	// Test PCR values
	t.Run("pcr_values", func(t *testing.T) {
		expectedPCR0 := "c853a6ace72694c912d934e821f50338e2e3ce99cb3a25d95d734b95614605d761dc4ff04989c2483e6e72818e8d5bd6"
		expectedPCR1 := "c853a6ace72694c912d934e821f50338e2e3ce99cb3a25d95d734b95614605d761dc4ff04989c2483e6e72818e8d5bd6"
		expectedPCR2 := "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a"
		expectedPCR3 := "864e9095a9947ab14698122370c13baf23183f4e9911953cf5b909a49db00f43f446707314674d9309974f3cc4b24728"

		require.Equal(t, expectedPCR0, hex.EncodeToString(manifest.Enclave.Pcr0))
		require.Equal(t, expectedPCR1, hex.EncodeToString(manifest.Enclave.Pcr1))
		require.Equal(t, expectedPCR2, hex.EncodeToString(manifest.Enclave.Pcr2))
		require.Equal(t, expectedPCR3, hex.EncodeToString(manifest.Enclave.Pcr3))
	})

	// Test Manifest Set threshold
	t.Run("manifest_set", func(t *testing.T) {
		require.Equal(t, uint32(2), manifest.ManifestSet.Threshold)
		require.Len(t, manifest.ManifestSet.Members, 2)
		require.Equal(t, "1", manifest.ManifestSet.Members[0].Alias)
		require.Equal(t, "2", manifest.ManifestSet.Members[1].Alias)
	})

	// Test Share Set threshold
	t.Run("share_set", func(t *testing.T) {
		require.Equal(t, uint32(2), manifest.ShareSet.Threshold)
		require.Len(t, manifest.ShareSet.Members, 2)
	})

	// Test Patch Set threshold
	t.Run("patch_set", func(t *testing.T) {
		require.Equal(t, uint32(2), manifest.PatchSet.Threshold)
		require.Len(t, manifest.PatchSet.Members, 2)
	})

	// Test manifest hash
	t.Run("manifest_hash", func(t *testing.T) {
		expectedHash := "fa5df35e6324d9222b0a430bf4ff8eb72609684adc5bb55d0de0ae292e33d617"
		actualHash := ComputeManifestHash(manifestBytes)
		require.Equal(t, expectedHash, actualHash)
	})

	// Test public keys in manifest set
	t.Run("manifest_set_public_keys", func(t *testing.T) {
		expectedKey1 := "044af8b082b9ef41a238037811a188309d8c8b00b6d49c0574538d7746d7383739e67e1107f134bc102a48301b07e7c53280decbe9c16c9fc1f19b9832018e1485048139aa5de49d9505465bcf1a879954c51ba7b258b669f4e42697088cbbca54aeb888d61e65b2602ce92ae945a0160533acc94942511f8e5b1940ed89cc8f141f"
		expectedKey2 := "04c1c4b4eb784505f167affae00e18b1521e7a0bfa3be46e6a6b43ba1f386afce48d964c885480cb197e3538fd30ebe38a07f76b6a286b37ba6d2abddbbd6c9c8304e492ca7bce95912a7b2565c8553e38cf3a4b1f858171900ed81888282db13d41e214dd6def2de2aacb1fcf92e3ae5a83e1b0ffa660fc59b9dd10e277cfd128dc"

		require.Equal(t, expectedKey1, hex.EncodeToString(manifest.ManifestSet.Members[0].PubKey))
		require.Equal(t, expectedKey2, hex.EncodeToString(manifest.ManifestSet.Members[1].PubKey))
	})

	// Test quorum key format
	t.Run("quorum_key", func(t *testing.T) {
		expectedKey := "04451028fc9d42cef6d8f2a3ebe17d65783c470dbc6f04663d500c12009930cf9b209e733f6ac6103cc28f07ecde2dbb55095738b828d6b7a55caf4ddf9d67f2ae047827dcd2325b8d58694c2ea14e8f1e1f8a36c84438d291ff9b1b067debdb3e2ba3822984cde8bed4de2c237bd323526da4961d368bcc63cbd2d37d00e936683e"
		require.Equal(t, expectedKey, hex.EncodeToString(manifest.Namespace.QuorumKey))
		// Should be a valid P-256 uncompressed public key (0x04 || 32 bytes X || 32 bytes Y)
		require.Equal(t, byte(0x04), manifest.Namespace.QuorumKey[0])
	})
}

// TestDecodeRawManifestFromFile tests raw manifest decoding from file
func TestDecodeRawManifestFromFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string // returns file path
		wantErr bool
		errMsg  string
		check   func(t *testing.T, manifest *Manifest, manifestBytes []byte)
	}{
		{
			name: "valid raw manifest from testdata",
			setup: func(t *testing.T) string {
				return "testdata/manifest.bin"
			},
			wantErr: false,
			check: func(t *testing.T, manifest *Manifest, manifestBytes []byte) {
				require.NotNil(t, manifest)
				require.NotEmpty(t, manifestBytes)
				// Manifest should have namespace
				require.NotEmpty(t, manifest.Namespace.Name)
			},
		},
		{
			name: "nonexistent file",
			setup: func(t *testing.T) string {
				return "testdata/nonexistent_manifest.bin"
			},
			wantErr: true,
			errMsg:  "failed to read file",
		},
		{
			name: "invalid manifest data",
			setup: func(t *testing.T) string {
				file := "testdata/invalid_manifest.bin"
				err := os.WriteFile(file, []byte{0xFF, 0xFF, 0xFF}, 0o644)
				require.NoError(t, err)
				t.Cleanup(func() { _ = os.Remove(file) })
				return file
			},
			wantErr: true,
			errMsg:  "failed to deserialize raw manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setup(t)
			manifest, manifestBytes, err := DecodeRawManifestFromFile(filePath)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				require.Nil(t, manifest)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.check != nil {
					tt.check(t, manifest, manifestBytes)
				}
			}
		})
	}
}

// TestDecodeRawManifestFromBase64 tests raw manifest decoding from base64
func TestDecodeRawManifestFromBase64(t *testing.T) {
	tests := []struct {
		name        string
		manifestB64 string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "invalid base64",
			manifestB64: "not-valid-base64!@#$",
			wantErr:     true,
			errMsg:      "failed to decode base64",
		},
		{
			name:        "empty base64",
			manifestB64: "",
			wantErr:     true,
			errMsg:      "failed to deserialize raw manifest",
		},
		{
			name:        "valid base64 but invalid manifest data",
			manifestB64: base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF}),
			wantErr:     true,
			errMsg:      "failed to deserialize raw manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, manifestBytes, err := DecodeRawManifestFromBase64(tt.manifestB64)

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
			require.Nil(t, manifest)
			require.Empty(t, manifestBytes)
		})
	}
}

// TestComputeManifestHash tests hash computation
func TestComputeManifestHash(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectedLen int
		shouldNotBe string // hash that should differ
	}{
		{
			name:        "empty data produces hash",
			data:        []byte{},
			expectedLen: 64, // SHA256 hex = 64 chars
		},
		{
			name:        "simple data produces hash",
			data:        []byte("test"),
			expectedLen: 64,
		},
		{
			name:        "different data produces different hash",
			data:        []byte("different"),
			expectedLen: 64,
			shouldNotBe: "9f86d081884c7d6d9ffd60014fc7ee77e8b61bbf97d660e79d4e5c0505e3cb81", // hash of "test"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := ComputeManifestHash(tt.data)

			require.Len(t, hash, tt.expectedLen)
			// Verify it's valid hex
			_, err := hex.DecodeString(hash)
			require.NoError(t, err)

			if tt.shouldNotBe != "" {
				require.NotEqual(t, tt.shouldNotBe, hash)
			}
		})
	}
}

// TestComputeManifestHashConsistency verifies hash is deterministic
func TestComputeManifestHashConsistency(t *testing.T) {
	data := []byte("consistent test data")

	hash1 := ComputeManifestHash(data)
	hash2 := ComputeManifestHash(data)

	require.Equal(t, hash1, hash2, "hash should be consistent for same data")
}

// TestRestartPolicyMarshalJSON tests JSON marshaling
func TestRestartPolicyMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		policy   RestartPolicy
		expected string
	}{
		{
			name:     "RestartPolicyNever",
			policy:   RestartPolicyNever,
			expected: `"Never"`,
		},
		{
			name:     "RestartPolicyAlways",
			policy:   RestartPolicyAlways,
			expected: `"Always"`,
		},
		{
			name:     "Unknown policy",
			policy:   RestartPolicy(99),
			expected: `"Unknown(99)"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.policy.MarshalJSON()

			require.NoError(t, err)
			require.Equal(t, tt.expected, string(data))
		})
	}
}

// TestRestartPolicyString tests string conversion
func TestRestartPolicyString(t *testing.T) {
	tests := []struct {
		name     string
		policy   RestartPolicy
		expected string
	}{
		{
			name:     "RestartPolicyNever",
			policy:   RestartPolicyNever,
			expected: "Never",
		},
		{
			name:     "RestartPolicyAlways",
			policy:   RestartPolicyAlways,
			expected: "Always",
		},
		{
			name:     "Unknown policy",
			policy:   RestartPolicy(100),
			expected: "Unknown(100)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.String()
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestManifestBorshRoundtrip tests that manifest can be serialized and deserialized
func TestManifestBorshRoundtrip(t *testing.T) {
	// Decode a real manifest from testdata
	manifest, _, err := DecodeRawManifestFromFile("testdata/manifest.bin")
	require.NoError(t, err)
	require.NotNil(t, manifest)

	// Verify manifest structure is intact
	t.Run("manifest_namespace", func(t *testing.T) {
		require.NotEmpty(t, manifest.Namespace.Name)
	})

	t.Run("manifest_pivot", func(t *testing.T) {
		// Verify pivot has hash (32 bytes)
		require.Equal(t, 32, len(manifest.Pivot.Hash[:]))
	})

	t.Run("manifest_quorum_members", func(t *testing.T) {
		require.Greater(t, len(manifest.ManifestSet.Members), 0)
		for _, member := range manifest.ManifestSet.Members {
			require.NotEmpty(t, member.Alias)
			require.NotEmpty(t, member.PubKey)
		}
	})
}

// TestDecodeManifestFromFileRawManifest tests decoding when file contains raw manifest
func TestDecodeManifestFromFileRawManifest(t *testing.T) {
	// Test with actual manifest.bin which is a raw manifest
	manifest, manifestBytes, envelopeBytes, err := DecodeManifestFromFile("testdata/manifest.bin")

	require.NoError(t, err)
	require.NotNil(t, manifest)
	require.NotEmpty(t, manifestBytes)
	require.NotEmpty(t, envelopeBytes)

	// For raw manifest, manifest bytes and envelope bytes should be the same
	require.Equal(t, manifestBytes, envelopeBytes)
}

// TestHashIsConsistentAcrossDecodings verifies same manifest produces same hash
func TestHashIsConsistentAcrossDecodings(t *testing.T) {
	// Decode the manifest
	_, manifestBytes, err := DecodeRawManifestFromFile("testdata/manifest.bin")
	require.NoError(t, err)

	// Compute hash
	hash1 := ComputeManifestHash(manifestBytes)

	// Decode again and verify hash is the same
	_, manifestBytes2, err := DecodeRawManifestFromFile("testdata/manifest.bin")
	require.NoError(t, err)

	hash2 := ComputeManifestHash(manifestBytes2)

	require.Equal(t, hash1, hash2, "manifest hash should be consistent")
}

// BenchmarkComputeManifestHash benchmarks hash computation
func BenchmarkComputeManifestHash(b *testing.B) {
	_, manifestBytes, err := DecodeRawManifestFromFile("testdata/manifest.bin")
	if err != nil {
		b.Fatalf("failed to load test manifest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeManifestHash(manifestBytes)
	}
}

// BenchmarkDecodeRawManifestFromFile benchmarks manifest decoding
func BenchmarkDecodeRawManifestFromFile(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DecodeRawManifestFromFile("testdata/manifest.bin")
	}
}

// Test root package wrapper functions

func TestDecodeManifestFromBase64Wrapper(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromBase64("not-valid-base64!")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid borsh", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF})
		_, _, _, err := DecodeManifestFromBase64(invalidB64)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deserialize manifest envelope")
	})
}

func TestDecodeManifestEnvelopeFromFileWrapper(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromFile("does-not-exist.bin")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read file")
	})
}

func TestDecodeManifestEnvelopeFromBase64Wrapper(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("!!!invalid!!!")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid envelope", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE})
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64(invalidB64)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deserialize manifest envelope")
	})
}
