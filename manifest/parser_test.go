package manifest

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeManifestFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromBase64("not-valid-base64!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromBase64("")
		assert.Error(t, err)
	})

	t.Run("invalid borsh data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF})
		_, _, _, err := DecodeManifestFromBase64(invalidB64)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize manifest envelope")
	})
}

func TestDecodeManifestFromFile(t *testing.T) {
	testdataDir := "../testdata"

	t.Run("valid manifest.bin", func(t *testing.T) {
		manifestPath := filepath.Join(testdataDir, "manifest.bin")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			t.Skip("testdata/manifest.bin not found")
		}

		manifest, manifestBytes, envelopeBytes, err := DecodeManifestFromFile(manifestPath)
		assert.NoError(t, err)
		assert.NotNil(t, manifest)
		assert.NotEmpty(t, manifestBytes)
		assert.NotEmpty(t, envelopeBytes)
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromFile("does-not-exist.bin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func TestDecodeRawManifestFromFile(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromFile("does-not-exist.bin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})

	t.Run("invalid manifest data", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.bin")
		err := os.WriteFile(invalidPath, []byte{0xFF}, 0644)
		assert.NoError(t, err)

		_, _, err = DecodeRawManifestFromFile(invalidPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize raw manifest")
	})
}

func TestDecodeRawManifestFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromBase64("!@#$%")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid borsh", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF})
		_, _, err := DecodeRawManifestFromBase64(invalidB64)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize raw manifest")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromBase64("")
		assert.Error(t, err)
	})
}

func TestDecodeManifestEnvelopeFromFile(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromFile("does-not-exist.bin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.bin")
		err := os.WriteFile(invalidPath, []byte{0xFF, 0xFE}, 0644)
		assert.NoError(t, err)

		_, _, _, _, err = DecodeManifestEnvelopeFromFile(invalidPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize manifest envelope")
	})
}

func TestDecodeManifestEnvelopeFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("!!!invalid!!!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE})
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64(invalidB64)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize manifest envelope")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("")
		assert.Error(t, err)
	})
}

// Test with actual testdata file
func TestDecodeActualManifest(t *testing.T) {
	testdataDir := "../testdata"
	manifestPath := filepath.Join(testdataDir, "manifest.bin")

	// Skip if testdata doesn't exist
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Skip("testdata/manifest.bin not found")
	}

	// This should work with either raw manifest or envelope
	manifest, manifestBytes, _, err := DecodeManifestFromFile(manifestPath)
	assert.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.NotEmpty(t, manifestBytes)

	// Test hash computation
	hash := ComputeHash(manifestBytes)
	assert.Len(t, hash, 64) // SHA256 produces 64 hex chars
}