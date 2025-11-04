package manifest

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/near/borsh-go"
)

// DecodeManifestFromBase64 decodes a base64-encoded manifest envelope and returns the manifest and envelope bytes
func DecodeManifestFromBase64(manifestB64 string) (*Manifest, []byte, []byte, error) {
	// Decode base64
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Deserialize the envelope
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope: %w", err)
	}

	// Re-encode just the Manifest struct to get its raw bytes
	manifestBytes, err := borsh.Serialize(env.Manifest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}

	return &env.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestFromFile decodes a manifest envelope from a binary file
func DecodeManifestFromFile(filePath string) (*Manifest, []byte, []byte, error) {
	// Read file
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to deserialize as envelope first
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err != nil {
		// If envelope deserialization fails, try direct manifest deserialization
		var manifest Manifest
		if err := borsh.Deserialize(&manifest, envelopeBytes); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to deserialize as envelope or manifest: %w", err)
		}
		// If the file contains raw manifest bytes, use them directly for hashing
		return &manifest, envelopeBytes, envelopeBytes, nil
	}

	// If we successfully parsed as envelope, re-serialize just the manifest portion
	manifestBytes, err := borsh.Serialize(env.Manifest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}

	return &env.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeRawManifestFromFile decodes a raw manifest (not envelope) from a binary file
func DecodeRawManifestFromFile(filePath string) (*Manifest, []byte, error) {
	// Read file
	manifestBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize as manifest directly
	var manifest Manifest
	if err := borsh.Deserialize(&manifest, manifestBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize raw manifest: %w", err)
	}

	return &manifest, manifestBytes, nil
}

// DecodeRawManifestFromBase64 decodes a raw manifest (not envelope) from base64
func DecodeRawManifestFromBase64(manifestB64 string) (*Manifest, []byte, error) {
	// Decode base64
	manifestBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Deserialize as manifest directly
	var manifest Manifest
	if err := borsh.Deserialize(&manifest, manifestBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize raw manifest: %w", err)
	}

	return &manifest, manifestBytes, nil
}

// DecodeManifestEnvelopeFromFile decodes a manifest envelope from a binary file
func DecodeManifestEnvelopeFromFile(filePath string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	// Read file
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize as envelope (strict - no fallback)
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope: %w", err)
	}

	// Re-serialize just the manifest portion for hashing
	manifestBytes, err := borsh.Serialize(env.Manifest)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}

	return &env, &env.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestEnvelopeFromBase64 decodes a manifest envelope from base64
func DecodeManifestEnvelopeFromBase64(manifestB64 string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	// Decode base64
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Deserialize as envelope (strict - no fallback)
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope: %w", err)
	}

	// Re-serialize just the manifest portion for hashing
	manifestBytes, err := borsh.Serialize(env.Manifest)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}

	return &env, &env.Manifest, manifestBytes, envelopeBytes, nil
}
