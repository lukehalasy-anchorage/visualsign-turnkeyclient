package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/near/borsh-go"
)

// RestartPolicy enum matching the Rust definition
type RestartPolicy uint8

const (
	RestartPolicyNever RestartPolicy = iota
	RestartPolicyAlways
)

// MarshalJSON converts RestartPolicy to JSON string format matching qos_client
func (r RestartPolicy) MarshalJSON() ([]byte, error) {
	switch r {
	case RestartPolicyNever:
		return []byte(`"Never"`), nil
	case RestartPolicyAlways:
		return []byte(`"Always"`), nil
	default:
		return []byte(fmt.Sprintf(`"Unknown(%d)"`, uint8(r))), nil
	}
}

// String converts RestartPolicy to string format
func (r RestartPolicy) String() string {
	switch r {
	case RestartPolicyNever:
		return "Never"
	case RestartPolicyAlways:
		return "Always"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(r))
	}
}

type Hash256 [32]byte

type Namespace struct {
	Name      string `borsh:"name"`
	Nonce     uint32 `borsh:"nonce"`
	QuorumKey []byte `borsh:"quorum_key"`
}

type NitroConfig struct {
	Pcr0               []byte `borsh:"pcr0"`
	Pcr1               []byte `borsh:"pcr1"`
	Pcr2               []byte `borsh:"pcr2"`
	Pcr3               []byte `borsh:"pcr3"`
	AwsRootCertificate []byte `borsh:"aws_root_certificate"`
	QosCommit          string `borsh:"qos_commit"`
}

type PivotConfig struct {
	Hash    Hash256       `borsh:"hash"`    // fixed 32 bytes
	Restart RestartPolicy `borsh:"restart"` // enum as u8
	Args    []string      `borsh:"args"`
}

type QuorumMember struct {
	Alias  string `borsh:"alias"`
	PubKey []byte `borsh:"pub_key"`
}

type ManifestSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []QuorumMember `borsh:"members"`
}

type ShareSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []QuorumMember `borsh:"members"`
}

type MemberPubKey struct {
	PubKey []byte `borsh:"pub_key"`
}

type PatchSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []MemberPubKey `borsh:"members"`
}

type Manifest struct {
	Namespace   Namespace   `borsh:"namespace"`
	Pivot       PivotConfig `borsh:"pivot"`
	ManifestSet ManifestSet `borsh:"manifest_set"`
	ShareSet    ShareSet    `borsh:"share_set"`
	Enclave     NitroConfig `borsh:"enclave"`
	PatchSet    PatchSet    `borsh:"patch_set"`
}

// Approval structures for manifest envelope
type Approval struct {
	Signature []byte       `borsh:"signature"`
	Member    QuorumMember `borsh:"member"`
}

// ManifestEnvelope wraps the manifest with approval signatures
type ManifestEnvelope struct {
	Manifest             Manifest   `borsh:"manifest"`
	ManifestSetApprovals []Approval `borsh:"manifest_set_approvals"`
	ShareSetApprovals    []Approval `borsh:"share_set_approvals"`
}

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

// ComputeManifestHash computes SHA256 hash of manifest bytes
func ComputeManifestHash(manifestBytes []byte) string {
	sum := sha256.Sum256(manifestBytes)
	return hex.EncodeToString(sum[:])
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
