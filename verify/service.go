package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// APIClient interface for making API calls
type APIClient interface {
	CreateSignablePayload(ctx context.Context, req *api.CreateSignablePayloadRequest) (*api.SignablePayloadResponse, error)
}

// AttestationVerifier interface for verifying attestations
type AttestationVerifier interface {
	Validate(attestationDocument string) (*nitroverifier.ValidationResult, error)
}

// Service handles verification logic
type Service struct {
	apiClient          APIClient
	attestationVerifier AttestationVerifier
}

// NewService creates a new verification service
func NewService(apiClient APIClient, attestationVerifier AttestationVerifier) *Service {
	return &Service{
		apiClient:          apiClient,
		attestationVerifier: attestationVerifier,
	}
}

// Verify performs end-to-end verification of a transaction in AWS Nitro enclave
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResult, error) {
	result := &VerifyResult{
		PCRs: make(map[uint][]byte),
		ManifestReserialization: ManifestSerializationResult{},
	}

	// Step 1: Call API to get signable payload and attestations
	apiReq := &api.CreateSignablePayloadRequest{
		UnsignedPayload: req.UnsignedPayload,
		Chain:           "CHAIN_SOLANA",
	}

	response, err := s.apiClient.CreateSignablePayload(ctx, apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}

	// Save QoS manifest envelope to file if requested
	if req.SaveManifestPath != "" && response.QosManifestEnvelopeB64 != "" {
		envelopeBytes, err := base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode manifest envelope: %w", err)
		}
		if err := os.WriteFile(req.SaveManifestPath, envelopeBytes, 0644); err != nil {
			return nil, fmt.Errorf("failed to save manifest envelope: %w", err)
		}
	}

	// Extract attestations from API response
	appAttestation, bootAttestationDoc, err := s.extractAttestations(response)
	if err != nil {
		return nil, err
	}

	// Store attestation data in result
	result.PublicKeyHex = appAttestation.PublicKey
	result.MessageHex = appAttestation.Message
	result.SignatureHex = appAttestation.Signature
	result.SignablePayload = response.SignablePayload

	// Step 2: Verify attestation document using awsnitroverifier
	validationResult, err := s.attestationVerifier.Validate(bootAttestationDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation document: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("attestation document validation failed: %v", validationResult.Errors)
	}

	result.AttestationValid = true
	result.ModuleID = validationResult.Document.ModuleID
	result.PCRs = validationResult.Document.PCRs
	result.UserData = validationResult.Document.UserData
	result.AttestationDocument = validationResult.Document

	// Verify UserData against provided QoS manifest if given
	if req.QosManifestHex != "" {
		if err := s.verifyUserData(validationResult.Document.UserData, req.QosManifestHex); err != nil {
			return nil, fmt.Errorf("QoS manifest verification failed: %w", err)
		}
	}

	// Also check against pivot binary hash if provided
	if req.PivotBinaryHashHex != "" && req.QosManifestHex == "" {
		if err := s.verifyUserData(validationResult.Document.UserData, req.PivotBinaryHashHex); err != nil {
			return nil, fmt.Errorf("pivot binary hash verification failed: %w", err)
		}
	}

	// Step 3: Extract and verify public key
	publicKeyForVerification, err := s.extractPublicKey(appAttestation.PublicKey)
	if err != nil {
		return nil, err
	}
	result.PublicKey = publicKeyForVerification

	// Step 4: Verify signature
	messageBytes, err := hex.DecodeString(appAttestation.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hex: %w", err)
	}

	signatureBytes, err := hex.DecodeString(appAttestation.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature hex: %w", err)
	}

	// The signature is over the SHA256 hash of the message hash
	sha256Hash := sha256.Sum256(messageBytes)
	signatureValid := ecdsa.Verify(publicKeyForVerification, sha256Hash[:],
		new(big.Int).SetBytes(signatureBytes[:32]),
		new(big.Int).SetBytes(signatureBytes[32:]))

	if !signatureValid {
		return nil, errors.New("signature verification failed")
	}

	result.SignatureValid = true
	result.Valid = true

	// Step 5: Decode QoS Manifest if available
	// TODO: Manifest reserialization currently produces different hash than UserData.
	// This is expected behavior for now - the manifest format needs alignment with API response.
	// See: https://github.com/tkhq/turnkey-sdk-go/issues/XXX
	if response.QosManifestB64 != "" {
		err := s.processManifest(response, validationResult.Document.UserData, req.AllowManifestReserializationMismatch, result)
		if err != nil {
			if req.AllowManifestReserializationMismatch {
				// Store the error in manifest reserialization result for display
				result.ManifestReserialization.Error = err.Error()
				result.ManifestReserialization.ResserializationNeeded = true
			} else {
				return nil, err
			}
		}
	}

	// Add PCR[4] if present
	if pcr4, exists := result.PCRs[4]; exists && len(pcr4) > 0 {
		result.PCR4 = hex.EncodeToString(pcr4)
	}

	return result, nil
}

// extractAttestations extracts and parses attestations from API response
func (s *Service) extractAttestations(response *api.SignablePayloadResponse) (*AppAttestation, string, error) {
	attestationJSON, ok := response.Attestations[api.AppAttestationKey]
	if !ok {
		return nil, "", errors.New("no app attestation found in response")
	}

	var appAttestation AppAttestation
	if err := json.Unmarshal([]byte(attestationJSON), &appAttestation); err != nil {
		return nil, "", fmt.Errorf("failed to parse app attestation: %w", err)
	}

	bootAttestationDoc, ok := response.Attestations[api.BootAttestationKey]
	if !ok {
		return nil, "", errors.New("no boot attestation found in response")
	}

	return &appAttestation, bootAttestationDoc, nil
}

// extractPublicKey extracts the 65-byte public key from the 130-byte hex string
func (s *Service) extractPublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	if len(publicKeyBytes) != 130 {
		return nil, fmt.Errorf("expected 130-byte public key, got %d bytes", len(publicKeyBytes))
	}

	// Extract the latter 65 bytes (uncompressed public key format: 0x04 || X || Y)
	publicKeyForVerification := publicKeyBytes[65:]

	if publicKeyForVerification[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed public key format (0x04 prefix), got 0x%02x", publicKeyForVerification[0])
	}

	// P-256 curve
	curve := elliptic.P256()
	keyLen := 32
	x := new(big.Int).SetBytes(publicKeyForVerification[1 : 1+keyLen])
	y := new(big.Int).SetBytes(publicKeyForVerification[1+keyLen:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the public key is on the curve
	if !curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, errors.New("public key is not on the P256 curve")
	}

	return pubKey, nil
}

// verifyUserData verifies that UserData matches the provided hash
func (s *Service) verifyUserData(userData []byte, expectedHashHex string) error {
	expectedHashBytes, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return fmt.Errorf("invalid hash hex provided: %w", err)
	}

	if hex.EncodeToString(expectedHashBytes) != hex.EncodeToString(userData) {
		return fmt.Errorf("hash mismatch: expected %s, got %s",
			expectedHashHex, hex.EncodeToString(userData))
	}

	return nil
}

// processManifest decodes and processes the QoS manifest
func (s *Service) processManifest(response *api.SignablePayloadResponse, userData []byte,
	allowMismatch bool, result *VerifyResult) error {

	decodedManifest, manifestBytes, _, err := manifest.DecodeManifestFromBase64(response.QosManifestB64)
	if err != nil {
		return fmt.Errorf("failed to decode QoS manifest: %w", err)
	}

	result.Manifest = decodedManifest

	// Compute different hashes
	rawManifestBytes, _ := base64.StdEncoding.DecodeString(response.QosManifestB64)
	rawManifestHash := manifest.ComputeHash(rawManifestBytes)
	reserializedManifestHash := manifest.ComputeHash(manifestBytes)

	serializationResult := ManifestSerializationResult{
		RawManifestHash:        rawManifestHash,
		ReserializedManifestHash: reserializedManifestHash,
	}

	// If we have the envelope version, compute its hash too
	if response.QosManifestEnvelopeB64 != "" {
		envelopeBytes, err := base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
		if err == nil {
			serializationResult.EnvelopeHash = manifest.ComputeHash(envelopeBytes)
		}
	}

	// Compare against UserData
	if len(userData) > 0 {
		userDataHex := hex.EncodeToString(userData)
		serializationResult.UserDataHash = userDataHex

		if rawManifestHash == userDataHex {
			serializationResult.Matches = true
		} else {
			serializationResult.ResserializationNeeded = true
			if !allowMismatch {
				serializationResult.Error = fmt.Sprintf(
					"manifest reserialization mismatch: boot-time %s != api %s",
					userDataHex, rawManifestHash)
				return errors.New(serializationResult.Error)
			}
		}

		// Store result hashes for output
		result.QosManifestHash = userDataHex
		result.PivotBinaryHash = userDataHex
	}

	result.ManifestReserialization = serializationResult
	return nil
}

// AppAttestation represents the parsed app attestation structure
type AppAttestation struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}
