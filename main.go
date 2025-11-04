package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
)

// TurnkeyAPIKey represents the API key configuration
type TurnkeyAPIKey struct {
	PublicKey      string `json:"publicKey"`
	PrivateKey     *ecdsa.PrivateKey
	OrganizationID string `json:"organizationId"`
}

// APIKeyProvider interface for providing Turnkey API keys
type APIKeyProvider interface {
	GetAPIKey(ctx context.Context) (*TurnkeyAPIKey, error)
}

// TurnkeyStamp represents the stamp structure for API key authentication
type TurnkeyStamp struct {
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Scheme    string `json:"scheme"`
}

// TurnkeyVisualSignRequest represents the request to Turnkey's visualsign API
type TurnkeyVisualSignRequest struct {
	Request struct {
		UnsignedPayload string `json:"unsigned_payload"`
		Chain           string `json:"chain"`
	} `json:"request"`
	OrganizationID string `json:"organization_id"`
}

// TurnkeyVisualSignResponse represents the response from Turnkey's visualsign API
type TurnkeyVisualSignResponse struct {
	BootProof *TurnkeyBootProof `json:"bootProof,omitempty"`
	Response  struct {
		ParsedTransaction struct {
			Payload struct {
				SignablePayload string `json:"signablePayload"`
			} `json:"payload"`
			Signature *TurnkeySignature `json:"signature,omitempty"`
		} `json:"parsedTransaction"`
	} `json:"response"`
	Error string `json:"error,omitempty"`
}

// TurnkeyBootProof represents the boot proof object in the response
type TurnkeyBootProof struct {
	QosManifestB64         string `json:"qosManifestB64"`
	QosManifestEnvelopeB64 string `json:"qosManifestEnvelopeB64"`
}

// TurnkeySignature represents the signature object in the response
type TurnkeySignature struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}

// AttestationQueryRequest represents the request to get attestation document
type AttestationQueryRequest struct {
	OrganizationID string `json:"organizationId"`
	EnclaveType    string `json:"enclaveType"`
	PublicKey      string `json:"publicKey"`
}

// AttestationQueryResponse represents the response from the attestation query
type AttestationQueryResponse struct {
	AttestationDocument string `json:"attestationDocument"`
}

// AttestationType represents different types of attestations
type AttestationType string

const (
	BootAttestationKey AttestationType = "boot_attestation"
	AppAttestationKey  AttestationType = "app_attestation"
)

// SignablePayloadResponse represents the response from CreateSignablePayload
type SignablePayloadResponse struct {
	SignablePayload                  string                     `json:"signablePayload"`
	TurnkeySerializedSignablePayload string                     `json:"turnkeySerializedSignablePayload"`
	Attestations                     map[AttestationType]string `json:"attestations"`
	QosManifestB64                   string                     `json:"qosManifestB64,omitempty"`
	QosManifestEnvelopeB64           string                     `json:"qosManifestEnvelopeB64,omitempty"`
}

// TurnkeyClient implements the Turnkey API client
type TurnkeyClient struct {
	HostURI        string
	HTTPClient     *http.Client
	APIKey         *TurnkeyAPIKey
	APIKeyProvider APIKeyProvider
}

// NewTurnkeyClient creates a new TurnkeyClient with API key authentication
func NewTurnkeyClient(hostURI string, httpClient *http.Client, organizationID string, provider APIKeyProvider) (*TurnkeyClient, error) {
	apiKey, err := provider.GetAPIKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load API key: %w", err)
	}

	apiKey.OrganizationID = organizationID

	return &TurnkeyClient{
		HostURI:        hostURI,
		HTTPClient:     httpClient,
		APIKey:         apiKey,
		APIKeyProvider: provider,
	}, nil
}

// CreateSignablePayload calls Turnkey's visualsign API to create a signable payload
func (c *TurnkeyClient) CreateSignablePayload(ctx context.Context, unsignedPayload string) (SignablePayloadResponse, error) {
	// Create the visualsign request
	reqBody := TurnkeyVisualSignRequest{
		Request: struct {
			UnsignedPayload string `json:"unsigned_payload"`
			Chain           string `json:"chain"`
		}{
			UnsignedPayload: unsignedPayload,
			Chain:           "CHAIN_SOLANA",
		},
		OrganizationID: c.APIKey.OrganizationID,
	}

	// Marshal request to JSON
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return SignablePayloadResponse{}, fmt.Errorf("failed to marshal visualsign request: %w", err)
	}

	// Create and stamp the request
	url := fmt.Sprintf("%s/visualsign/api/v1/parse", c.HostURI)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return SignablePayloadResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")

	// Generate and add stamp
	stamp, err := c.generateStamp(reqJSON)
	if err != nil {
		return SignablePayloadResponse{}, fmt.Errorf("failed to generate stamp: %w", err)
	}
	req.Header.Set("X-Stamp", stamp)

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return SignablePayloadResponse{}, fmt.Errorf("failed to send request to Turnkey visualsign API: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return SignablePayloadResponse{}, fmt.Errorf("turnkey API returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var turnkeyResp TurnkeyVisualSignResponse
	bodyBytes, _ := io.ReadAll(resp.Body)

	err = json.Unmarshal(bodyBytes, &turnkeyResp)
	if err != nil {
		return SignablePayloadResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for error in response
	if turnkeyResp.Error != "" {
		return SignablePayloadResponse{}, fmt.Errorf("turnkey API returned error: %s", turnkeyResp.Error)
	}

	// Extract the signable payload string - keep as string, don't decode
	signablePayloadString := turnkeyResp.Response.ParsedTransaction.Payload.SignablePayload

	// Process attestations if available
	attestations := make(map[AttestationType]string)

	if turnkeyResp.Response.ParsedTransaction.Signature != nil {
		// Set app attestation from the signature response
		appAttestationData := map[string]interface{}{
			"message":   turnkeyResp.Response.ParsedTransaction.Signature.Message,
			"publicKey": turnkeyResp.Response.ParsedTransaction.Signature.PublicKey,
			"scheme":    turnkeyResp.Response.ParsedTransaction.Signature.Scheme,
			"signature": turnkeyResp.Response.ParsedTransaction.Signature.Signature,
		}
		appAttestationJSON, err := json.Marshal(appAttestationData)
		if err != nil {
			return SignablePayloadResponse{}, fmt.Errorf("failed to marshal app attestation: %w", err)
		}
		attestations[AppAttestationKey] = string(appAttestationJSON)

		// Get boot attestation using the public key
		bootAttestation, err := c.getBootAttestation(ctx, turnkeyResp.Response.ParsedTransaction.Signature.PublicKey)
		if err != nil {
			// Don't fail the entire request if boot attestation fails
			fmt.Printf("Warning: failed to get boot attestation: %v\n", err)
		} else if bootAttestation != "" {
			attestations[BootAttestationKey] = bootAttestation
		}
	} else {
		// No signature in response - attestations not available from this endpoint
		fmt.Printf("INFO: No signature in response, attestations not available\n")
	}

	// Extract qosManifestB64 and qosManifestEnvelopeB64 from bootProof if available
	var qosManifestB64, qosManifestEnvelopeB64 string
	if turnkeyResp.BootProof != nil {
		qosManifestB64 = turnkeyResp.BootProof.QosManifestB64
		qosManifestEnvelopeB64 = turnkeyResp.BootProof.QosManifestEnvelopeB64
	}

	return SignablePayloadResponse{
		SignablePayload:                  signablePayloadString,
		TurnkeySerializedSignablePayload: signablePayloadString,
		Attestations:                     attestations,
		QosManifestB64:                   qosManifestB64,
		QosManifestEnvelopeB64:           qosManifestEnvelopeB64,
	}, nil
}

// getBootAttestation retrieves the boot attestation document for a given public key
func (c *TurnkeyClient) getBootAttestation(ctx context.Context, publicKey string) (string, error) {
	// Create the attestation query request
	reqBody := AttestationQueryRequest{
		OrganizationID: c.APIKey.OrganizationID,
		EnclaveType:    "signer",
		PublicKey:      publicKey,
	}

	// Marshal request to JSON
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal attestation request: %w", err)
	}

	// Create and stamp the request
	url := fmt.Sprintf("%s/public/v1/query/get_attestation", c.HostURI)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")

	// Generate and add stamp
	stamp, err := c.generateStamp(reqJSON)
	if err != nil {
		return "", fmt.Errorf("failed to generate stamp: %w", err)
	}
	req.Header.Set("X-Stamp", stamp)

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request to attestation API: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("attestation API returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var attestationResp AttestationQueryResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&attestationResp); err != nil {
		return "", fmt.Errorf("failed to decode attestation response: %w", err)
	}

	return attestationResp.AttestationDocument, nil
}

// GetBootAttestationForPublicKey retrieves boot attestation for a specific public key
func (c *TurnkeyClient) GetBootAttestationForPublicKey(ctx context.Context, publicKey string) (string, error) {
	return c.getBootAttestation(ctx, publicKey)
}

// generateStamp creates an API key stamp for the request
func (c *TurnkeyClient) generateStamp(requestBody []byte) (string, error) {
	// Sign the request body with the private key
	signature, err := c.signWithAPIKey(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to sign request body: %w", err)
	}

	// Create the stamp structure
	stamp := TurnkeyStamp{
		PublicKey: c.APIKey.PublicKey,
		Signature: hex.EncodeToString(signature),
		Scheme:    "SIGNATURE_SCHEME_TK_API_P256",
	}

	// Marshal to JSON
	stampJSON, err := json.Marshal(stamp)
	if err != nil {
		return "", fmt.Errorf("failed to marshal stamp: %w", err)
	}

	// Base64URL encode the stamp
	return base64.RawURLEncoding.EncodeToString(stampJSON), nil
}

// signWithAPIKey signs the data with the API key private key
func (c *TurnkeyClient) signWithAPIKey(data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign the hash using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, c.APIKey.PrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	// Convert to DER format using standard library
	return asn1MarshalECDSASignature(r, s)
}

// ECDSASignature represents an ECDSA signature for ASN.1 encoding
type ECDSASignature struct {
	R, S *big.Int
}

// asn1MarshalECDSASignature converts ECDSA signature components to DER format using standard library
func asn1MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	signature := ECDSASignature{R: r, S: s}
	return asn1.Marshal(signature)
}

// FileAPIKeyProvider implements APIKeyProvider by reading from files
type FileAPIKeyProvider struct {
	KeyName string
}

// GetAPIKey loads the API key from files
func (f *FileAPIKeyProvider) GetAPIKey(ctx context.Context) (*TurnkeyAPIKey, error) {
	return loadAPIKeyFromFile(f.KeyName)
}

// loadAPIKeyFromFile loads the API key from the Turnkey CLI configuration
func loadAPIKeyFromFile(keyName string) (*TurnkeyAPIKey, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".config", "turnkey", "keys")

	// Load public key
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	publicKeyHex := strings.TrimSpace(string(publicKeyBytes))

	// Load private key
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Parse private key format: "hexkey:curve"
	privateKeyContent := strings.TrimSpace(string(privateKeyBytes))
	parts := strings.Split(privateKeyContent, ":")
	if len(parts) != 2 {
		return nil, errors.New("invalid private key format, expected 'hexkey:curve'")
	}

	privateKeyHex := parts[0]
	curve := parts[1]

	if curve != "p256" {
		return nil, fmt.Errorf("unsupported curve: %s, only p256 is supported", curve)
	}

	// Decode hex private key
	privateKeyBytes, err = hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	// Create ECDSA private key
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: new(big.Int).SetBytes(privateKeyBytes),
	}

	// Calculate public key point
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKeyBytes)

	return &TurnkeyAPIKey{
		PublicKey:  publicKeyHex,
		PrivateKey: privateKey,
	}, nil
}

// createClient creates a new TurnkeyClient with the given parameters
func createClient(hostURI, organizationID, keyName string) (*TurnkeyClient, error) {
	httpClient := &http.Client{}
	provider := &FileAPIKeyProvider{KeyName: keyName}
	return NewTurnkeyClient(hostURI, httpClient, organizationID, provider)
}

func main() {
	cmd := &cli.Command{
		Name:  "turnkey-client",
		Usage: "Turnkey Visualsign Client",
		Commands: []*cli.Command{
			{
				Name:  "parse",
				Usage: "Parse transaction and extract attestations",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "host",
						Usage:    "Turnkey API host URL",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "organization-id",
						Usage:    "Organization ID",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "key-name",
						Usage:    "API key name",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "unsigned-payload",
						Usage:    "Unsigned transaction payload (base64)",
						Required: true,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					runParse(
						cmd.String("host"),
						cmd.String("organization-id"),
						cmd.String("key-name"),
						cmd.String("unsigned-payload"),
					)
					return nil
				},
			},
			{
				Name:  "verify",
				Usage: "Verify transaction was executed in AWS Nitro enclave (end-to-end)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "host",
						Usage:    "Turnkey API host URL",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "organization-id",
						Usage:    "Organization ID",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "key-name",
						Usage:    "API key name",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "unsigned-payload",
						Usage:    "Unsigned transaction payload (base64)",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "qos-manifest-hex",
						Usage: "Expected QoS manifest hash (hex format) to verify against UserData",
					},
					&cli.StringFlag{
						Name:  "pivot-binary-hash-hex",
						Usage: "Alternative name for QoS manifest hash (both verify against UserData)",
					},
					&cli.StringFlag{
						Name:  "save-qos-manifest",
						Usage: "Save the QoS manifest envelope to a binary file at the specified path",
					},
					&cli.BoolFlag{
						Name:  "allow-manifest-reserialization-mismatch",
						Usage: "Continue verification even if manifest reserialization produces different hash than UserData (show warning instead of aborting)",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					runVerify(
						c.String("host"),
						c.String("organization-id"),
						c.String("key-name"),
						c.String("unsigned-payload"),
						c.String("qos-manifest-hex"),
						c.String("pivot-binary-hash-hex"),
						c.String("save-qos-manifest"),
						c.Bool("allow-manifest-reserialization-mismatch"),
					)
					return nil
				},
			},
			{
				Name:  "decode-manifest",
				Usage: "Decode and display a raw QoS manifest (manifest-only, no approvals)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "file",
						Usage: "Path to raw manifest binary file",
					},
					&cli.StringFlag{
						Name:  "base64",
						Usage: "Base64-encoded raw manifest",
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "Output in JSON format",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					file := c.String("file")
					b64 := c.String("base64")

					if file == "" && b64 == "" {
						return fmt.Errorf("either --file or --base64 must be provided")
					}
					if file != "" && b64 != "" {
						return fmt.Errorf("only one of --file or --base64 should be provided")
					}

					runDecodeManifest(file, b64, c.Bool("json"))
					return nil
				},
			},
			{
				Name:  "decode-manifest-envelope",
				Usage: "Decode and display a QoS manifest envelope with approvals",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "file",
						Usage: "Path to manifest envelope binary file",
					},
					&cli.StringFlag{
						Name:  "base64",
						Usage: "Base64-encoded manifest envelope",
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "Output in JSON format",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					file := c.String("file")
					b64 := c.String("base64")

					if file == "" && b64 == "" {
						return fmt.Errorf("either --file or --base64 must be provided")
					}
					if file != "" && b64 != "" {
						return fmt.Errorf("only one of --file or --base64 should be provided")
					}

					runDecodeManifestEnvelope(file, b64, c.Bool("json"))
					return nil
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

// runParse parses transaction and extracts attestations (original functionality)
func runParse(hostURI, organizationID, keyName, unsignedPayload string) {
	// Create Turnkey client
	client, err := createClient(hostURI, organizationID, keyName)
	if err != nil {
		log.Fatalf("Failed to create Turnkey client: %v", err)
	}

	// Create signable payload
	response, err := client.CreateSignablePayload(context.Background(), unsignedPayload)
	if err != nil {
		log.Fatalf("Failed to create signable payload: %v", err)
	}

	// Output the result as JSON
	output, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal response: %v", err)
	}

	fmt.Println(string(output))

	// Provide summary information to stderr
	fmt.Fprintf(os.Stderr, "\n=== TURNKEY CLIENT SUMMARY ===\n")
	fmt.Fprintf(os.Stderr, "✓ Transaction parsed successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Signable payload extracted (%d characters)\n", len(response.SignablePayload))
	if len(response.Attestations) > 0 {
		fmt.Fprintf(os.Stderr, "✓ Attestations extracted:\n")
		for attestationType := range response.Attestations {
			fmt.Fprintf(os.Stderr, "  - %s\n", attestationType)
		}
	} else {
		fmt.Fprintf(os.Stderr, "⚠ No attestations available\n")
	}
}

// runDecodeManifest decodes and displays a raw QoS manifest (manifest-only, no envelope)
func runDecodeManifest(filePath string, base64String string, jsonOutput bool) {
	var manifest *Manifest
	var manifestBytes []byte
	var err error

	if filePath != "" {
		// Decode from file - force manifest-only parsing
		manifest, manifestBytes, err = DecodeRawManifestFromFile(filePath)
		if err != nil {
			log.Fatalf("Failed to decode raw manifest from file: %v", err)
		}
	} else {
		// Decode from base64 - force manifest-only parsing
		manifest, manifestBytes, err = DecodeRawManifestFromBase64(base64String)
		if err != nil {
			log.Fatalf("Failed to decode raw manifest from base64: %v", err)
		}
	}

	// For raw manifest, manifest and envelope are the same
	manifestHash := ComputeManifestHash(manifestBytes)

	if jsonOutput {
		// Output as JSON matching qos_client manifest format (no approvals)
		output := map[string]interface{}{
			"namespace": map[string]interface{}{
				"name":      manifest.Namespace.Name,
				"nonce":     manifest.Namespace.Nonce,
				"quorumKey": hex.EncodeToString(manifest.Namespace.QuorumKey),
			},
			"pivot": map[string]interface{}{
				"hash":    hex.EncodeToString(manifest.Pivot.Hash[:]),
				"restart": manifest.Pivot.Restart,
				"args":    manifest.Pivot.Args,
			},
			"manifestSet": map[string]interface{}{
				"threshold": manifest.ManifestSet.Threshold,
				"members":   formatMembers(manifest.ManifestSet.Members),
			},
			"shareSet": map[string]interface{}{
				"threshold": manifest.ShareSet.Threshold,
				"members":   formatMembers(manifest.ShareSet.Members),
			},
			"enclave": map[string]interface{}{
				"pcr0":               hex.EncodeToString(manifest.Enclave.Pcr0),
				"pcr1":               hex.EncodeToString(manifest.Enclave.Pcr1),
				"pcr2":               hex.EncodeToString(manifest.Enclave.Pcr2),
				"pcr3":               hex.EncodeToString(manifest.Enclave.Pcr3),
				"awsRootCertificate": hex.EncodeToString(manifest.Enclave.AwsRootCertificate),
				"qosCommit":          manifest.Enclave.QosCommit,
			},
			"patchSet": map[string]interface{}{
				"threshold": manifest.PatchSet.Threshold,
				"members":   formatPatchMembers(manifest.PatchSet.Members),
			},
		}

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal output: %v", err)
		}
		fmt.Println(string(jsonBytes))
		return
	}

	// Text output for raw manifest
	fmt.Printf("=== QoS Manifest ===\n")
	fmt.Printf("Manifest Hash: %s\n\n", manifestHash)
	printManifest(manifest)
}

// runDecodeManifestEnvelope decodes and displays a QoS manifest envelope with approvals
func runDecodeManifestEnvelope(filePath string, base64String string, jsonOutput bool) {
	var envelope *ManifestEnvelope
	var manifest *Manifest
	var manifestBytes, envelopeBytes []byte
	var err error

	if filePath != "" {
		// Decode from file
		envelope, manifest, manifestBytes, envelopeBytes, err = DecodeManifestEnvelopeFromFile(filePath)
		if err != nil {
			log.Fatalf("Failed to decode manifest envelope from file: %v", err)
		}
	} else {
		// Decode from base64
		envelope, manifest, manifestBytes, envelopeBytes, err = DecodeManifestEnvelopeFromBase64(base64String)
		if err != nil {
			log.Fatalf("Failed to decode manifest envelope from base64: %v", err)
		}
	}

	// Compute hashes
	manifestHash := ComputeManifestHash(manifestBytes)
	envelopeHash := ComputeManifestHash(envelopeBytes)

	if jsonOutput {
		// Output as JSON matching qos_client manifest-envelope format
		output := map[string]interface{}{
			"manifest": map[string]interface{}{
				"namespace": map[string]interface{}{
					"name":      manifest.Namespace.Name,
					"nonce":     manifest.Namespace.Nonce,
					"quorumKey": hex.EncodeToString(manifest.Namespace.QuorumKey),
				},
				"pivot": map[string]interface{}{
					"hash":    hex.EncodeToString(manifest.Pivot.Hash[:]),
					"restart": manifest.Pivot.Restart,
					"args":    manifest.Pivot.Args,
				},
				"manifestSet": map[string]interface{}{
					"threshold": manifest.ManifestSet.Threshold,
					"members":   formatMembers(manifest.ManifestSet.Members),
				},
				"shareSet": map[string]interface{}{
					"threshold": manifest.ShareSet.Threshold,
					"members":   formatMembers(manifest.ShareSet.Members),
				},
				"enclave": map[string]interface{}{
					"pcr0":               hex.EncodeToString(manifest.Enclave.Pcr0),
					"pcr1":               hex.EncodeToString(manifest.Enclave.Pcr1),
					"pcr2":               hex.EncodeToString(manifest.Enclave.Pcr2),
					"pcr3":               hex.EncodeToString(manifest.Enclave.Pcr3),
					"awsRootCertificate": hex.EncodeToString(manifest.Enclave.AwsRootCertificate),
					"qosCommit":          manifest.Enclave.QosCommit,
				},
				"patchSet": map[string]interface{}{
					"threshold": manifest.PatchSet.Threshold,
					"members":   formatPatchMembers(manifest.PatchSet.Members),
				},
			},
			"manifestSetApprovals": formatApprovals(envelope.ManifestSetApprovals),
			"shareSetApprovals":    formatApprovals(envelope.ShareSetApprovals),
		}

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Human-readable output
		fmt.Fprintf(os.Stderr, "=== QoS Manifest Decoded ===\n\n")
		fmt.Fprintf(os.Stderr, "Namespace:\n")
		fmt.Fprintf(os.Stderr, "  Name: %s\n", manifest.Namespace.Name)
		fmt.Fprintf(os.Stderr, "  Nonce: %d\n", manifest.Namespace.Nonce)
		fmt.Fprintf(os.Stderr, "  Quorum Key: %s\n", hex.EncodeToString(manifest.Namespace.QuorumKey))
		fmt.Fprintf(os.Stderr, "\nPivot Config:\n")
		fmt.Fprintf(os.Stderr, "  Binary Hash: %s\n", hex.EncodeToString(manifest.Pivot.Hash[:]))
		fmt.Fprintf(os.Stderr, "  Restart Policy: %d\n", manifest.Pivot.Restart)
		fmt.Fprintf(os.Stderr, "\nManifest Set:\n")
		fmt.Fprintf(os.Stderr, "  Threshold: %d\n", manifest.ManifestSet.Threshold)
		fmt.Fprintf(os.Stderr, "  Members: %d\n", len(manifest.ManifestSet.Members))
		fmt.Fprintf(os.Stderr, "\nEnclave (Nitro Config):\n")
		fmt.Fprintf(os.Stderr, "  PCR0: %s\n", hex.EncodeToString(manifest.Enclave.Pcr0))
		fmt.Fprintf(os.Stderr, "  PCR1: %s\n", hex.EncodeToString(manifest.Enclave.Pcr1))
		fmt.Fprintf(os.Stderr, "  PCR2: %s\n", hex.EncodeToString(manifest.Enclave.Pcr2))
		fmt.Fprintf(os.Stderr, "  PCR3: %s\n", hex.EncodeToString(manifest.Enclave.Pcr3))
		fmt.Fprintf(os.Stderr, "\nHashes:\n")
		fmt.Fprintf(os.Stderr, "  Manifest: %s\n", manifestHash)
		fmt.Fprintf(os.Stderr, "  Envelope: %s\n", envelopeHash)
	}
}

// formatMembers formats QuorumMember array for JSON output
func formatMembers(members []QuorumMember) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"alias":  m.Alias,
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

// formatPatchMembers formats MemberPubKey array for JSON output
func formatPatchMembers(members []MemberPubKey) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

func formatApprovals(approvals []Approval) []map[string]interface{} {
	result := make([]map[string]interface{}, len(approvals))
	for i, approval := range approvals {
		result[i] = map[string]interface{}{
			"signature": hex.EncodeToString(approval.Signature),
			"member": map[string]string{
				"alias":  approval.Member.Alias,
				"pubKey": hex.EncodeToString(approval.Member.PubKey),
			},
		}
	}
	return result
}

func printManifest(manifest *Manifest) {
	fmt.Printf("Namespace:\n")
	fmt.Printf("  Name: %s\n", manifest.Namespace.Name)
	fmt.Printf("  Nonce: %d\n", manifest.Namespace.Nonce)
	fmt.Printf("  Quorum Key: %s\n", hex.EncodeToString(manifest.Namespace.QuorumKey))

	fmt.Printf("\nPivot:\n")
	fmt.Printf("  Hash: %s\n", hex.EncodeToString(manifest.Pivot.Hash[:]))
	fmt.Printf("  Restart: %s\n", manifest.Pivot.Restart)
	fmt.Printf("  Args: %v\n", manifest.Pivot.Args)

	fmt.Printf("\nManifest Set (threshold: %d):\n", manifest.ManifestSet.Threshold)
	for i, member := range manifest.ManifestSet.Members {
		fmt.Printf("  Member %d: %s (%s)\n", i+1, member.Alias, hex.EncodeToString(member.PubKey)[:16]+"...")
	}

	fmt.Printf("\nShare Set (threshold: %d):\n", manifest.ShareSet.Threshold)
	for i, member := range manifest.ShareSet.Members {
		fmt.Printf("  Member %d: %s (%s)\n", i+1, member.Alias, hex.EncodeToString(member.PubKey)[:16]+"...")
	}

	fmt.Printf("\nEnclave:\n")
	fmt.Printf("  PCR0: %s\n", hex.EncodeToString(manifest.Enclave.Pcr0))
	fmt.Printf("  PCR1: %s\n", hex.EncodeToString(manifest.Enclave.Pcr1))
	fmt.Printf("  PCR2: %s\n", hex.EncodeToString(manifest.Enclave.Pcr2))
	fmt.Printf("  PCR3: %s\n", hex.EncodeToString(manifest.Enclave.Pcr3))
	fmt.Printf("  QoS Commit: %s\n", manifest.Enclave.QosCommit)
}
