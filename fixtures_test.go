package main

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// Embedded test fixtures
// These include real Turnkey attestation documents and manifest data

//go:embed testdata/turnkey-attestation.base64
var turnkeyAttestationBase64 string

//go:embed testdata/manifest.bin
var testManifestBinary []byte

// getTurnkeyAttestation returns a real Turnkey attestation document for testing
// This attestation document contains valid AWS Nitro enclave attestation data
// obtained from the Turnkey service.
func getTurnkeyAttestation() string {
	return strings.TrimSpace(turnkeyAttestationBase64)
}

// getTestManifest returns the embedded test manifest binary data
// This is a real manifest file in Borsh format from Turnkey
func getTestManifest() []byte {
	return testManifestBinary
}

// TestManifestParsing tests parsing of the embedded test manifest
func TestManifestParsing(t *testing.T) {
	manifestData := getTestManifest()
	require.NotEmpty(t, manifestData)

	m, manifestBytes, err := manifest.DecodeRawManifestFromBase64(strings.TrimSpace(string(manifestData)))
	require.NoError(t, err)
	require.NotNil(t, m)
	require.NotEmpty(t, manifestBytes)

	// Verify manifest has expected structure
	require.NotNil(t, m.Namespace)
	require.NotNil(t, m.Enclave)
	require.NotEmpty(t, m.Enclave.Pcr0)
	require.NotEmpty(t, m.Enclave.Pcr1)
	require.NotEmpty(t, m.Enclave.Pcr2)
	require.NotEmpty(t, m.Enclave.Pcr3)
}

// TestTurnkeyAttestationAvailable tests that the turnkey attestation fixture is available
func TestTurnkeyAttestationAvailable(t *testing.T) {
	attestation := getTurnkeyAttestation()
	require.NotEmpty(t, attestation)
	// Attestation document should be base64 encoded
	require.Greater(t, len(attestation), 0)
}

// Commands to obtain test fixtures:
//
// ## Turnkey Attestation:
// To obtain a new Turnkey attestation document:
//
// ```bash
// turnkey request \
//   --host api.turnkey.com \
//   --path /public/v1/query/get_attestation \
//   --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
//   --organization=<yourOrgId> | jq -r '.attestationDocument' > testdata/turnkey-attestation.base64
// ```
//
// Replace <yourOrgId> with your actual Turnkey organization ID.
// Requires the Turnkey CLI and appropriate permissions.
//
// Note: Attestation documents contain expired certificates and may require
// using SkipTimestampCheck: true when verifying in tests.
//
// ## Manifest Binary:
// To obtain a new manifest binary:
//
// ```bash
// # The manifest binary can be obtained from the Turnkey manifest extractor
// # or generated as part of the transaction signing process
// cp /path/to/manifest.bin testdata/manifest.bin
// ```
//
// The manifest.bin file is in Borsh binary format and represents the
// serialized transaction manifest from a Turnkey attestation.
