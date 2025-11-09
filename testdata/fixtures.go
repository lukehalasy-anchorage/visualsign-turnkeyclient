// Package testdata provides embedded test fixtures for use across all test packages.
package testdata

import _ "embed"

// ManifestBin is the real production manifest binary used for testing
//
//go:embed manifest.bin
var ManifestBin []byte

// AttestationBase64 is the real production attestation document in base64 format
//
//go:embed turnkey-attestation.base64
var AttestationBase64 []byte
