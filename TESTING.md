# Testing and Validation

## Security Test Coverage

See complete test suite in [`verify/service_test.go`](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service_test.go).

**1. Signature Validation Tests**
```go
func TestSignatureValidation(t *testing.T) {
    tests := []struct {
        name      string
        message   string
        signature string
        valid     bool
    }{
        {"valid signature", validMessage, validSignature, true},
        {"tampered message", tamperedMessage, validSignature, false},
        {"invalid signature", validMessage, invalidSignature, false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := verifySignature(publicKey, tt.message, tt.signature)
            assert.Equal(t, tt.valid, result)
        })
    }
}
```

**2. Attestation Validation Tests**
```go
func TestAttestationValidation(t *testing.T) {
    t.Run("expired attestation rejected", func(t *testing.T) {
        oldAttestation := createAttestationWithTimestamp(
            time.Now().Add(-10 * time.Minute))
        err := validateAttestation(oldAttestation)
        assert.Error(t, err)
    })

    t.Run("invalid PCR rejected", func(t *testing.T) {
        attestation := createAttestationWithInvalidPCR()
        err := validateAttestation(attestation)
        assert.Error(t, err)
    })
}
```

**3. Manifest Validation Tests**
```go
func TestManifestValidation(t *testing.T) {
    t.Run("manifest hash matches UserData", func(t *testing.T) {
        manifest := loadTestManifest()
        attestation := loadTestAttestation()
        err := verifyManifestHash(manifest, attestation)
        assert.NoError(t, err)
    })

    t.Run("binary hash verified", func(t *testing.T) {
        manifest := loadTestManifest()
        expectedHash := "ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678"
        actualHash := hex.EncodeToString(manifest.Pivot.Hash[:])
        assert.Equal(t, expectedHash, actualHash)
    })
}
```

## Recommended Security Testing

- **Unit Tests**: Comprehensive test coverage for all verification levels
- **Integration Tests**: End-to-end verification with real API responses
- **Penetration Testing**: Annual testing focusing on protocol-specific attacks
- **Dependency Scanning**: Regular scanning for vulnerable dependencies
- **Static Analysis**: Code scanning for security vulnerabilities