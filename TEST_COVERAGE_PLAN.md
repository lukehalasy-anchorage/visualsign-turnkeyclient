# Test Coverage Implementation Plan for visualsign-turnkeyclient

## Goal
Increase test coverage from 42.9% to 80% by implementing tests for untested packages.

## Current Status
- **Current Coverage**: 42.9%
- **Target Coverage**: 80%
- **Packages with 0% coverage**: cmd, crypto, keys, manifest, verify
- **Package with low coverage**: api (8.2%)

## Implementation Instructions

### Phase 1: Core Cryptographic Functions (Target: +8-10% coverage)

#### 1.1 Test crypto package (crypto/signing.go)
**File to create**: `crypto/signing_test.go`

**Functions to test**:
- `SignWithECDSA(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error)`
- `MarshalECDSASignatureDER(r, s *big.Int) ([]byte, error)`
- `VerifyECDSASignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool`

**Test cases to implement**:
```go
// Test structure example:
func TestSignWithECDSA(t *testing.T) {
    // Test valid signing
    // Test with nil private key
    // Test with empty data
    // Test signature can be verified
}

func TestMarshalECDSASignatureDER(t *testing.T) {
    // Test valid r,s values
    // Test with nil values
    // Test with zero values
    // Test with max values
}

func TestVerifyECDSASignature(t *testing.T) {
    // Test valid signature verification
    // Test invalid signature
    // Test wrong public key
    // Test malformed signature
}
```

#### 1.2 Test keys package (keys/loader.go)
**File to create**: `keys/loader_test.go`

**Functions to test**:
- `LoadAPIKeyFromFile(publicKeyPath, privateKeyPath string) (*APIKey, error)`
- `GetAPIKey() (*APIKey, error)` (FileAPIKeyProvider method)

**Test approach using existing test files**:
1. Create permanent test fixtures in `keys/testdata/` directory
2. Test loading valid keys from testdata
3. Test missing file scenarios (use non-existent paths)
4. Test invalid key formats (create invalid test fixtures)

**Test fixture files to create**:
- `keys/testdata/valid_public.hex` - Valid P256 public key
- `keys/testdata/valid_private.hex` - Valid P256 private key
- `keys/testdata/invalid_public.hex` - Invalid hex format
- `keys/testdata/wrong_curve_private.hex` - Non-P256 curve key

**Example test structure**:
```go
func TestLoadAPIKeyFromFile(t *testing.T) {
    // Test successful loading
    key, err := LoadAPIKeyFromFile(
        "testdata/valid_public.hex",
        "testdata/valid_private.hex",
    )
    assert.NoError(t, err)
    assert.NotNil(t, key)

    // Test missing public key file
    _, err = LoadAPIKeyFromFile(
        "testdata/non_existent.hex",
        "testdata/valid_private.hex",
    )
    assert.Error(t, err)

    // Test invalid hex format
    _, err = LoadAPIKeyFromFile(
        "testdata/invalid_public.hex",
        "testdata/valid_private.hex",
    )
    assert.Error(t, err)
}
```

#### 1.3 Test manifest/hash.go
**File to create**: `manifest/hash_test.go`

**Function to test**:
- `ComputeHash(manifest *awsnitroverifier.Manifest) (string, error)`

**Test cases**:
```go
func TestComputeHash(t *testing.T) {
    // Create test manifest
    // Compute hash
    // Verify hash is consistent
    // Test with nil manifest
    // Test with empty manifest
}
```

### Phase 2: Manifest Parsing (Target: +9-11% coverage)

#### 2.1 Test manifest/parser.go
**File to create**: `manifest/parser_test.go`

**Functions to test** (all currently at 0%):
1. `DecodeManifestFromBase64(base64Str string) (*awsnitroverifier.Manifest, error)`
2. `DecodeManifestFromFile(filePath string) (*awsnitroverifier.Manifest, error)`
3. `DecodeRawManifestFromFile(filePath string) ([]byte, error)`
4. `DecodeRawManifestFromBase64(base64Str string) ([]byte, error)`
5. `DecodeManifestEnvelopeFromFile(filePath string) (*awsnitroverifier.ManifestEnvelope, error)`
6. `DecodeManifestEnvelopeFromBase64(base64Str string) (*awsnitroverifier.ManifestEnvelope, error)`

**Test resources available**:
- Use `/home/user/projects/visualsign-turnkeyclient/testdata/manifest.bin`
- Create test base64 strings from the binary file

**Test implementation**:
```go
func TestDecodeManifestFromFile(t *testing.T) {
    // Test with testdata/manifest.bin
    // Test with non-existent file
    // Test with invalid manifest file
}

func TestDecodeManifestFromBase64(t *testing.T) {
    // Read testdata/manifest.bin and encode to base64
    // Test valid decoding
    // Test invalid base64
    // Test invalid borsh data
}

// Similar pattern for other functions
```

#### 2.2 Test manifest/types.go
**File to create**: `manifest/types_test.go`

**Functions to test**:
- `(r RestartPolicy) MarshalJSON() ([]byte, error)`
- `(r RestartPolicy) String() string`

**Test cases**:
```go
func TestRestartPolicyMarshalJSON(t *testing.T) {
    // Test RestartPolicyNever
    // Test RestartPolicyAlways
    // Test unknown values
}

func TestRestartPolicyString(t *testing.T) {
    // Test all enum values
    // Test default case
}
```

### Phase 3: API Client Functions (Target: +8-10% coverage)

#### 3.1 Test api/client.go
**File to update**: `api/client_test.go` (already exists with some tests)

**Functions to add tests for** (currently 0%):
- `NewClient(baseURL string, httpClient HTTPClient) *Client`
- `CreateSignablePayload(ctx context.Context, request *TurnkeyVisualSignRequest) (*CreateSignablePayloadResponse, error)`
- `GetBootAttestation(ctx context.Context, request *GetQuorumAttestationRequest) (*GetQuorumAttestationResponse, error)`

**Testing approach**:
1. Create mock HTTP client (interface already defined)
2. Test successful API calls
3. Test error responses
4. Test network errors
5. Test JSON parsing errors

**Mock HTTP client example**:
```go
type mockHTTPClient struct {
    response *http.Response
    err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
    return m.response, m.err
}

func TestCreateSignablePayload(t *testing.T) {
    // Test successful response
    // Test 400 error
    // Test 500 error
    // Test network error
    // Test invalid JSON response
}
```

### Phase 4: Verification Service (Target: +12-15% coverage)

#### 4.1 Test verify/service.go
**File to create**: `verify/service_test.go`

**Key functions to test**:
- `NewService(apiClient APIClient, verifier AttestationVerifier) *Service`
- `Verify(ctx context.Context, options Options) (*Result, error)`
- `extractAttestations(response *api.GetQuorumAttestationResponse) ([]Attestation, error)`
- `extractPublicKey(attestation Attestation) ([]byte, error)`
- `verifyUserData(manifest *awsnitroverifier.Manifest, expectedHash []byte) error`

**Testing strategy**:
1. Create mock APIClient interface
2. Create mock AttestationVerifier interface
3. Use real testdata fixtures
4. Test complete verification flow
5. Test error scenarios

**Mock setup example**:
```go
type mockAPIClient struct {
    attestationResponse *api.GetQuorumAttestationResponse
    attestationErr      error
}

type mockAttestationVerifier struct {
    verifyResult error
}

func TestVerify(t *testing.T) {
    // Setup mocks
    // Test successful verification
    // Test attestation fetch failure
    // Test invalid attestation format
    // Test signature verification failure
    // Test manifest hash mismatch
}
```

### Phase 5: Optional - Formatter Functions (Target: +8-10% coverage)

#### 5.1 Test verify/formatter.go
**File to create**: `verify/formatter_test.go`

**Functions to test**:
- `FormatPCRValues(pcrs map[int]string) string`
- `FormatManifest(manifest *awsnitroverifier.Manifest) string`
- `FormatVerificationResult(result *Result) string`

**Note**: This phase is optional if 80% is already reached.

## Execution Steps for Each Phase

### For each phase:

1. **Create test file**: Use the specified filename
2. **Import required packages**:
   ```go
   import (
       "testing"
       "github.com/stretchr/testify/assert"
       "github.com/stretchr/testify/require"
       // Other needed imports
   )
   ```

3. **Write test functions**: Follow the test structure provided

4. **Run tests and check coverage**:
   ```bash
   go test -v -race -coverprofile=coverage.out ./...
   grep "coverage:" -A1
   ```

5. **Verify no test failures**: All tests must pass

6. **Check incremental coverage**:
   ```bash
   go test -coverprofile=coverage.out ./... 2>&1 | grep "coverage:"
   ```

## Success Criteria

After implementing Phases 1-4:
- Coverage should be ≥80%
- All tests should pass
- CI/CD pipeline should pass with the updated coverage

## Common Patterns to Follow

### Table-driven tests
```go
func TestFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "test", "expected", false},
        {"empty input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Function(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.want, got)
            }
        })
    }
}
```

### Working with test fixtures
```go
// Use permanent test fixtures in testdata directories
func TestWithTestFixtures(t *testing.T) {
    // Read from existing test files
    manifest, err := DecodeManifestFromFile("testdata/manifest.bin")
    require.NoError(t, err)

    // Test with non-existent files for error cases
    _, err = DecodeManifestFromFile("testdata/does_not_exist.bin")
    assert.Error(t, err)
}

// Or use go:embed for compile-time inclusion
//go:embed testdata/*
var testFS embed.FS

func TestWithEmbeddedFiles(t *testing.T) {
    data, err := testFS.ReadFile("testdata/manifest.bin")
    require.NoError(t, err)
    // Use data directly without file I/O
}
```

### Mocking HTTP clients
```go
func TestWithMockHTTP(t *testing.T) {
    mockResponse := &http.Response{
        StatusCode: 200,
        Body:       io.NopCloser(strings.NewReader(`{"key":"value"}`)),
    }

    client := &mockHTTPClient{response: mockResponse}
    // Use client in test
}
```

## Notes

- Start with Phase 1 as it has the highest ROI (low effort, good coverage gain)
- Use existing test patterns from `apikey_test.go` and `client_test.go` as reference
- The `testdata` directory contains real fixtures that should be used in tests
- If you encounter import issues with `awsnitroverifier`, ensure the private repo token is configured
- Run `go mod download` if you encounter missing dependencies

## Expected Timeline

- Phase 1: 1-2 hours (simple, pure functions)
- Phase 2: 2-3 hours (file I/O and parsing)
- Phase 3: 2-3 hours (HTTP mocking)
- Phase 4: 3-4 hours (complex integration)
- Total: 8-12 hours to reach 80% coverage

## Commands Reference

```bash
# Run all tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# Check coverage percentage
go test -coverprofile=coverage.out ./... 2>&1 | grep "coverage:" | tail -1

# View detailed coverage by function
go tool cover -func=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# Run tests for specific package
go test -v -cover ./crypto/...
```