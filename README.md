# Turnkey Visualsign Client

A Go client for Turnkey's Visualsign API that provides end-to-end verification of transactions executed in AWS Nitro enclaves, including QoS manifest decoding and validation.

## Features

- Parse Solana transactions via Turnkey's Visualsign API
- Verify AWS Nitro enclave attestations
- Decode and display QoS ([QuorumOS](https://github.com/tkhq/qos)) manifests
- Validate signatures from ephemeral keys
- Export QoS manifests for offline verification
- Compare against reference `qos_client` implementation

## Installation

### Prerequisites

This project requires Go 1.25.0 or later.

**Private Dependencies**: This project depends on `github.com/anchorageoss/awsnitroverifier`, which is a private repository. To build this project, you need:

1. Access to the Anchorage GitHub organization
2. Git credentials configured (SSH or HTTPS with personal access token)
3. Set the `GOPRIVATE` environment variable:

```bash
export GOPRIVATE=github.com/anchorageoss/*
```

You can make this permanent by adding it to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
echo 'export GOPRIVATE=github.com/anchorageoss/*' >> ~/.bashrc
```

### Build

```bash
# Set GOPRIVATE if not already set
export GOPRIVATE=github.com/anchorageoss/*

# Build binary to bin/ directory using Makefile
make build

# Or build directly with go
go build -o bin/turnkey-client .

# Or run directly without building
go run . <command> [args...]
```

### Running Tests

```bash
# Run all tests with coverage
make test

# Run tests and view coverage report
make test-coverage

# Run tests and serve coverage interactively (http://localhost:3000)
make test-cover

# Run specific test suite
make test-manifest    # Tests for manifest parsing
make test-crypto      # Tests for cryptography
make test-apikey      # Tests for API key handling
make test-client      # Tests for client functionality

# Run benchmarks
make bench
```

## Commands

### Parse Command

Parse a transaction and extract attestations:

```bash
./bin/turnkey-client parse \
  --host https://api.turnkey.com \
  --organization-id <your-org-id> \
  --key-name testkey \
  --unsigned-payload <base64-encoded-payload>
```

### Verify Command

Perform end-to-end verification of a transaction:

```bash
./bin/turnkey-client verify \
  --host https://api.turnkey.com \
  --organization-id <your-org-id> \
  --key-name testkey \
  --unsigned-payload <base64-encoded-payload>
```

#### Optional Flags

- `--qos-manifest-hex <hex>`: Expected QoS manifest hash to verify against UserData
- `--pivot-binary-hash-hex <hex>`: Hash of the binary that QoS runs after initrd is booted
- `--save-qos-manifest <path>`: Save the QoS manifest envelope to a binary file

### Decode Manifest Command

Decode and display a QoS manifest from a file or base64 string:

```bash
# Decode from file (human-readable)
./bin/turnkey-client decode-manifest raw --file /tmp/manifest.bin

# Decode from file (JSON output)
./bin/turnkey-client decode-manifest raw --file /tmp/manifest.bin --json

# Decode from base64 string
./bin/turnkey-client decode-manifest raw --base64 "AQAAAAAAA..." --json

# Decode manifest envelope (with approvals)
./bin/turnkey-client decode-manifest envelope --file /tmp/manifest.bin --json
```

#### Flags

- `--file <path>`: Path to manifest envelope binary file
- `--base64 <string>`: Base64-encoded manifest envelope string
- `--json`: Output in JSON format (compatible with qos_client format)

**Note**: Either `--file` or `--base64` must be provided, but not both.

## Verification Process

The verify command performs comprehensive validation:

1. **API Call**: Calls Turnkey's Visualsign API to parse the transaction
2. **Attestation Verification**: Validates the AWS Nitro attestation document
3. **Public Key Extraction**: Extracts the ephemeral public key from the signature
4. **Signature Verification**: Verifies the ECDSA signature matches the message
5. **Manifest Decoding**: Decodes the QoS manifest from borsh-encoded data
6. **Hash Validation**: Compares manifest hash against UserData in attestation

### Verification Output

```
=== STEP 1: API Response Received ===
✓ Received boot attestation document
✓ Public key: 04083c74f3776534d731...
✓ Signature: a81944cb12c2a2c0f4d4...

=== STEP 2: Verify Attestation Document ===
✓ Attestation document verified successfully
✓ Module ID: i-0f9376f6d51f64b81-enc0199e598f3733503
✓ PCRs verified: 16 PCRs found

📋 UserData (QoS Manifest Hash / Pivot Binary Hash):
  Hex: 60d9c5754d6979afca7a5e75edfa43b629110301d8c57f9ff1718b74f70b5a9c

=== QoS Manifest Decoding ===
✓ Manifest decoded successfully
✓ Raw Manifest Bytes SHA256: 1748b319a6353f8191c79f2e4841ef7c...
✓ Envelope SHA256: de3900c56a32686ab5c0d752f63ecf61...

📋 Manifest Details:
  Namespace:
    Name: testkey/anchorageoss/visualsign-parser
    Nonce: 20251001
    Quorum Key: 04451028fc9d42cef6d8f2a3ebe17d65...
  Pivot Config:
    Binary Hash: ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678
    Restart Policy: 1 (Always)
  Manifest Set:
    Threshold: 2
    Members: 2
  Enclave (Nitro Config):
    PCR0: f67076a8f9796b90d7f0eb148ec6926f66fe04c80861151916961f7dec715b3c...
```

## QoS Manifest Validation

### What is a QoS Manifest?

The QoS ([QuorumOS](https://github.com/tkhq/qos)) manifest defines the security policy for the Nitro enclave. QuorumOS is Turnkey's secure operating system for AWS Nitro Enclaves that enforces threshold cryptography and secure key management.

The manifest specifies:

- **Namespace**: Organization and enclave identifier (e.g., `testkey/anchorageoss/visualsign-parser`)
- **Pivot Config**: Binary hash of the enclave application and restart policy
- **Manifest Set**: Quorum members who can update the manifest (threshold-based)
- **Share Set**: Members who hold key shares for cryptographic operations
- **Enclave Config**: Expected PCR values that attest to the enclave state
- **Patch Set**: Members authorized to apply security patches

### Why Validate the Manifest?

The manifest hash in the attestation's `UserData` field proves that:
1. The enclave is running QuorumOS
2. The enclave is running the expected binary (via pivot hash)
3. The enclave has the correct security configuration in the correct environment (via PCR3)
4. Only authorized parties can modify the manifest (via quorum members)
5. The enclave configuration hasn't been tampered with

### Decoding Process

1. Extract `qosManifestEnvelopeB64` from API response's `bootProof` field
2. Decode from base64 to get borsh-encoded bytes
3. Deserialize using borsh format to extract manifest structure
4. Compute SHA256 hash and compare against attestation UserData

```go
// Manifest structure (simplified)
type Manifest struct {
    Namespace   Namespace   // org/app identifier
    Pivot       PivotConfig // binary hash + restart policy
    ManifestSet ManifestSet // quorum for manifest updates
    ShareSet    ShareSet    // key share holders
    Enclave     NitroConfig // expected PCRs
    PatchSet    PatchSet    // patch approvers
}
```

### Validation Against Reference Implementation

We validate our Go implementation against Turnkey's reference Rust `qos_client`:

#### Step 1: Save Manifest from Go Client

```bash
./bin/turnkey-client verify \
  --host https://api.testkey.turnkey.com \
  --organization-id <your-org-id> \
  --key-name testkey \
  --unsigned-payload 'AQAAAAA...' \
  --save-qos-manifest /tmp/manifest.bin
```

#### Step 2: Verify with Docker Container

The easiest way to verify against the reference implementation is to use a containerized version:

```bash
# Build a container image with qos_client
docker run -v /tmp:/tmp \
  ghcr.io/tkhq/qos:latest \
  qos_client display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin
```

Or manually verify with qos_client (Rust Reference) if you have it installed:

```bash
cd ~/projects/tkhq/qos/src/qos_client/
cargo run --bin qos_client -- display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin
```

#### Step 3: Compare JSON Outputs

```bash
# Get JSON from reference implementation
cd ~/projects/tkhq/qos/src/qos_client/
cargo run --bin qos_client -- display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin \
  --json > /tmp/reference.json

# View formatted output
cat /tmp/reference.json | jq .
```

### Automated Verification Script

Use the provided script to automate the comparison between our Go client and the reference implementation. By default, it uses a Docker container for the reference implementation:

```bash
chmod +x verify-manifest.sh
./verify-manifest.sh /tmp/manifest.bin
```

Or use a local qos_client installation:

```bash
./verify-manifest.sh /tmp/manifest.bin false
```

The script:
1. Runs `qos_client --json` in Docker container to get reference output (or local if specified)
2. Runs `./visualsign-turnkey-client decode-manifest --json` to get our output
3. Compares key fields (namespace, nonce, pivot hash, PCRs, etc.)
4. Reports matches/mismatches with clear visual indicators

**Script Output:**
```
=== QoS Manifest Verification ===
Manifest file: /tmp/manifest.bin
Reference tool: ~/projects/tkhq/qos/src/qos_client

Running qos_client (reference implementation)...
Running Go client (our implementation)...

=== Extracting Key Fields ===
✓ Fields extracted from both implementations

=== Comparison Results ===

✅ Namespace: MATCH
✅ Nonce: MATCH
✅ Quorum Key: MATCH
✅ Pivot Hash: MATCH
✅ Restart Policy: MATCH
✅ Manifest Threshold: MATCH
✅ Manifest Members: MATCH
✅ PCR0: MATCH
✅ PCR1: MATCH
✅ PCR2: MATCH
✅ PCR3: MATCH

✅ Verification Complete: All fields match!

Reference JSON saved to: /tmp/qos_manifest_reference.json
Go client JSON saved to: /tmp/go_manifest_output.json
```

### Key Validation Points

#### 1. Namespace Validation
```
Name: testkey/anchorageoss/visualsign-parser
```
- **Environment**: `testkey` or `prod`
- **Organization**: `anchorageoss`
- **Application**: `visualsign-parser`

The namespace identifies the specific enclave instance and must match expectations.

#### 2. Pivot Config Validation
```
Binary Hash: ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678
Restart Policy: Always
```
- **Binary Hash**: SHA256 of the enclave application binary
- **Restart Policy**: Controls enclave restart behavior
  - `Never` (0): Enclave stops on exit
  - `Always` (1): Enclave automatically restarts

#### 3. PCR Validation

Platform Configuration Registers (PCRs) attest to the enclave state:

| PCR | Measures | Purpose |
|-----|----------|---------|
| PCR0 | Enclave image file | Verifies the exact enclave image |
| PCR1 | Linux kernel and bootstrap | Validates the OS environment |
| PCR2 | Application | Confirms the application code |
| PCR3 | IAM role and instance ID | Ties to AWS identity |

**Critical**: These PCR values MUST match the expected PCRs. You should be able to reproduce them locally.

#### 4. Quorum Validation
```
Manifest Set:
  Threshold: 2
  Members: 2
```
- **Threshold**: Minimum signatures needed to update the manifest
- **Members**: List of authorized public keys

Each member has:
- **Alias**: Human-readable identifier (e.g., "1", "2")
- **PubKey**: P-256 public key (130 hex characters)

### Hash Verification Process

The client computes three types of hashes:

```
Raw Manifest Hash:        1748b319a6353f8191c79f2e4841ef7c948a722107ab3d99fec82bf6f306d464
Re-serialized Hash:       1748b319a6353f8191c79f2e4841ef7c948a722107ab3d99fec82bf6f306d464
Envelope Hash:            de3900c56a32686ab5c0d752f63ecf61a27a82f9c1b0da3c30d95c30de141d3e

UserData (from attestation): 60d9c5754d6979afca7a5e75edfa43b629110301d8c57f9ff1718b74f70b5a9c
```

**Hash Mismatch Reasons:**
- ⚠️ **Different manifest versions**: The API may return a newer manifest than what was present at enclave boot time
- ⚠️ **Manifest update**: The manifest was updated after the enclave started
- ⚠️ **Environment difference**: Comparing prod manifest against testkey attestation

**Note**: When the Enclave reboots/is redeployed, it generates a new manifest. It's possible that deployments happen without callers knowing about it, so always get latest value and confirm end to end.

### Troubleshooting

#### Hash Mismatch

If manifest hash doesn't match UserData:

1. **Check Environment**: Ensure you're comparing the same environment (testkey vs prod)
2. **Check Timing**: Verify the manifest wasn't updated after enclave boot
3. **Use Reference**: Compare with `qos_client` output to verify decoding is correct
4. **Check Envelope**: Try comparing envelope hash vs raw manifest hash

```bash
# Compare hashes
./bin/turnkey-client verify ... 2>&1 | grep "SHA256"
```

#### Decoding Errors

If manifest decoding fails:

1. **Verify Base64**: Check that the base64 encoding is valid
2. **Check Field Name**: Use `qosManifestEnvelopeB64` (not `qosManifestB64`)
3. **Borsh Format**: Ensure the borsh deserialization format matches the manifest structure
4. **Compare with Reference**: Run `qos_client` to see if it can decode the same file

```bash
# Test with Docker container (easiest method)
docker run --rm -v /tmp:/tmp \
  ghcr.io/tkhq/qos:latest \
  qos_client display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin

# Or test with local qos_client if installed
cd ~/projects/tkhq/qos/src/qos_client/
cargo run --bin qos_client -- display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin
```

#### Reference Implementation Differences

Our Go implementation should produce identical output to `qos_client`. If you find differences:

1. **Field Order**: Check if fields are in the correct order
2. **Type Mismatches**: Verify uint32 vs uint64, etc.
3. **Missing Fields**: Ensure all struct fields are present
4. **Hex Encoding**: Check lowercase vs uppercase hex

Report any discrepancies as they indicate a bug in the Go implementation.

## Implementation Details

### Borsh Serialization

The manifest uses [Borsh](https://borsh.io/) (Binary Object Representation Serializer for Hashing):

```go
type Manifest struct {
    Namespace   Namespace   `borsh:"namespace"`
    Pivot       PivotConfig `borsh:"pivot"`
    ManifestSet ManifestSet `borsh:"manifest_set"`
    ShareSet    ShareSet    `borsh:"share_set"`
    Enclave     NitroConfig `borsh:"enclave"`
    PatchSet    PatchSet    `borsh:"patch_set"`
}
```

**Key Features of Borsh:**
- Deterministic serialization (same object → same bytes)
- Efficient binary format
- Strong typing with explicit field order
- Used by Turnkey QuorumOS for manifest integrity

### Dependencies

- `github.com/anchorageoss/awsnitroverifier`: AWS Nitro attestation verification
- `github.com/near/borsh-go`: Borsh serialization/deserialization
- `github.com/urfave/cli/v3`: Command-line interface framework

### Code Structure

The project is organized into focused packages for better testability and reusability:

```
.
├── main.go                    # CLI entry point (23 lines)
├── go.mod                     # Go module definition
│
├── api/                       # Turnkey API client
│   ├── client.go              # HTTP client, CreateSignablePayload, attestation
│   ├── types.go               # Request/response types
│   └── client_test.go         # Internal tests for private methods
│
├── cmd/                       # CLI command handlers (urfave/cli)
│   ├── verify.go              # End-to-end verification command
│   ├── parse.go               # Parse transaction command
│   └── decode.go              # Decode manifest commands (raw/envelope)
│
├── manifest/                  # QoS manifest parsing and hashing
│   ├── types.go               # Manifest structures (Borsh-encoded)
│   ├── parser.go              # Borsh deserialization functions
│   ├── hash.go                # SHA256 hash computation
│   └── *_test.go              # Manifest tests
│
├── verify/                    # Attestation verification service
│   ├── service.go             # Core verification logic
│   ├── types.go               # VerifyRequest, VerifyResult
│   ├── formatter.go           # Output formatting (no printing)
│   └── *_test.go              # Verification tests
│
├── crypto/                    # Cryptographic operations
│   ├── signing.go             # ECDSA signing and verification
│   └── *_test.go              # Crypto tests
│
├── keys/                      # API key management
│   ├── loader.go              # Load keys from ~/.config/turnkey/keys/
│   └── *_test.go              # Key loading tests
│
├── bin/                       # Build output (created by make build)
│   └── turnkey-client         # Compiled binary
│
├── testdata/                  # Test fixtures (Borsh manifests)
├── Makefile                   # Build and test targets
├── verify-manifest.sh         # Automated verification script
└── README.md                  # This file
```

**Architecture Layers:**
- **CLI Layer** (`cmd/`): urfave/cli command handlers with no business logic
- **Service Layer** (`verify/`, `api/`): Business logic and API client
- **Library Layer** (all packages): Pure functions, dependency injection via interfaces
- **Testability**: All layers use interfaces for dependency injection, enabling mock testing

## Security Considerations

### Attestation Verification

The client verifies:
1. ✅ AWS Nitro attestation document signature chain
2. ✅ PCR values match expected enclave measurements
3. ✅ Certificate chain roots to AWS Nitro service
4. ✅ Timestamp is recent (can be disabled for historical data)
5. ✅ Module ID matches expected format

### Signature Verification

The client verifies:
1. ✅ ECDSA signature over the message hash
2. ✅ Public key matches the one in the attestation
3. ✅ Message hash matches the signed transaction payload
4. ✅ Signature scheme is P-256 (ephemeral key)
5. ✅ Public key is on the P-256 curve

### Manifest Integrity

The client verifies:
1. ✅ Manifest hash matches UserData in attestation (or explains mismatch)
2. ✅ Borsh deserialization succeeds without errors
3. ✅ All required fields are present and valid
4. ✅ PCR values in manifest match attestation PCRs
5. ✅ Quorum thresholds are sensible (≥ 1, ≤ member count)

## Example: Complete Verification Workflow

```bash
# 0. Build the binary
make build

# 1. Run verification and save manifest
./bin/turnkey-client verify \
  --host https://api.testkey.turnkey.com \
  --organization-id <your-org-id> \
  --key-name testkey \
  --unsigned-payload '<base64-encoded-payload>' \
  --save-qos-manifest /tmp/manifest.bin

# 2. Decode manifest with our Go client
./bin/turnkey-client decode-manifest raw --file /tmp/manifest.bin

# 3. Get JSON output from our Go client
./bin/turnkey-client decode-manifest raw --file /tmp/manifest.bin --json | jq .

# 4. Verify with Docker container (easiest method)
docker run -v /tmp:/tmp \
  ghcr.io/tkhq/qos:latest \
  qos_client display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin \
  --json | jq .

# 5. Or manually verify with reference implementation if installed locally
cd ~/projects/tkhq/qos/src/qos_client/
cargo run --bin qos_client -- display \
  --display-type manifest-envelope \
  --file-path /tmp/manifest.bin

# 6. Run automated verification (compares both implementations)
./verify-manifest.sh /tmp/manifest.bin
```

## API Key Setup

The client expects API keys in the Turnkey CLI format at `~/.config/turnkey/keys/`:

```
~/.config/turnkey/keys/<key-name>.public   # Hex-encoded compressed public key
~/.config/turnkey/keys/<key-name>.private  # Format: "hexkey:p256"
```

## Development and Library Usage

This project can be used both as a CLI tool and as a Go library for programmatic access to Turnkey's Visualsign API and attestation verification.

### Using as a Library

Import the packages you need:

```go
import (
    "context"
    "net/http"

    "github.com/anchorageoss/visualsign-turnkey-client/api"
    "github.com/anchorageoss/visualsign-turnkey-client/keys"
    "github.com/anchorageoss/visualsign-turnkey-client/verify"
)

// Create an API key provider
keyProvider := &keys.FileKeyProvider{KeyName: "my-key"}

// Create an API client
client, err := api.NewClient(
    "https://api.turnkey.com",
    &http.Client{},
    "your-org-id",
    keyProvider,
)

// Call Turnkey's Visualsign API
response, err := client.CreateSignablePayload(
    context.Background(),
    &api.CreateSignablePayloadRequest{
        UnsignedPayload: "your-payload",
        Chain:           "CHAIN_SOLANA",
    },
)

// Verify attestations
verifier := verify.NewService(verifyClient)
result, err := verifier.Verify(context.Background(), &verify.VerifyRequest{
    // ... verification request details
})
```

All packages use interfaces for dependency injection, making them easy to test and mock.

### Running Tests

```bash
# Run all tests with coverage
make test

# Run tests and view coverage report
make test-coverage

# Run tests and serve coverage interactively
make test-cover
```

### Building

```bash
# Build binary to bin/ directory
make build

# Or build directly with go
go build -o bin/turnkey-client .

# Or run directly without building
go run . <command> [args...]
```

### Adding New Features

1. **API Client**: Update `api/client.go` and `api/types.go` for API changes
2. **Manifest Parsing**: Update `manifest/types.go` for new manifest fields
3. **Verification Logic**: Update `verify/service.go` for verification changes
4. **CLI Commands**: Add command handlers to `cmd/`
5. **Tests**: Add tests in corresponding `*_test.go` files
6. **Validation**: Test against `qos_client` reference implementation using `./verify-manifest.sh`

For private method testing, add tests to the same-package `*_test.go` file (e.g., `api/client_test.go` can test `generateStamp()` which is private to the `api` package).

## References

- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
- [QuorumOS (QoS)](https://github.com/tkhq/qos) - Turnkey's secure enclave operating system
- [Borsh Specification](https://borsh.io/)
- [AWS Nitro Attestation](https://github.com/aws/aws-nitro-enclaves-nsm-api)
- [Turnkey Documentation](https://docs.turnkey.com/)

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for details.
