# Wallet Integrators Guide to VisualSign Protocol (VSP)

## Executive Summary

The VisualSign Protocol (VSP) provides cryptographically verifiable transaction signing through AWS Nitro Enclaves, ensuring
that transaction parsing and signing occur in a secure, isolated environment. This guide demonstrates how wallets can 
ncrementally integrate VSP verification, starting with basic signature validation and progressively adding stronger security
guarantees.

### Why VisualSign Protocol?

VSP protects against:
- Compromised API servers that might sign malicious transactions
- Supply chain attacks on transaction parsing code
- Man-in-the-middle attacks on transaction data
- Unauthorized modifications to the signing environment

### Incremental Integration Path

Wallets can adopt VSP verification in three progressive levels:

1. **Level 1**: Basic P256 signature verification (1-2 days implementation)
2. **Level 2**: Boot attestation with PCR validation (3-5 days implementation)
3. **Level 3**: Complete manifest verification (5-10 days implementation)

Each level provides meaningful security improvements while allowing teams to balance implementation complexity against 
ecurity requirements.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Level 1: Basic P256 Signature Verification](#level-1-basic-p256-signature-verification)
3. [Level 2: Boot Attestation with PCR Validation](#level-2-boot-attestation-with-pcr-validation)
4. [Level 3: Complete Manifest Verification](#level-3-complete-manifest-verification)
5. [API Documentation](#api-documentation)
6. [Security Considerations](#security-considerations)
7. [Production Deployment](#production-deployment)
8. [Reference Implementation](#reference-implementation)

---

## Architecture Overview

### System Components

```
[Wallet] → [Turnkey API] → [AWS Nitro Enclave]
                               ├─ QuorumOS (QoS)
                               ├─ visualsign-parser
                               └─ Ephemeral P256 Key
           ← [Signed Transaction + Attestations]
```

### Key Components

- **AWS Nitro Enclave**: Hardware-isolated compute environment that prevents even privileged users from accessing running 
ode
- **QuorumOS (QoS)**: Turnkey's secure operating system implementing threshold cryptography
- **visualsign-parser**: The application binary running inside the enclave 
[Visualsign Parser GitHub Repo](https://github.com/anchorageoss/visualsign-parser)
- **Attestations**: Cryptographic proofs of the enclave's configuration and operation

### Verification Flow

```
Transaction → API → Enclave → Parse → Sign → Return with:
                                               ├─ Signed transaction
                                               ├─ App attestation (P256 signature)
                                               ├─ Boot attestation (AWS Nitro document)
                                               └─ QoS manifest
```

---

## Level 1: Basic P256 Signature Verification

### Overview

Level 1 provides basic cryptographic verification that a transaction was signed by Turnkey's service. This level verifies 
he ECDSA P256 signature from the ephemeral key generated inside the enclave.

> **Note**: Input signature verification will be added in future versions to provide additional transaction integrity 
uarantees.

### What You Get

- ✅ Verification that transaction was signed by Turnkey
- ✅ Protection against signature forgery
- ✅ Basic integrity check on transaction data
- ✅ Minimal implementation complexity

### What You Don't Get

- ❌ No proof that signing happened in secure enclave
- ❌ No verification of enclave configuration
- ❌ Trust relies entirely on Turnkey's infrastructure

### Implementation

#### Step 1: Call the API

```go
import (
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
)

// Make API request to create signable payload
request := CreateSignablePayloadRequest{
    UnsignedPayload: base64EncodedTransaction,
    Chain:           "CHAIN_SOLANA",
}

response, err := turnkeyClient.CreateSignablePayload(request)
if err != nil {
    return err
}
```

#### Step 2: Extract App Attestation

```go
// Parse the app attestation JSON
appAttestationJSON := response.Attestations["app_attestation"]
var appAttestation struct {
    Message   string `json:"message"`
    PublicKey string `json:"publicKey"`
    Signature string `json:"signature"`
    Scheme    string `json:"scheme"`
}

err = json.Unmarshal([]byte(appAttestationJSON), &appAttestation)
if err != nil {
    return err
}
```

#### Step 3: Handle the 130-byte Public Key Format

The public key is returned as a 130-byte hex string containing two 65-byte uncompressed P256 public keys. Use the latter 65 
ytes for verification:

```go
// Decode the 130-byte hex string
publicKeyBytes, err := hex.DecodeString(appAttestation.PublicKey)
if err != nil || len(publicKeyBytes) != 130 {
    return errors.New("invalid public key format")
}

// Extract the latter 65 bytes (bytes 65-130)
publicKeyForVerification := publicKeyBytes[65:]

// Verify it's an uncompressed P256 key (starts with 0x04)
if publicKeyForVerification[0] != 0x04 {
    return errors.New("expected uncompressed public key format")
}

// Parse X and Y coordinates (32 bytes each after the 0x04 prefix)
x := new(big.Int).SetBytes(publicKeyForVerification[1:33])
y := new(big.Int).SetBytes(publicKeyForVerification[33:65])

pubKey := &ecdsa.PublicKey{
    Curve: elliptic.P256(),
    X:     x,
    Y:     y,
}
```

#### Step 4: Verify the Signature

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
)

// Decode message and signature
messageBytes, _ := hex.DecodeString(appAttestation.Message)
signatureBytes, _ := hex.DecodeString(appAttestation.Signature)

// Compute SHA256 of the message
hash := sha256.Sum256(messageBytes)

// Extract R and S components (32 bytes each)
r := new(big.Int).SetBytes(signatureBytes[:32])
s := new(big.Int).SetBytes(signatureBytes[32:64])

// Verify ECDSA signature
if !ecdsa.Verify(pubKey, hash[:], r, s) {
    return errors.New("signature verification failed")
}

fmt.Println("✓ Level 1: Signature verified successfully")
```

#### Step 5: Return the Signed Transaction

```go
// The signablePayload is ready to broadcast
signedTransaction := response.SignablePayload
return signedTransaction
```

### Testing Level 1

```go
func TestLevel1Verification(t *testing.T) {
    // Test with known valid signature
    publicKey := "04...130 hex chars..."
    message := "deadbeef..."
    signature := "a1b2c3d4..."

    valid := verifyP256Signature(publicKey, message, signature)
    assert.True(t, valid)

    // Test with tampered signature
    tamperedSig := "00000000..."
    valid = verifyP256Signature(publicKey, message, tamperedSig)
    assert.False(t, valid)
}
```

---

## Level 2: Boot Attestation with PCR Validation

### Overview

Level 2 adds cryptographic proof that transaction signing occurred inside an AWS Nitro Enclave with specific software 
onfiguration. This level verifies the boot attestation document and validates Platform Configuration Register (PCR) values.

### What You Get

- ✅ All Level 1 guarantees
- ✅ Cryptographic proof of enclave execution
- ✅ Verification of software stack via PCR values
- ✅ Protection against API compromise
- ✅ AWS-signed attestation that cannot be forged

### Understanding PCR Values

PCRs are SHA384 hashes that uniquely identify the enclave's software stack:

| PCR | Measures | Purpose |
|-----|----------|---------|
| PCR0 | Enclave image file (.eif) | Verifies exact enclave image |
| PCR1 | Linux kernel and bootstrap | Validates OS environment |
| PCR2 | Application | Confirms application code |
| PCR3 | IAM role + Instance ID | Ties to AWS identity (dynamic) |

### Implementation

#### Step 1: Install AWS Nitro Verifier

```bash
go get github.com/anchorageoss/awsnitroverifier
```

#### Step 2: Extract and Verify Boot Attestation

```go
import (
    nitroverifier "github.com/anchorageoss/awsnitroverifier"
)

// Extract boot attestation from response
bootAttestationB64 := response.Attestations["boot_attestation"]
bootAttestationBytes, err := base64.StdEncoding.DecodeString(bootAttestationB64)
if err != nil {
    return err
}

// Create verifier
verifier := nitroverifier.NewVerifier(nitroverifier.VerifierOptions{
    SkipTimestampCheck: false, // Enable timestamp validation
})

// Validate attestation document
validationResult, err := verifier.Validate(bootAttestationBytes)
if err != nil {
    return fmt.Errorf("attestation validation failed: %w", err)
}

if !validationResult.Valid {
    return fmt.Errorf("attestation invalid: %v", validationResult.Errors)
}

fmt.Println("✓ Level 2: Boot attestation verified by AWS Nitro")
```

#### Step 3: Validate PCR Values

```go
// Extract verified attestation data
attestationDoc := validationResult.Document

// Define approved PCR values
// These values should be obtained from Turnkey documentation
// or from your own enclave builds
approvedPCRs := map[uint]string{
    0: "f67076a8f9796b90d7f0eb148ec6926f66fe04c80861151916961f7dec715b3c",
    1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b",
    2: "4c495bf7c91e69f0aced18c8f7f6b9038e3aaa5c4b8a4e6d5b9b7ee1e55c5e3f",
    // PCR3 is dynamic - either skip or validate pattern
}

// Verify each PCR
for idx, expectedHash := range approvedPCRs {
    actualPCR := attestationDoc.PCRs[idx]
    actualHash := hex.EncodeToString(actualPCR)

    if actualHash != expectedHash {
        return fmt.Errorf("PCR[%d] mismatch: expected %s, got %s",
            idx, expectedHash, actualHash)
    }
}

fmt.Printf("✓ Level 2: All PCR values validated\n")
fmt.Printf("  Module ID: %s\n", attestationDoc.ModuleID)
fmt.Printf("  PCR0: %x...\n", attestationDoc.PCRs[0][:8])
fmt.Printf("  UserData: %x\n", attestationDoc.UserData)
```

#### Step 4: Maintain PCR Allowlist

```go
// PCR values change when enclave software is updated
// Implement a versioning strategy for transitions

type PCRSet struct {
    PCR0      string
    PCR1      string
    PCR2      string
    ValidFrom time.Time
    ValidUntil time.Time
}

var approvedPCRSets = []PCRSet{
    {
        PCR0: "f67076a8f9796b90d7f0eb148ec6926f66fe04c80861151916961f7dec715b3c",
        PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b",
        PCR2: "4c495bf7c91e69f0aced18c8f7f6b9038e3aaa5c4b8a4e6d5b9b7ee1e55c5e3f",
        ValidFrom: time.Parse("2025-01-01"),
        ValidUntil: time.Parse("2025-06-01"),
    },
    // Add new sets during software updates
}

func validatePCRs(pcrs map[uint][]byte) error {
    now := time.Now()
    for _, pcrSet := range approvedPCRSets {
        if now.After(pcrSet.ValidFrom) && now.Before(pcrSet.ValidUntil) {
            if matchesPCRSet(pcrs, pcrSet) {
                return nil
            }
        }
    }
    return errors.New("no matching PCR set found")
}
```

### Building visualsign-parser

To independently verify PCR2, you can build the visualsign-parser from source:

```bash
# Clone the repository
git clone https://github.com/anchorageoss/visualsign-parser
cd visualsign-parser

# Build the binary
make build

# Compute SHA256 (this should match Pivot.Hash in manifest)
sha256sum build/visualsign-parser
```

---

## Level 3: Complete Manifest Verification

### Overview

Level 3 provides complete verification of the enclave configuration through the QuorumOS (QoS) manifest. This level 
alidates that the specific visualsign-parser binary is running with the expected configuration and security policies.

### What You Get

- ✅ All Level 1 & 2 guarantees
- ✅ Verification of exact application binary (SHA256)
- ✅ Protection against unauthorized manifest updates
- ✅ Complete zero-trust verification
- ✅ Ability to reproduce PCR values independently

### Understanding the QoS Manifest

The manifest is a Borsh-encoded security policy containing:

```
Manifest Structure:
├── Namespace
│   └── Name: "testkey/anchorageoss/visualsign-parser"
├── Pivot (Application Config)
│   ├── Hash: SHA256 of visualsign-parser binary ← THIS IS THE SHA256SUM
│   ├── Restart: Policy (Always/Never)
│   └── Args: Command line arguments
├── Enclave (Nitro Config)
│   ├── PCR0-3: Expected PCR values
│   └── QosCommit: Git commit of QuorumOS
└── Quorum Sets
    ├── ManifestSet: Who can update manifest
    └── ShareSet: Key share holders
```

### Where to Find the SHA256sum

The SHA256 hash of the visualsign-parser binary is stored in the **`Pivot.Hash`** field of the manifest. This 32-byte value 
niquely identifies the exact application binary running in the enclave.

### Implementation

#### Step 1: Extract Manifest from Response

```go
// Get manifest envelope (includes approval signatures)
manifestEnvelopeB64 := response.BootProof.QosManifestEnvelopeB64

// Also available: raw manifest without signatures
rawManifestB64 := response.BootProof.QosManifestB64
```

#### Step 2: Decode Manifest from Borsh

```go
import (
    "github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// Decode the manifest envelope
envelope, manifestStruct, manifestBytes, _, err :=
    manifest.DecodeManifestEnvelopeFromBase64(manifestEnvelopeB64)
if err != nil {
    // Try raw manifest if envelope fails
    manifestStruct, manifestBytes, err =
        manifest.DecodeRawManifestFromBase64(rawManifestB64)
    if err != nil {
        return err
    }
}
```

#### Step 3: Verify Manifest Hash Against UserData

The UserData field in the boot attestation contains the SHA256 hash of the manifest:

```go
// Compute SHA256 of manifest
manifestHash := sha256.Sum256(manifestBytes)
manifestHashHex := hex.EncodeToString(manifestHash[:])

// Get UserData from boot attestation (from Level 2)
userDataHex := hex.EncodeToString(attestationDoc.UserData)

// Verify they match
if manifestHashHex != userDataHex {
    return fmt.Errorf("manifest hash mismatch: computed %s, attestation has %s",
        manifestHashHex, userDataHex)
}

fmt.Println("✓ Level 3: Manifest hash verified against boot attestation")
```

#### Step 4: Validate visualsign-parser Binary Hash

```go
// Extract the SHA256 hash of visualsign-parser binary
pivotHash := hex.EncodeToString(manifestStruct.Pivot.Hash[:])
fmt.Printf("visualsign-parser SHA256: %s\n", pivotHash)

// Verify against expected hash
// This hash can be computed independently by building visualsign-parser
expectedBinaryHash := "ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678"
if pivotHash != expectedBinaryHash {
    return fmt.Errorf("visualsign-parser binary hash mismatch")
}

// Verify namespace
expectedNamespace := "testkey/anchorageoss/visualsign-parser"
if manifestStruct.Namespace.Name != expectedNamespace {
    return fmt.Errorf("unexpected namespace: %s", manifestStruct.Namespace.Name)
}

fmt.Println("✓ Level 3: visualsign-parser binary verified")
```

#### Step 5: Validate PCRs from Manifest

```go
// Compare manifest PCRs with attestation PCRs
manifestPCRs := map[uint][]byte{
    0: manifestStruct.Enclave.Pcr0,
    1: manifestStruct.Enclave.Pcr1,
    2: manifestStruct.Enclave.Pcr2,
    3: manifestStruct.Enclave.Pcr3,
}

for idx, expectedPCR := range manifestPCRs {
    actualPCR := attestationDoc.PCRs[idx]

    if !bytes.Equal(expectedPCR, actualPCR) {
        return fmt.Errorf("PCR[%d] mismatch between manifest and attestation", idx)
    }
}

fmt.Println("✓ Level 3: All PCRs match between manifest and attestation")
```

#### Step 6: Monitor Manifest Updates

```go
// Store and monitor manifest hashes for changes
type ManifestTracker struct {
    CurrentHash  string
    PreviousHash string
    LastUpdated  time.Time
}

func (m *ManifestTracker) CheckManifestUpdate(newHash string) {
    if newHash != m.CurrentHash {
        // Manifest has changed!
        log.Warn("MANIFEST UPDATE DETECTED",
            "previous", m.CurrentHash,
            "new", newHash,
            "timestamp", time.Now())

        // Alert security team
        alertSecurityTeam("Manifest updated", newHash)

        // Require manual approval before accepting
        if !approveManifestUpdate(newHash) {
            panic("Unapproved manifest update")
        }

        m.PreviousHash = m.CurrentHash
        m.CurrentHash = newHash
        m.LastUpdated = time.Now()
    }
}
```

### Reproducing the SHA256

To independently verify the visualsign-parser binary hash:

```bash
# Clone and build visualsign-parser
git clone https://github.com/anchorageoss/visualsign-parser
cd visualsign-parser
make build

# Compute SHA256
sha256sum build/visualsign-parser
# Output: ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678

# This hash should match Pivot.Hash in the manifest
```

---

## API Documentation

### Authentication

Turnkey API uses ECDSA P256 signatures for authentication:

```go
// Generate authentication stamp
func generateAuthStamp(privateKey *ecdsa.PrivateKey, requestBody []byte) (string, error) {
    // Hash the request body
    hash := sha256.Sum256(requestBody)

    // Sign with private key
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        return "", err
    }

    // Encode signature
    signature := append(r.Bytes(), s.Bytes()...)

    // Create stamp JSON
    stamp := map[string]string{
        "publicKey": hex.EncodeToString(compressPublicKey(privateKey.PublicKey)),
        "signature": hex.EncodeToString(signature),
        "scheme":    "SIGNATURE_SCHEME_TK_API_P256",
    }

    stampJSON, _ := json.Marshal(stamp)
    return base64.StdEncoding.EncodeToString(stampJSON), nil
}
```

### API Endpoints

**Create Signable Payload**
```
POST /visualsign/api/v1/parse
Host: api.turnkey.com
Content-Type: application/json
X-Stamp: <authentication-stamp>

{
  "unsignedPayload": "<base64-transaction>",
  "chain": "CHAIN_SOLANA"
}
```

**Response Structure**
```json
{
  "signablePayload": "<hex-signed-transaction>",
  "attestations": {
    "app_attestation": "<json-p256-signature>",
    "boot_attestation": "<base64-nitro-document>"
  },
  "bootProof": {
    "qosManifestB64": "<base64-raw-manifest>",
    "qosManifestEnvelopeB64": "<base64-manifest-with-signatures>"
  }
}
```

---

## Security Considerations

### Overview

This section covers security considerations specific to the VisualSign Protocol. For general application security practices, refer to:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

### Reference Implementation

The complete verification implementation is available in the [`verify/service.go`](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go) file. Key verification steps:

- [Boot attestation validation](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L95-L109) (Level 2)
- [Manifest processing and hash verification](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L251-L343) (Level 3)
- [ECDSA signature verification](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L150-L160) (All levels)

---

### Security Comparison by Level

| Threat | Level 1 | Level 2 | Level 3 |
|--------|---------|---------|---------|
| Signature Forgery | ✅ Protected | ✅ Protected | ✅ Protected |
| Compromised Service Provider | ❌ Vulnerable | ✅ Protected | ✅ Protected |
| Malicious Enclave | ❌ Vulnerable | ⚠️ Partial | ✅ Protected |
| Binary Substitution | ❌ Vulnerable | ❌ Vulnerable | ✅ Protected |
| Unauthorized Updates | ❌ Vulnerable | ❌ Vulnerable | ✅ Protected |

---

### Threat Model Analysis

#### Assets Protected

1. **Enclave Ephemeral Private Key**: Generated inside enclave, never leaves secure environment
2. **Transaction Integrity**: What is signed matches what was parsed
3. **Execution Environment**: Verified code runs in isolated enclave
4. **Signing Operations**: Cannot be tampered with or replayed

> **Note**: The VisualSign Protocol protects the ephemeral signing key generated inside the enclave. User's long-term private keys are managed separately by the wallet's key management system.

#### Threat Actors

| Actor | Capabilities | Mitigated By |
|-------|--------------|--------------|
| **Network Attacker** | MITM, replay, tampering | TLS 1.3 + timestamp validation + attestation binding |
| **Compromised API Server** | Serve malicious responses | Level 2+ (Boot attestation verification) |
| **Malicious Insider** | Replace enclave code | Level 3 (Manifest + PCR validation) |
| **Supply Chain Attack** | Malicious dependencies | Level 3 (Hash verification + PCR validation) |
| **Physical Access** | Hardware tampering | AWS Nitro hardware security |

---

### Attack Vectors and Mitigations

#### 1. Compromised Service Provider

**Attack**: If the service provider infrastructure is compromised, attackers could attempt to return malicious signatures

**Protection by Level**:
- **Level 1**: ❌ No protection - trusts service provider completely
- **Level 2**: ✅ Protected - AWS-signed attestation cannot be forged by service provider
- **Level 3**: ✅ Protected - Full manifest verification ensures correct code is running

**Why Level 2+ Works**:

The Nitro attestation document is signed by AWS hardware, not the service provider. A compromised service provider infrastructure cannot:
- Forge AWS signatures (requires AWS root key)
- Generate valid attestations for unauthorized code
- Modify PCR values without detection

This is the core security property of the VisualSign Protocol: cryptographic proof that the signing operation occurred in a verified enclave, independent of service provider infrastructure security.

#### 2. Binary Substitution Attack

**Attack**: Replace visualsign-parser with a malicious version that signs unauthorized transactions

**Protection by Level**:
- **Level 1**: ❌ No detection - doesn't verify binary
- **Level 2**: ⚠️ Partial - PCRs change if enclave image changes, but don't identify the specific binary
- **Level 3**: ✅ Protected - Pivot.Hash in manifest contains exact SHA256 of authorized binary

**Implementation**: See [`verifyUserData`](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L236-L248) and [`processManifest`](https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L251-L343) in the reference implementation.

```go
// Level 3: Verify exact binary
expectedHash := "ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678"
actualHash := hex.EncodeToString(manifestStruct.Pivot.Hash[:])

if actualHash != expectedHash {
    return fmt.Errorf("SECURITY: Unauthorized binary detected! Expected %s, got %s",
        expectedHash, actualHash)
}
```

#### 3. Replay Attacks

**Attack**: Reuse valid attestation documents to sign different transactions

**Mitigations**:
- Timestamp validation in Nitro attestation (automatically checked by [`awsnitroverifier`](https://github.com/anchorageoss/awsnitroverifier))
- Short-lived ephemeral keys (rotated per session)
- UserData field binds attestation to specific manifest

**Implementation**:
```go
// Enable timestamp validation
verifier := nitroverifier.NewVerifier(nitroverifier.VerifierOptions{
    SkipTimestampCheck: false, // MUST be false in production
})

// Validate timestamp is recent
maxAge := 5 * time.Minute
if time.Since(validationResult.Document.Timestamp) > maxAge {
    return errors.New("attestation too old")
}
```

**Recommended Policy**:
- Maximum attestation age: 5 minutes for standard transactions
- Maximum attestation age: 1 minute for high-value transactions
- Clock skew tolerance: ±30 seconds

#### 4. Manifest Manipulation

**Attack**: Attacker updates manifest to authorize malicious code

**Mitigations**:
- Manifest hash embedded in UserData field of Nitro attestation
- UserData is measured by AWS hardware and signed by AWS root key
- Manifest updates require quorum approval (defined in ManifestSet)
- Client-side monitoring detects unexpected manifest changes

**Implementation**:
```go
type ManifestPolicy struct {
    ApprovedHashes  []string
    AlertOnChange   bool
    RequireApproval bool
}

func (p *ManifestPolicy) ValidateManifest(manifestBytes []byte) error {
    hash := sha256.Sum256(manifestBytes)
    hashHex := hex.EncodeToString(hash[:])

    // Check against approved hashes
    for _, approved := range p.ApprovedHashes {
        if hashHex == approved {
            return nil
        }
    }

    if p.RequireApproval {
        return fmt.Errorf("manifest %s not in approved list", hashHex)
    }

    if p.AlertOnChange {
        log.Warn("Unknown manifest detected", "hash", hashHex)
    }

    return nil
}
```

#### 5. Downgrade Attacks

**Attack**: Force wallet to use lower verification level

**Mitigations**:
- Verification level configured server-side, not negotiated
- No fallback mechanism from higher to lower levels
- Monitoring alerts on verification failures

**Implementation**:
```go
const RequiredLevel = 3 // Compile-time constant

func VerifyTransaction(config VerificationConfig, response Response) error {
    if config.Level < RequiredLevel {
        return fmt.Errorf("SECURITY: Verification level %d below required level %d",
            config.Level, RequiredLevel)
    }

    // No fallback logic - fail if verification fails
    return verifyAtLevel(config.Level, response)
}
```

---

### Cryptographic Guarantees

#### ECDSA P256 Signatures

**Algorithm**: ECDSA with P-256 curve (secp256r1)

**Security Properties**:
- **Unforgeability**: Cannot create valid signature without private key
- **Non-repudiation**: Signature proves transaction was signed by specific key
- **Integrity**: Any modification invalidates signature

**Key Generation**: Ephemeral key pair generated inside Nitro Enclave at session start

**Strength**: 128-bit security level (equivalent to 3072-bit RSA)

#### SHA256 and SHA384 Hashing

**Usage**:
- Manifest integrity (UserData field) - SHA256
- Binary verification (Pivot.Hash) - SHA256
- PCR measurements - SHA384
- Message hashing for ECDSA signatures - SHA256

**Strength**: 128-bit and 192-bit security levels respectively

#### AWS Nitro Attestation Document

**Signature Algorithm**: RSA-4096 with SHA384

**Certificate Chain**:
```
AWS Root CA
  └─ AWS Nitro Attestation CA (region-specific)
      └─ Enclave-specific certificate (ephemeral)
```

**Security Properties**:
- Root certificate embedded in AWS Nitro Verifier library
- Signature cannot be forged without AWS private key
- PCR values measured by hardware, not software
- Timestamp prevents replay attacks

**Documentation**: See [Turnkey Boot Proofs](https://docs.rs/turnkey_proofs/latest/turnkey_proofs/#boot-proofs) for detailed attestation structure.

---

### Understanding PCR Measurements

PCR (Platform Configuration Register) values are SHA-384 hashes that uniquely identify the enclave's configuration. According to the [AWS Nitro Enclaves documentation](https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf):

| PCR | Measures | Security Property |
|-----|----------|-------------------|
| **PCR0** | Hash over kernel, command line, and all ramdisk sections | Verifies complete enclave image |
| **PCR1** | Hash over kernel, command line, and first ramdisk | Validates boot environment |
| **PCR2** | Hash over subsequent ramdisk sections | Confirms additional components |
| **PCR3** | IAM role + Instance ID | Ties to AWS identity (dynamic) |

#### Important PCR Limitations

As documented in the [Trail of Bits analysis](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/), PCR measurements have limitations:

- **Section Concatenation**: PCRs concatenate section data without domain separation, meaning "bytes can be moved between adjacent sections without changing PCRs"
- **Metadata Exclusion**: The metadata section of EIF files is not attested
- **Parser Discrepancies**: The public `nitro-cli describe-eif` parser may differ from the hypervisor parser

**Security Recommendations**:
1. Verify PCR0, PCR1, and PCR2 together (not in isolation)
2. For strongest guarantees, use Level 3 with manifest verification (Pivot.Hash)
3. Skip PCR3 validation as it changes per instance
4. Do not rely solely on PCRs for binary identification - use manifest Pivot.Hash

#### PCR Verification in Practice

```go
// Level 2: Validate PCRs from attestation
// See: https://github.com/anchorageoss/visualsign-turnkeyclient/blob/24886a1a9e5cb4f39b8f88cd9c0ef31603074683/verify/service.go#L107
result.PCRs = validationResult.Document.PCRs

// Define approved PCR values (PCR0, PCR1, PCR2)
approvedPCRs := map[uint]string{
    0: "f67076a8f9796b90d7f0eb148ec6926f66fe04c80861151916961f7dec715b3c",
    1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b",
    2: "4c495bf7c91e69f0aced18c8f7f6b9038e3aaa5c4b8a4e6d5b9b7ee1e55c5e3f",
    // Skip PCR3 - it's dynamic per instance
}

// Verify each PCR
for idx, expectedHash := range approvedPCRs {
    actualHash := hex.EncodeToString(attestationDoc.PCRs[idx])
    if actualHash != expectedHash {
        return fmt.Errorf("PCR[%d] mismatch", idx)
    }
}
```

---

### Key Management

#### Ephemeral Key Lifecycle

**Generation**: Inside Nitro Enclave at session start
**Usage**: Sign single transaction or batch
**Destruction**: Automatically destroyed when enclave terminates
**Rotation**: New key pair for each session

**Security Benefits**:
- Limited blast radius if key somehow compromised
- No long-term key storage in enclave
- Cannot sign historical transactions with current key
- Fresh key for each signing operation

#### Public Key Verification Order

**CRITICAL**: Always verify attestation before trusting the public key

```go
// WRONG - trusts public key without attestation:
publicKey := extractPublicKey(response.AppAttestation)
valid := verifySignature(publicKey, message, signature) // INSECURE!

// CORRECT - attestation verified first:
if err := verifyBootAttestation(response); err != nil {
    return err
}
if err := verifyManifest(response); err != nil {
    return err
}
publicKey := extractPublicKey(response.AppAttestation)
valid := verifySignature(publicKey, message, signature)
```

The attestation verification proves that the public key was generated inside a legitimate enclave running authorized code.

---

### Network Security

#### TLS Configuration

**Requirements**:
- TLS 1.3 required
- Certificate validation enabled
- Hostname verification enabled

**Implementation**:
```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
}

// Optional: Certificate pinning for additional security
tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    return verifyPinnedCertificate(rawCerts[0])
}
```

---

### Operational Security

#### Monitoring and Alerting

**Critical Events to Monitor**:

1. **Manifest Changes**
```go
if manifestHash != expectedManifestHash {
    alert := SecurityAlert{
        Severity: "CRITICAL",
        Type:     "MANIFEST_CHANGE",
        Details: map[string]string{
            "expected": expectedManifestHash,
            "actual":   manifestHash,
        },
    }
    sendSecurityAlert(alert)
}
```

2. **Verification Failures**
```go
// Track failure rate
metrics.Counter("verification.failure",
    "level", verificationLevel,
    "reason", failureReason)

if failureRate > 0.01 { // 1% threshold
    alertSecurityTeam("High verification failure rate", failureRate)
}
```

3. **PCR Mismatches**
```go
if !validatePCRs(attestation.PCRs) {
    // PCR mismatch is CRITICAL - could indicate compromise
    sendSecurityAlert(SecurityAlert{
        Severity: "CRITICAL",
        Type:     "PCR_MISMATCH",
        Details:  extractPCRDetails(attestation),
    })
    return errors.New("SECURITY: PCR validation failed")
}
```

#### Security Event Logging

**Required Logs**:
```go
// Log all verification attempts
logger.Info("verification_attempt",
    "level", verificationLevel,
    "tx_id", transactionID)

// Log verification results
logger.Info("verification_result",
    "level", verificationLevel,
    "result", "success",
    "duration_ms", durationMs)

// Log security-critical events
logger.Warn("manifest_validation",
    "manifest_hash", manifestHash,
    "approved", isApproved)
```

**Retention**:
- Security logs: 1 year minimum
- Audit logs: 7 years for compliance requirements
- Encrypt logs at rest

#### PCR and Manifest Management

**Version Management**:
```go
type PCRSet struct {
    PCR0       string
    PCR1       string
    PCR2       string
    ValidFrom  time.Time
    ValidUntil time.Time
}

var approvedPCRSets = []PCRSet{
    {
        PCR0:       "f67076a8...",
        PCR1:       "bcdf05fe...",
        PCR2:       "4c495bf7...",
        ValidFrom:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
        ValidUntil: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
    },
    // Add new sets during software updates with overlap period
}
```

**Update Process**:
1. Receive notification of new manifest from service provider
2. Verify new manifest through independent channel
3. Add new manifest hash to approved list
4. Deploy configuration update
5. Monitor for successful transitions
6. Remove old manifest after grace period

---

### Testing and Validation

#### Security Test Coverage

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

#### Recommended Security Testing

- **Unit Tests**: Comprehensive test coverage for all verification levels
- **Integration Tests**: End-to-end verification with real API responses
- **Penetration Testing**: Annual testing focusing on protocol-specific attacks
- **Dependency Scanning**: Regular scanning for vulnerable dependencies
- **Static Analysis**: Code scanning for security vulnerabilities

---

### Known Limitations

#### 1. Trust in AWS Nitro Hardware

**Assumption**: AWS Nitro hardware is not compromised

**Mitigation**: AWS Nitro has undergone independent security audits. Monitor [AWS security bulletins](https://aws.amazon.com/security/) for updates.

#### 2. PCR3 Variability

**Issue**: PCR3 includes IAM role and instance ID, which are dynamic per enclave instance

**Mitigation**: Skip PCR3 validation; focus on PCR0-2 for software verification

#### 3. PCR Limitations

**Issue**: As noted in the [Trail of Bits analysis](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/), PCRs have structural limitations with section concatenation

**Mitigation**: Use Level 3 with manifest Pivot.Hash for strongest binary verification guarantees

#### 4. Build Reproducibility

**Issue**: Exact binary reproducibility requires identical build environment

**Current State**: visualsign-parser builds are not fully reproducible; must trust published hashes

**Future**: Work toward deterministic builds and multi-party verification

#### 5. No Input Signature Verification (Level 1)

**Current State**: Input signature verification not yet implemented in Level 1

**Roadmap**: Future versions will include input signature verification

---

### Compliance Considerations

#### Financial Services Regulations

**Recommended Configuration**:
- **Level 3 verification** for regulated financial activities
- Complete audit trail of verification operations
- Annual security audits and penetration testing
- Incident response procedures

**Relevant Standards**:
- SOC 2 Type II
- PCI DSS (if handling payment cards)
- MiCA (EU Crypto-Assets Regulation)
- GDPR (EU data protection)

Consult your compliance team for specific requirements.

---

### Trust Model

```
Fully Trusted (Required for Security):
├── AWS Nitro hardware and firmware
├── AWS root certificates
├── Your verification code
└── Operating system running verification

Verified Through Attestation (Zero-Trust):
├── Service provider API (verified via attestation)
├── QuorumOS manifest (verified via UserData)
├── visualsign-parser binary (verified via Pivot.Hash)
└── Enclave configuration (verified via PCRs)

Not Trusted (Assume Hostile):
├── Network communication (until TLS verified)
├── Service provider infrastructure (until attestation verified)
└── Any component not explicitly verified
```

**Key Principle**: "Never trust, always verify" - All components are verified cryptographically through attestation chains rooted in AWS hardware.

---

### Best Practices Summary

#### Development Phase
✅ Start with Level 1 for initial integration
✅ Write comprehensive tests for all verification levels
✅ Use testnet for testing
✅ Implement proper error handling

#### Production Deployment
✅ **Use Level 2 minimum**, Level 3 strongly recommended
✅ Enable timestamp validation (do not skip)
✅ Configure TLS 1.3
✅ Implement monitoring and alerting
✅ Maintain approved PCR/manifest lists
✅ Document security procedures

#### Production Operations
✅ Monitor verification success rates
✅ Alert on manifest changes
✅ Regular security log review
✅ Coordinate with service provider on updates
✅ Annual security assessments

---

### Additional Security Resources

- **AWS Nitro Enclaves**: [Official Documentation (PDF)](https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf)
- **Turnkey Boot Proofs**: [turnkey_proofs Rust crate documentation](https://docs.rs/turnkey_proofs/latest/turnkey_proofs/#boot-proofs)
- **PCR Analysis**: [Trail of Bits: AWS Nitro Enclaves Images and Attestation](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/)
- **Reference Implementation**: [visualsign-turnkeyclient on GitHub](https://github.com/anchorageoss/visualsign-turnkeyclient)

---

### Security Contact

For security concerns or vulnerability reports:
- **visualsign-turnkeyclient**: [GitHub Security Advisories](https://github.com/anchorageoss/visualsign-turnkeyclient/security)
- **Turnkey API**: Contact Turnkey support
- **AWS Nitro**: [AWS Security Center](https://aws.amazon.com/security/)

**Responsible Disclosure**: Report security vulnerabilities privately before public disclosure

---

## Production Deployment

### Configuration Example

```yaml
verification:
  level: 3  # 1, 2, or 3

  # Level 2: PCR validation
  approved_pcr_sets:
    - pcr0: "f67076a8f9796b90d7f0eb148ec6926f66fe04c80861151916961f7dec715b3c"
      pcr1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b"
      pcr2: "4c495bf7c91e69f0aced18c8f7f6b9038e3aaa5c4b8a4e6d5b9b7ee1e55c5e3f"
      valid_until: "2025-06-01"

  # Level 3: Manifest validation
  approved_manifest_hashes:
    - "60d9c5754d6979afca7a5e75edfa43b629110301d8c57f9ff1718b74f70b5a9c"

  # Expected binary hash
  visualsign_parser_hash: "ef9f552a75bf22c7556b9900bae09f3557eb46f9123b00f94fe71baa8656e678"
```

### Monitoring

```go
// Track verification metrics
metrics.Counter("wallet.verification.success", tags{"level": "3"})
metrics.Counter("wallet.verification.failure", tags{"level": "3", "reason": "pcr_mismatch"})
metrics.Histogram("wallet.verification.duration_ms")

// Alert on anomalies
if manifestHash != expectedHash {
    metrics.Counter("wallet.security.manifest_change")
    alertSecurityTeam("Manifest changed", manifestHash)
}
```

### Migration Strategy

To upgrade from Level 1 → 2 → 3:

```go
// Run new level in shadow mode first
func verify(response Response) error {
    // Current production level
    if err := verifyLevel2(response); err != nil {
        return err
    }

    // Shadow mode for next level
    go func() {
        if err := verifyLevel3(response); err != nil {
            log.Warn("Level 3 would fail", "error", err)
            metrics.Counter("wallet.shadow.level3.failure")
        }
    }()

    return nil
}
```

---

## Reference Implementation

The complete reference implementation is available at:
https://github.com/anchorageoss/visualsign-turnkeyclient

### Key Files

- `verify/service.go`: Core verification logic for all levels
- `manifest/parser.go`: Borsh deserialization for Level 3
- `manifest/types.go`: Manifest structure definitions
- `cmd/verify.go`: CLI command implementation

### Running the Reference

```bash
# Clone the repository
git clone https://github.com/anchorageoss/visualsign-turnkeyclient
cd visualsign-turnkeyclient

# Build
make build

# Run verification (all levels)
./bin/visualsign-turnkeyclient verify \
  --host https://api.turnkey.com \
  --organization-id <your-org-id> \
  --key-name <your-key> \
  --unsigned-payload <base64-payload> \
  --qos-manifest-hex <expected-manifest-hash> \
  --debug

# Decode manifest for inspection
./bin/visualsign-turnkeyclient decode-manifest envelope \
  --file manifest.bin --json
```

### Testing

```bash
# Run unit tests
make test

# Run with test vectors
go test ./verify -run TestVerificationLevels
```

---

## Additional Resources

- **visualsign-parser**: https://github.com/anchorageoss/visualsign-parser
- **QuorumOS Documentation**: https://github.com/tkhq/qos
- **AWS Nitro Enclaves**: https://aws.amazon.com/ec2/nitro/nitro-enclaves/
- **Turnkey Documentation**: https://docs.turnkey.com/
- **Reference Client**: https://github.com/anchorageoss/visualsign-turnkeyclient

---

## Quick Decision Guide

Choose your integration level based on:

| Factor | Level 1 | Level 2 | Level 3 |
|--------|---------|---------|---------|
| **Implementation Time** | 1-2 days | 3-5 days | 5-10 days |
| **Security Level** | Basic | High | Maximum |
| **Transaction Value** | < $1K | < $100K | Any amount |
| **Regulatory Compliance** | No | Limited | Yes |
| **Trust Model** | Trust Turnkey | Trust AWS | Zero-trust |

---

## Support

For questions or issues:
- Open an issue on the reference implementation repository
- Contact Turnkey support for API-related questions
- Review the QuorumOS documentation for manifest details

---

*This guide is maintained by the VisualSign Protocol team and updated regularly as the protocol evolves.*