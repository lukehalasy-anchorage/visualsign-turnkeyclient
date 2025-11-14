# Threat Model Analysis

## Assets Protected

1. **Enclave Ephemeral Private Key**: Generated inside enclave, never leaves secure environment
2. **Transaction Integrity**: What is signed matches what was parsed
3. **Execution Environment**: Verified code runs in isolated enclave
4. **Signing Operations**: Cannot be tampered with or replayed

> **Note**: The VisualSign Protocol protects the ephemeral signing key generated inside the enclave. User's long-term private keys are managed separately by the wallet's key management system.

## Threat Actors

| Actor | Capabilities | Mitigated By |
|-------|--------------|--------------|
| **Network Attacker** | MITM, replay, tampering | TLS 1.3 + timestamp validation + attestation binding |
| **Compromised API Server** | Serve malicious responses | Level 2+ (Boot attestation verification) |
| **Malicious Insider** | Replace enclave code | Level 3 (Manifest + PCR validation) |
| **Supply Chain Attack** | Malicious dependencies | Level 3 (Hash verification + PCR validation) |
| **Physical Access** | Hardware tampering | AWS Nitro hardware security |

---

## Attack Vectors and Mitigations

### 1. Compromised Service Provider

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

### 2. Binary Substitution Attack

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

### 3. Replay Attacks

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

### 4. Manifest Manipulation

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

### 5. Downgrade Attacks

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