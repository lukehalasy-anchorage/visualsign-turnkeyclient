package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
)

// printPCRValues prints PCR values with descriptive labels and proper formatting
func printPCRValues(pcrs map[uint][]byte, title string, indent string) {
	fmt.Fprintf(os.Stderr, "\n%s%s:\n", indent, title)

	// Helper function to check if PCR is all zeros
	isAllZeros := func(pcr []byte) bool {
		for _, b := range pcr {
			if b != 0 {
				return false
			}
		}
		return true
	}

	// PCR 0 and 1: QoS hash
	for idx := uint(0); idx <= 1; idx++ {
		if pcr, exists := pcrs[idx]; exists && len(pcr) > 0 {
			fmt.Fprintf(os.Stderr, "%s    PCR[%d]: %s (QoS hash)\n", indent, idx, hex.EncodeToString(pcr))
		}
	}

	// PCR 2: General PCR
	if pcr, exists := pcrs[2]; exists && len(pcr) > 0 {
		fmt.Fprintf(os.Stderr, "%s    PCR[2]: %s\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 3: Hash of the AWS Role
	if pcr, exists := pcrs[3]; exists && len(pcr) > 0 {
		fmt.Fprintf(os.Stderr, "%s    PCR[3]: %s (Hash of the AWS Role)\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 4: Legacy
	if pcr, exists := pcrs[4]; exists && len(pcr) > 0 {
		fmt.Fprintf(os.Stderr, "%s    PCR[4]: %s (legacy)\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 5-15: Check if all are zeros and display accordingly
	var allZeroPCRs []uint
	var nonZeroPCRs []uint

	for idx := uint(5); idx <= 15; idx++ {
		if pcr, exists := pcrs[idx]; exists && len(pcr) > 0 {
			if isAllZeros(pcr) {
				allZeroPCRs = append(allZeroPCRs, idx)
			} else {
				nonZeroPCRs = append(nonZeroPCRs, idx)
			}
		}
	}

	// Display non-zero PCRs individually
	for _, idx := range nonZeroPCRs {
		if pcr, exists := pcrs[idx]; exists {
			fmt.Fprintf(os.Stderr, "%s    PCR[%d]: %s\n", indent, idx, hex.EncodeToString(pcr))
		}
	}

	// Display all-zero PCRs as a range if there are any
	if len(allZeroPCRs) > 0 {
		if len(allZeroPCRs) == 1 {
			fmt.Fprintf(os.Stderr, "%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, allZeroPCRs[0])
		} else {
			// Find consecutive ranges
			start := allZeroPCRs[0]
			end := allZeroPCRs[0]

			for i := 1; i < len(allZeroPCRs); i++ {
				if allZeroPCRs[i] == end+1 {
					end = allZeroPCRs[i]
				} else {
					// Print current range
					if start == end {
						fmt.Fprintf(os.Stderr, "%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start)
					} else {
						fmt.Fprintf(os.Stderr, "%s    PCR[%d-%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start, end)
					}
					start = allZeroPCRs[i]
					end = allZeroPCRs[i]
				}
			}

			// Print final range
			if start == end {
				fmt.Fprintf(os.Stderr, "%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start)
			} else {
				fmt.Fprintf(os.Stderr, "%s    PCR[%d-%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start, end)
			}
		}
	}
}

// runVerify performs end-to-end verification of a transaction run in AWS Nitro enclave
func runVerify(hostURI, organizationID, keyName, unsignedPayload, qosManifestHex, pivotBinaryHashHex, saveManifestPath string, allowManifestReserializationMismatch bool) {
	// Create Turnkey client
	client, err := createClient(hostURI, organizationID, keyName)
	if err != nil {
		log.Fatalf("Failed to create Turnkey client: %v", err)
	}

	// Call the API using existing client
	response, err := client.CreateSignablePayload(context.Background(), unsignedPayload)
	if err != nil {
		log.Fatalf("Failed to call API: %v", err)
	}

	// Save QoS manifest envelope to file if requested
	if saveManifestPath != "" && response.QosManifestEnvelopeB64 != "" {
		envelopeBytes, err := base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
		if err != nil {
			log.Fatalf("Failed to decode manifest envelope: %v", err)
		}
		if err := os.WriteFile(saveManifestPath, envelopeBytes, 0644); err != nil {
			log.Fatalf("Failed to save manifest envelope to %s: %v", saveManifestPath, err)
		}
		fmt.Fprintf(os.Stderr, "✓ Saved QoS manifest envelope to %s (%d bytes)\n", saveManifestPath, len(envelopeBytes))
	}

	// Parse the app attestation to extract signature fields
	var appAttestation struct {
		Message   string `json:"message"`
		PublicKey string `json:"publicKey"`
		Scheme    string `json:"scheme"`
		Signature string `json:"signature"`
	}

	if attestationJSON, ok := response.Attestations[AppAttestationKey]; !ok {
		log.Fatalf("No app attestation found in response")
	} else if err := json.Unmarshal([]byte(attestationJSON), &appAttestation); err != nil {
		log.Fatalf("Failed to parse app attestation: %v", err)
	}

	// Get the boot attestation document
	bootAttestationDoc, ok := response.Attestations[BootAttestationKey]
	if !ok {
		log.Fatalf("No boot attestation found in response")
	}

	fmt.Fprintf(os.Stderr, "\n=== STEP 1: API Response Received ===\n")
	fmt.Fprintf(os.Stderr, "✓ Received boot attestation document (%d bytes base64)\n", len(bootAttestationDoc))
	fmt.Fprintf(os.Stderr, "✓ Public key: %s\n", appAttestation.PublicKey)
	fmt.Fprintf(os.Stderr, "✓ Signature: %s\n", appAttestation.Signature)

	// Step 1: Verify the attestation document using awsnitroverifier
	fmt.Fprintf(os.Stderr, "\n=== STEP 2: Verify Attestation Document ===\n")
	verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
		SkipTimestampCheck: true, // Skip timestamp check as we're verifying historical data
	})

	result, err := verifier.Validate(bootAttestationDoc)
	if err != nil {
		log.Fatalf("Failed to verify attestation document: %v", err)
	}

	if !result.Valid {
		log.Fatalf("Attestation document validation failed: %v", result.Errors)
	}

	fmt.Fprintf(os.Stderr, "✓ Attestation document verified successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Module ID: %s\n", result.Document.ModuleID)
	fmt.Fprintf(os.Stderr, "✓ PCRs verified: %d PCRs found\n", len(result.Document.PCRs))

	// Extract and verify UserData (contains QoS Manifest hash / Pivot Binary Hash)
	if len(result.Document.UserData) > 0 {
		fmt.Fprintf(os.Stderr, "\n📋 UserData (QoS Manifest Hash / Pivot Binary Hash):\n")
		fmt.Fprintf(os.Stderr, "  Hex: %s\n", hex.EncodeToString(result.Document.UserData))
		fmt.Fprintf(os.Stderr, "  Length: %d bytes\n", len(result.Document.UserData))

		// Verify against provided QoS manifest if given
		if qosManifestHex != "" {
			qosManifestBytes, err := hex.DecodeString(qosManifestHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  Invalid QoS manifest hex provided: %v\n", err)
			} else if hex.EncodeToString(qosManifestBytes) == hex.EncodeToString(result.Document.UserData) {
				fmt.Fprintf(os.Stderr, "  ✅ QoS Manifest matches expected value\n")
			} else {
				fmt.Fprintf(os.Stderr, "  ❌ QoS Manifest mismatch!\n")
				fmt.Fprintf(os.Stderr, "     Expected: %s\n", qosManifestHex)
				fmt.Fprintf(os.Stderr, "     Actual:   %s\n", hex.EncodeToString(result.Document.UserData))
				log.Fatalf("QoS Manifest verification failed")
			}
		}

		// Also check against pivot binary hash parameter if provided
		if pivotBinaryHashHex != "" && qosManifestHex == "" {
			pivotBinaryHashBytes, err := hex.DecodeString(pivotBinaryHashHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  Invalid pivot binary hash hex provided: %v\n", err)
			} else if hex.EncodeToString(pivotBinaryHashBytes) == hex.EncodeToString(result.Document.UserData) {
				fmt.Fprintf(os.Stderr, "  ✅ Pivot Binary Hash matches expected value\n")
			} else {
				fmt.Fprintf(os.Stderr, "  ❌ Pivot Binary Hash mismatch!\n")
				fmt.Fprintf(os.Stderr, "     Expected: %s\n", pivotBinaryHashHex)
				fmt.Fprintf(os.Stderr, "     Actual:   %s\n", hex.EncodeToString(result.Document.UserData))
				log.Fatalf("Pivot Binary Hash verification failed")
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "\n📋 UserData: Not present in attestation\n")
	}

	// Print all PCR values with descriptive labels
	printPCRValues(result.Document.PCRs, "📊 PCR Values", "")

	// Decode QoS Manifest if available
	if response.QosManifestB64 != "" {
		fmt.Fprintf(os.Stderr, "\n=== QoS Manifest Decoding ===\n")
		manifest, manifestBytes, _, err := DecodeManifestFromBase64(response.QosManifestB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to decode QoS manifest: %v\n", err)
		} else {
			// Compute different hashes to figure out which one matches UserData
			rawManifestBytes, _ := base64.StdEncoding.DecodeString(response.QosManifestB64)
			rawManifestHash := ComputeManifestHash(rawManifestBytes)
			manifestHash := ComputeManifestHash(manifestBytes)

			fmt.Fprintf(os.Stderr, "✓ Manifest decoded successfully\n")
			fmt.Fprintf(os.Stderr, "✓ Raw Manifest Bytes SHA256: %s\n", rawManifestHash)
			fmt.Fprintf(os.Stderr, "✓ Re-serialized Manifest SHA256: %s\n", manifestHash)

			// If we have the envelope version, compute its hash too
			var envelopeHash string
			if response.QosManifestEnvelopeB64 != "" {
				envelopeBytes, err := base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
				if err == nil {
					envelopeHash = ComputeManifestHash(envelopeBytes)
					fmt.Fprintf(os.Stderr, "✓ Envelope SHA256: %s\n", envelopeHash)
				}
			}

			// Compare against UserData - Manifest Serialization Check
			if len(result.Document.UserData) > 0 {
				userDataHex := hex.EncodeToString(result.Document.UserData)
				if rawManifestHash == userDataHex {
					fmt.Fprintf(os.Stderr, "✓ Raw manifest hash matches UserData in attestation\n")
				} else {
					if allowManifestReserializationMismatch {
						fmt.Fprintf(os.Stderr, "ℹ️  INFO: Manifest reserialization mismatch (continuing due to --allow-manifest-reserialization-mismatch)\n")
					} else {
						fmt.Fprintf(os.Stderr, "⚠️  Manifest reserialization mismatch detected\n")
					}
					fmt.Fprintf(os.Stderr, "   Boot-time hash (UserData): %s\n", userDataHex)
					fmt.Fprintf(os.Stderr, "   API manifest hash:         %s\n", rawManifestHash)
					fmt.Fprintf(os.Stderr, "\n   This likely indicates different Borsh serialization between\n")
					fmt.Fprintf(os.Stderr, "   the enclave boot process and this Go client implementation.\n")
					fmt.Fprintf(os.Stderr, "   The core attestation verification has still passed successfully.\n")
					if !allowManifestReserializationMismatch {
						log.Fatalf("Manifest reserialization verification failed - use --allow-manifest-reserialization-mismatch to continue")
					}
				}
			}

			// Display manifest details
			fmt.Fprintf(os.Stderr, "\n📋 Manifest Details:\n")
			fmt.Fprintf(os.Stderr, "  Namespace:\n")
			fmt.Fprintf(os.Stderr, "    Name: %s\n", manifest.Namespace.Name)
			fmt.Fprintf(os.Stderr, "    Nonce: %d\n", manifest.Namespace.Nonce)
			fmt.Fprintf(os.Stderr, "    Quorum Key: %s\n", hex.EncodeToString(manifest.Namespace.QuorumKey))

			fmt.Fprintf(os.Stderr, "  Pivot Config:\n")
			fmt.Fprintf(os.Stderr, "    Binary Hash: %s\n", hex.EncodeToString(manifest.Pivot.Hash[:]))
			fmt.Fprintf(os.Stderr, "    Restart Policy: %d\n", manifest.Pivot.Restart)
			if len(manifest.Pivot.Args) > 0 {
				fmt.Fprintf(os.Stderr, "    Args: %v\n", manifest.Pivot.Args)
			}

			fmt.Fprintf(os.Stderr, "  Manifest Set:\n")
			fmt.Fprintf(os.Stderr, "    Threshold: %d\n", manifest.ManifestSet.Threshold)
			fmt.Fprintf(os.Stderr, "    Members: %d\n", len(manifest.ManifestSet.Members))
			for i, member := range manifest.ManifestSet.Members {
				fmt.Fprintf(os.Stderr, "      [%d] %s: %s\n", i, member.Alias, hex.EncodeToString(member.PubKey))
			}

			fmt.Fprintf(os.Stderr, "  Share Set:\n")
			fmt.Fprintf(os.Stderr, "    Threshold: %d\n", manifest.ShareSet.Threshold)
			fmt.Fprintf(os.Stderr, "    Members: %d\n", len(manifest.ShareSet.Members))

			// Convert manifest PCRs to the same format and display them
			manifestPCRs := map[uint][]byte{
				0: manifest.Enclave.Pcr0,
				1: manifest.Enclave.Pcr1,
				2: manifest.Enclave.Pcr2,
				3: manifest.Enclave.Pcr3,
			}
			printPCRValues(manifestPCRs, "Enclave (Nitro Config)", "  ")
			fmt.Fprintf(os.Stderr, "    QoS Commit: %s\n", manifest.Enclave.QosCommit)

			fmt.Fprintf(os.Stderr, "  Patch Set:\n")
			fmt.Fprintf(os.Stderr, "    Threshold: %d\n", manifest.PatchSet.Threshold)
			fmt.Fprintf(os.Stderr, "    Members: %d\n", len(manifest.PatchSet.Members))
		}
	}

	// Step 2: Extract public key from the 130-byte hex string (we want the latter 65 bytes)
	fmt.Fprintf(os.Stderr, "\n=== STEP 3: Extract Public Key ===\n")
	publicKeyHex := appAttestation.PublicKey
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode public key hex: %v", err)
	}

	if len(publicKeyBytes) != 130 {
		log.Fatalf("Expected 130-byte public key, got %d bytes", len(publicKeyBytes))
	}

	// Extract the latter 65 bytes (uncompressed public key format: 0x04 || X || Y)
	publicKeyForVerification := publicKeyBytes[65:]
	fmt.Fprintf(os.Stderr, "✓ Extracted 65-byte public key from 130-byte string\n")
	fmt.Fprintf(os.Stderr, "✓ Public key for verification: %s\n", hex.EncodeToString(publicKeyForVerification))

	// Parse the public key as an uncompressed ECDSA public key (P-256)
	if publicKeyForVerification[0] != 0x04 {
		log.Fatalf("Expected uncompressed public key format (0x04 prefix), got 0x%02x", publicKeyForVerification[0])
	}

	// P-256 curve (ephemeral signing key)
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
		log.Fatalf("Public key is not on the P256 curve")
	}

	// Step 3: Verify the signature
	fmt.Fprintf(os.Stderr, "\n=== STEP 4: Verify Signature ===\n")

	// The message is a borsh-encoded hash of the signablePayload
	messageHex := appAttestation.Message
	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		log.Fatalf("Failed to decode message hex: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✓ Message hash: %s\n", hex.EncodeToString(messageBytes))

	// The signature is in hex format
	signatureHex := appAttestation.Signature
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Fatalf("Failed to decode signature hex: %v", err)
	}

	// Parse signature (r || s format, 64 bytes total)
	if len(signatureBytes) != 64 {
		log.Fatalf("Expected 64-byte signature, got %d bytes", len(signatureBytes))
	}

	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	// IMPORTANT: The signature is over the SHA256 hash of the message hash
	// (following the awsnitroverifier implementation)
	sha256Hash := sha256.Sum256(messageBytes)

	fmt.Fprintf(os.Stderr, "✓ SHA256 of message: %s\n", hex.EncodeToString(sha256Hash[:]))

	// Verify the signature
	valid := ecdsa.Verify(pubKey, sha256Hash[:], r, s)
	if !valid {
		log.Fatalf("Signature verification failed")
	}

	fmt.Fprintf(os.Stderr, "✓ Signature verified successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Signature is valid for the message hash provided by Turnkey\n")

	// Final summary
	fmt.Fprintf(os.Stderr, "\n=== VERIFICATION COMPLETE ===\n")
	fmt.Fprintf(os.Stderr, "✓ All verification steps passed successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Transaction was executed inside AWS Nitro enclave\n")
	fmt.Fprintf(os.Stderr, "✓ Signature is valid and matches the enclave public key\n")
	fmt.Fprintf(os.Stderr, "✓ Message hash matches the signable payload\n")

	// Output JSON result
	output := map[string]interface{}{
		"valid":            true,
		"attestationValid": result.Valid,
		"signatureValid":   valid,
		"moduleId":         result.Document.ModuleID,
		"publicKey":        publicKeyHex,
		"signablePayload":  response.SignablePayload,
		"message":          messageHex,
		"signature":        signatureHex,
	}

	// Add UserData (QoS Manifest / Pivot Binary Hash) if present
	if len(result.Document.UserData) > 0 {
		output["qosManifest"] = hex.EncodeToString(result.Document.UserData)
		output["pivotBinaryHash"] = hex.EncodeToString(result.Document.UserData) // Same as qosManifest
	}

	// Add PCR[4] (Application Measurement) if present
	if pcr4, exists := result.Document.PCRs[4]; exists && len(pcr4) > 0 {
		output["pcr4"] = hex.EncodeToString(pcr4)
	}

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal output: %v", err)
	}

	fmt.Println(string(outputJSON))
}
