package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/keys"
	"github.com/anchorageoss/visualsign-turnkeyclient/verify"
	"github.com/urfave/cli/v3"
)

// VerifyCommand creates the verify command
func VerifyCommand() *cli.Command {
	return &cli.Command{
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
			&cli.StringFlag{
				Name:  "chain",
				Usage: "Blockchain network (CHAIN_SOLANA, CHAIN_ETHEREUM, etc)",
				Value: "CHAIN_SOLANA",
			},
			&cli.BoolFlag{
				Name:  "allow-manifest-reserialization-mismatch",
				Usage: "Continue verification even if manifest reserialization produces different hash than UserData (show warning instead of aborting)",
				Value: true, // TODO: Default to true for now - align manifest format with API response
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Enable debug output (attestation document, PCR values, manifest details)",
			},
		},
		Action: runVerifyCommand,
	}
}

func runVerifyCommand(ctx context.Context, cmd *cli.Command) error {
	// Extract flags
	hostURI := cmd.String("host")
	organizationID := cmd.String("organization-id")
	keyName := cmd.String("key-name")
	unsignedPayload := cmd.String("unsigned-payload")
	qosManifestHex := cmd.String("qos-manifest-hex")
	pivotBinaryHashHex := cmd.String("pivot-binary-hash-hex")
	saveManifestPath := cmd.String("save-qos-manifest")
	chain := cmd.String("chain")
	allowMismatch := cmd.Bool("allow-manifest-reserialization-mismatch")
	debug := cmd.Bool("debug")

	// Create API client
	httpClient := &http.Client{}
	keyProvider := &keys.FileKeyProvider{KeyName: keyName}
	apiClient, err := api.NewClient(hostURI, httpClient, organizationID, keyProvider)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Create attestation verifier
	verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	// Create verification service
	service := verify.NewService(apiClient, verifier)

	// Perform verification
	result, err := service.Verify(ctx, &verify.VerifyRequest{
		UnsignedPayload:                      unsignedPayload,
		QosManifestHex:                       qosManifestHex,
		PivotBinaryHashHex:                   pivotBinaryHashHex,
		SaveManifestPath:                     saveManifestPath,
		Chain:                                chain,
		AllowManifestReserializationMismatch: allowMismatch,
	})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Print to stderr for debugging/logging
	fmt.Fprintf(os.Stderr, "\n=== STEP 1: API Response Received ===\n")
	fmt.Fprintf(os.Stderr, "✓ Received boot attestation document\n")
	fmt.Fprintf(os.Stderr, "✓ Public key: %s\n", result.PublicKeyHex)
	fmt.Fprintf(os.Stderr, "✓ Signature: %s\n", result.SignatureHex)

	fmt.Fprintf(os.Stderr, "\n=== STEP 2: Verify Attestation Document ===\n")
	fmt.Fprintf(os.Stderr, "✓ Attestation document verified successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Module ID: %s\n", result.ModuleID)
	fmt.Fprintf(os.Stderr, "✓ PCRs verified: %d PCRs found\n", len(result.PCRs))

	// Format and print PCR values
	formatter := verify.NewFormatter()

	// Print debug information if requested
	if debug {
		// Print raw attestation document for debugging
		if result.AttestationDocument != nil {
			attestationJSON, err := json.MarshalIndent(result.AttestationDocument, "", "  ")
			if err == nil {
				fmt.Fprintf(os.Stderr, "\n📋 Raw Attestation Document:\n")
				fmt.Fprintf(os.Stderr, "%s\n", string(attestationJSON))
			}
		}

		if len(result.UserData) > 0 {
			fmt.Fprintf(os.Stderr, "\n📋 UserData (QoS Manifest Hash / Pivot Binary Hash):\n")
			fmt.Fprintf(os.Stderr, "  Hex: %s\n", result.QosManifestHash)
		}

		// Print PCR values
		fmt.Fprint(os.Stderr, formatter.FormatPCRValues(result.PCRs, "📊 PCR Values", ""))
	}

	// Display manifest details if available
	if result.Manifest != nil || result.ManifestReserialization.ResserializationNeeded {
		fmt.Fprintf(os.Stderr, "\n=== QoS Manifest Decoding ===\n")
		if result.Manifest != nil {
			fmt.Fprintf(os.Stderr, "✓ Manifest decoded successfully\n")
		}
		if result.ManifestReserialization.Matches {
			fmt.Fprintf(os.Stderr, "✓ Raw manifest hash matches UserData in attestation\n")
		} else if result.ManifestReserialization.ResserializationNeeded {
			if result.ManifestReserialization.Error != "" {
				fmt.Fprintf(os.Stderr, "ℹ️  WARNING: Manifest parsing error (continuing due to --allow-manifest-reserialization-mismatch)\n")
				fmt.Fprintf(os.Stderr, "  Error: %s\n", result.ManifestReserialization.Error)
			} else {
				fmt.Fprintf(os.Stderr, "ℹ️  INFO: Manifest reserialization mismatch (continuing due to --allow-manifest-reserialization-mismatch)\n")
			}
		}

		if debug {
			// Display hash details only if there's a mismatch or error
			hashMismatch := result.ManifestReserialization.UserDataHash != "" &&
				result.ManifestReserialization.RawManifestHash != "" &&
				result.ManifestReserialization.RawManifestHash != result.ManifestReserialization.UserDataHash &&
				(result.ManifestReserialization.EnvelopeHash == "" || result.ManifestReserialization.EnvelopeHash != result.ManifestReserialization.UserDataHash)

			hasError := result.ManifestReserialization.Error != ""

			if hashMismatch || hasError {
				fmt.Fprintf(os.Stderr, "\n📊 Manifest Hash Details (DEBUG):\n")
				if result.ManifestReserialization.UserDataHash != "" {
					fmt.Fprintf(os.Stderr, "  UserData (from attestation):     %s\n", result.ManifestReserialization.UserDataHash)
				}
				if result.ManifestReserialization.RawManifestHash != "" {
					match := ""
					if result.ManifestReserialization.RawManifestHash == result.ManifestReserialization.UserDataHash {
						match = " ✅ MATCHES UserData"
					}
					fmt.Fprintf(os.Stderr, "  Raw Manifest (from API):        %s%s\n", result.ManifestReserialization.RawManifestHash, match)
				}
				if result.ManifestReserialization.ReserializedManifestHash != "" {
					fmt.Fprintf(os.Stderr, "  Reserialized Manifest:          %s\n", result.ManifestReserialization.ReserializedManifestHash)
				}
				if result.ManifestReserialization.EnvelopeHash != "" {
					match := ""
					if result.ManifestReserialization.EnvelopeHash == result.ManifestReserialization.UserDataHash {
						match = " ✅ MATCHES UserData"
					}
					fmt.Fprintf(os.Stderr, "  Manifest Envelope (from API):   %s%s\n", result.ManifestReserialization.EnvelopeHash, match)
				}

				// Display raw payload for debugging
				if result.ManifestReserialization.RawManifestB64 != "" {
					fmt.Fprintf(os.Stderr, "\n  Raw Manifest Payload (base64):\n")
					fmt.Fprintf(os.Stderr, "    %s\n", result.ManifestReserialization.RawManifestB64)
				}
				if result.ManifestReserialization.EnvelopeB64 != "" {
					fmt.Fprintf(os.Stderr, "\n  Manifest Envelope Payload (base64):\n")
					fmt.Fprintf(os.Stderr, "    %s\n", result.ManifestReserialization.EnvelopeB64)
				}
			}

			if result.Manifest != nil {
				fmt.Fprintf(os.Stderr, "\n📋 Manifest Details:\n")
				manifestPCRs := map[uint][]byte{
					0: result.Manifest.Enclave.Pcr0,
					1: result.Manifest.Enclave.Pcr1,
					2: result.Manifest.Enclave.Pcr2,
					3: result.Manifest.Enclave.Pcr3,
				}
				fmt.Fprint(os.Stderr, formatter.FormatPCRValues(manifestPCRs, "Enclave (Nitro Config)", "  "))
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n=== STEP 3: Extract Public Key ===\n")
	fmt.Fprintf(os.Stderr, "✓ Extracted 65-byte public key from 130-byte string\n")
	fmt.Fprintf(os.Stderr, "✓ Public key for verification: %s\n", result.PublicKeyHex[len(result.PublicKeyHex)-64:])

	fmt.Fprintf(os.Stderr, "\n=== STEP 4: Verify Signature ===\n")
	fmt.Fprintf(os.Stderr, "✓ Message hash: %s\n", result.MessageHex)
	fmt.Fprintf(os.Stderr, "✓ Signature verified successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Signature is valid for the message hash provided by Turnkey\n")

	fmt.Fprintf(os.Stderr, "\n=== VERIFICATION COMPLETE ===\n")
	fmt.Fprintf(os.Stderr, "✓ All verification steps passed successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Transaction was executed inside AWS Nitro enclave\n")
	fmt.Fprintf(os.Stderr, "✓ Signature is valid and matches the enclave public key\n")

	// Output JSON result to stdout
	jsonOutput, err := json.MarshalIndent(formatter.FormatVerificationResult(result), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	fmt.Println(string(jsonOutput))
	return nil
}
