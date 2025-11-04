package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/urfave/cli/v3"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/keys"
)

// AttestationCommand creates the attestation command
func AttestationCommand() *cli.Command {
	return &cli.Command{
		Name:     "attestation",
		Usage:    "Get boot attestation for a public key",
		Commands: []*cli.Command{
			getBootAttestationCommand(),
		},
	}
}

func getBootAttestationCommand() *cli.Command {
	return &cli.Command{
		Name:  "get-boot",
		Usage: "Get boot attestation for a specific public key",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "host",
				Usage:    "Turnkey API host",
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
				Name:     "public-key",
				Usage:    "Public key to get attestation for",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "enclave-type",
				Usage: "Enclave type (defaults to 'signer')",
				Value: "signer",
			},
		},
		Action: runGetBootAttestationCommand,
	}
}

func runGetBootAttestationCommand(ctx context.Context, cmd *cli.Command) error {
	hostURI := cmd.String("host")
	organizationID := cmd.String("organization-id")
	keyName := cmd.String("key-name")
	publicKey := cmd.String("public-key")
	enclaveType := cmd.String("enclave-type")

	// Create HTTP client
	httpClient := &http.Client{}

	// Create key provider
	keyProvider := &keys.FileKeyProvider{KeyName: keyName}

	// Create API client
	client, err := api.NewClient(hostURI, httpClient, organizationID, keyProvider)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Get boot attestation
	attestation, err := client.GetBootAttestation(ctx, publicKey, enclaveType)
	if err != nil {
		return fmt.Errorf("failed to get boot attestation: %w", err)
	}

	// Print the attestation document
	fmt.Println(attestation)

	return nil
}
