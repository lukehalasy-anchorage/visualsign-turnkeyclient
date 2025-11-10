package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestAttestationCommand(t *testing.T) {
	cmd := AttestationCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "attestation", cmd.Name)
	require.Len(t, cmd.Commands, 1)
}

func TestGetBootAttestationCommand(t *testing.T) {
	cmd := getBootAttestationCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "get-boot", cmd.Name)
	require.NotEmpty(t, cmd.Usage)

	// Verify required flags exist
	require.NotNil(t, cmd.Flags)
	require.Len(t, cmd.Flags, 5)

	// Check for specific required flags
	var hasHost, hasOrgID, hasKeyName, hasPubKey, hasEnclaveType bool
	for _, flag := range cmd.Flags {
		switch f := flag.(type) {
		case *cli.StringFlag:
			if f.Name == "host" {
				hasHost = true
				require.True(t, f.Required)
			}
			if f.Name == "organization-id" {
				hasOrgID = true
				require.True(t, f.Required)
			}
			if f.Name == "key-name" {
				hasKeyName = true
				require.True(t, f.Required)
			}
			if f.Name == "public-key" {
				hasPubKey = true
				require.True(t, f.Required)
			}
			if f.Name == "enclave-type" {
				hasEnclaveType = true
				require.Equal(t, "signer", f.Value) // Check default value
			}
		}
	}

	require.True(t, hasHost)
	require.True(t, hasOrgID)
	require.True(t, hasKeyName)
	require.True(t, hasPubKey)
	require.True(t, hasEnclaveType)
}
