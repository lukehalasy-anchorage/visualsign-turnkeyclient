package verify

import (
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/stretchr/testify/require"
)

func TestNewFormatter(t *testing.T) {
	formatter := NewFormatter()
	require.NotNil(t, formatter)
}

func TestFormatPCRValues(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic PCR formatting", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0x01, 0x02, 0x03},
			1: {0x04, 0x05, 0x06},
		}

		result := formatter.FormatPCRValues(pcrs, "Test PCRs", "")
		require.NotEmpty(t, result)
		require.Contains(t, result, "Test PCRs")
		require.Contains(t, result, "010203")
		require.Contains(t, result, "040506")
	})

	t.Run("empty PCRs", func(t *testing.T) {
		pcrs := map[uint][]byte{}
		result := formatter.FormatPCRValues(pcrs, "Empty PCRs", "")
		require.NotEmpty(t, result)
	})

	t.Run("with indent", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0xaa, 0xbb},
		}
		result := formatter.FormatPCRValues(pcrs, "Indented", "  ")
		require.Contains(t, result, "  ")
	})

	t.Run("zero PCR values", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0x00, 0x00, 0x00},
		}
		result := formatter.FormatPCRValues(pcrs, "Zeros", "")
		require.NotEmpty(t, result)
	})
}

func TestFormatManifest(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic manifest", func(t *testing.T) {
		m := &manifest.Manifest{
			Namespace: manifest.Namespace{
				Name:  "test",
				Nonce: 1,
			},
			Pivot: manifest.PivotConfig{
				Restart: manifest.RestartPolicyNever,
				Args:    []string{},
			},
			ManifestSet: manifest.ManifestSet{
				Threshold: 2,
				Members:   []manifest.QuorumMember{},
			},
			ShareSet: manifest.ShareSet{
				Threshold: 3,
				Members:   []manifest.QuorumMember{},
			},
		}

		result := formatter.FormatManifest(m)
		require.NotEmpty(t, result)
		require.Contains(t, result, "test")
		require.Contains(t, result, "threshold: 2")
		require.Contains(t, result, "threshold: 3")
	})
}

func TestFormatMembers(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format quorum members", func(t *testing.T) {
		members := []manifest.QuorumMember{
			{Alias: "member1", PubKey: []byte{0x01, 0x02}},
			{Alias: "member2", PubKey: []byte{0x03, 0x04}},
		}

		result := formatter.FormatMembers(members)
		require.Len(t, result, 2)
		require.Equal(t, "member1", result[0]["alias"])
		require.Equal(t, "0102", result[0]["pubKey"])
	})

	t.Run("empty members", func(t *testing.T) {
		members := []manifest.QuorumMember{}
		result := formatter.FormatMembers(members)
		require.Len(t, result, 0)
	})
}

func TestFormatPatchMembers(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format patch members", func(t *testing.T) {
		members := []manifest.MemberPubKey{
			{PubKey: []byte{0xaa, 0xbb}},
			{PubKey: []byte{0xcc, 0xdd}},
		}

		result := formatter.FormatPatchMembers(members)
		require.Len(t, result, 2)
		require.Equal(t, "aabb", result[0]["pubKey"])
		require.Equal(t, "ccdd", result[1]["pubKey"])
	})

	t.Run("empty members", func(t *testing.T) {
		members := []manifest.MemberPubKey{}
		result := formatter.FormatPatchMembers(members)
		require.Len(t, result, 0)
	})
}

func TestFormatApprovals(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format approvals", func(t *testing.T) {
		approvals := []manifest.Approval{
			{
				Signature: []byte{0x11, 0x22},
				Member:    manifest.QuorumMember{Alias: "approver1", PubKey: []byte{0x33, 0x44}},
			},
		}

		result := formatter.FormatApprovals(approvals)
		require.Len(t, result, 1)
		require.Equal(t, "1122", result[0]["signature"])
		memberMap := result[0]["member"].(map[string]string)
		require.Equal(t, "approver1", memberMap["alias"])
	})

	t.Run("empty approvals", func(t *testing.T) {
		approvals := []manifest.Approval{}
		result := formatter.FormatApprovals(approvals)
		require.Len(t, result, 0)
	})
}

func TestFormatVerificationResult(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic verification result", func(t *testing.T) {
		result := &VerifyResult{
			AttestationValid: true,
			SignablePayload:  "test-payload",
			PublicKeyHex:     "pubkey",
			SignatureHex:     "signature",
			MessageHex:       "message",
			ModuleID:         "module-123",
			PCRs: map[uint][]byte{
				0: {0x01},
			},
		}

		formatted := formatter.FormatVerificationResult(result)
		require.NotNil(t, formatted)
		require.Equal(t, true, formatted["attestationValid"])
		require.Equal(t, "test-payload", formatted["signablePayload"])
		require.Equal(t, "pubkey", formatted["publicKey"])
	})
}

func TestFormatManifestJSON(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic manifest JSON", func(t *testing.T) {
		m := &manifest.Manifest{
			Namespace: manifest.Namespace{
				Name:  "json-test",
				Nonce: 42,
			},
			Pivot: manifest.PivotConfig{
				Restart: manifest.RestartPolicyAlways,
			},
			ManifestSet: manifest.ManifestSet{
				Threshold: 1,
			},
		}

		result := formatter.FormatManifestJSON(m)
		require.NotNil(t, result)

		namespace := result["namespace"].(map[string]interface{})
		require.Equal(t, "json-test", namespace["name"])
		require.Equal(t, uint32(42), namespace["nonce"])
	})
}

func TestFormatManifestEnvelopeJSON(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic envelope JSON", func(t *testing.T) {
		env := &manifest.ManifestEnvelope{
			Manifest: manifest.Manifest{
				Namespace: manifest.Namespace{
					Name:  "envelope-test",
					Nonce: 99,
				},
			},
			ManifestSetApprovals: []manifest.Approval{},
		}

		result := formatter.FormatManifestEnvelopeJSON(env)
		require.NotNil(t, result)
		require.NotNil(t, result["manifest"])
	})

	t.Run("envelope with approvals", func(t *testing.T) {
		env := &manifest.ManifestEnvelope{
			Manifest: manifest.Manifest{
				Namespace: manifest.Namespace{Name: "test"},
			},
			ManifestSetApprovals: []manifest.Approval{
				{Signature: []byte{0xaa}, Member: manifest.QuorumMember{Alias: "signer"}},
			},
		}

		result := formatter.FormatManifestEnvelopeJSON(env)
		require.NotNil(t, result)
		approvals := result["manifestSetApprovals"].([]map[string]interface{})
		require.Len(t, approvals, 1)
	})
}
