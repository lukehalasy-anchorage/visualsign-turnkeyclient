package verify

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// Formatter formats verification and manifest data for display
type Formatter struct{}

// NewFormatter creates a new formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

// FormatPCRValues formats PCR values with descriptive labels and proper formatting
func (f *Formatter) FormatPCRValues(pcrs map[uint][]byte, title string, indent string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n%s%s:\n", indent, title))

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
			sb.WriteString(fmt.Sprintf("%s    PCR[%d]: %s (QoS hash)\n", indent, idx, hex.EncodeToString(pcr)))
		}
	}

	// PCR 2: General PCR
	if pcr, exists := pcrs[2]; exists && len(pcr) > 0 {
		sb.WriteString(fmt.Sprintf("%s    PCR[2]: %s\n", indent, hex.EncodeToString(pcr)))
	}

	// PCR 3: Hash of the AWS Role
	if pcr, exists := pcrs[3]; exists && len(pcr) > 0 {
		sb.WriteString(fmt.Sprintf("%s    PCR[3]: %s (Hash of the AWS Role)\n", indent, hex.EncodeToString(pcr)))
	}

	// PCR 4: Legacy
	if pcr, exists := pcrs[4]; exists && len(pcr) > 0 {
		sb.WriteString(fmt.Sprintf("%s    PCR[4]: %s (legacy)\n", indent, hex.EncodeToString(pcr)))
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
			sb.WriteString(fmt.Sprintf("%s    PCR[%d]: %s\n", indent, idx, hex.EncodeToString(pcr)))
		}
	}

	// Display all-zero PCRs as a range if there are any
	if len(allZeroPCRs) > 0 {
		if len(allZeroPCRs) == 1 {
			sb.WriteString(fmt.Sprintf("%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, allZeroPCRs[0]))
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
						sb.WriteString(fmt.Sprintf("%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start))
					} else {
						sb.WriteString(fmt.Sprintf("%s    PCR[%d-%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start, end))
					}
					start = allZeroPCRs[i]
					end = allZeroPCRs[i]
				}
			}

			// Print final range
			if start == end {
				sb.WriteString(fmt.Sprintf("%s    PCR[%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start))
			} else {
				sb.WriteString(fmt.Sprintf("%s    PCR[%d-%d]: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 (all zeros)\n", indent, start, end))
			}
		}
	}

	return sb.String()
}

// FormatManifest formats manifest details for display
func (f *Formatter) FormatManifest(m *manifest.Manifest) string {
	var sb strings.Builder

	sb.WriteString("Namespace:\n")
	sb.WriteString(fmt.Sprintf("  Name: %s\n", m.Namespace.Name))
	sb.WriteString(fmt.Sprintf("  Nonce: %d\n", m.Namespace.Nonce))
	sb.WriteString(fmt.Sprintf("  Quorum Key: %s\n", hex.EncodeToString(m.Namespace.QuorumKey)))

	sb.WriteString("\nPivot:\n")
	sb.WriteString(fmt.Sprintf("  Hash: %s\n", hex.EncodeToString(m.Pivot.Hash[:])))
	sb.WriteString(fmt.Sprintf("  Restart: %s\n", m.Pivot.Restart))
	sb.WriteString(fmt.Sprintf("  Args: %v\n", m.Pivot.Args))

	sb.WriteString(fmt.Sprintf("\nManifest Set (threshold: %d):\n", m.ManifestSet.Threshold))
	for i, member := range m.ManifestSet.Members {
		pubKeyStr := hex.EncodeToString(member.PubKey)
		if len(pubKeyStr) > 16 {
			pubKeyStr = pubKeyStr[:16] + "..."
		}
		sb.WriteString(fmt.Sprintf("  Member %d: %s (%s)\n", i+1, member.Alias, pubKeyStr))
	}

	sb.WriteString(fmt.Sprintf("\nShare Set (threshold: %d):\n", m.ShareSet.Threshold))
	for i, member := range m.ShareSet.Members {
		pubKeyStr := hex.EncodeToString(member.PubKey)
		if len(pubKeyStr) > 16 {
			pubKeyStr = pubKeyStr[:16] + "..."
		}
		sb.WriteString(fmt.Sprintf("  Member %d: %s (%s)\n", i+1, member.Alias, pubKeyStr))
	}

	sb.WriteString("\nEnclave:\n")
	sb.WriteString(fmt.Sprintf("  PCR0: %s\n", hex.EncodeToString(m.Enclave.Pcr0)))
	sb.WriteString(fmt.Sprintf("  PCR1: %s\n", hex.EncodeToString(m.Enclave.Pcr1)))
	sb.WriteString(fmt.Sprintf("  PCR2: %s\n", hex.EncodeToString(m.Enclave.Pcr2)))
	sb.WriteString(fmt.Sprintf("  PCR3: %s\n", hex.EncodeToString(m.Enclave.Pcr3)))
	sb.WriteString(fmt.Sprintf("  QoS Commit: %s\n", m.Enclave.QosCommit))

	return sb.String()
}

// FormatMembers formats QuorumMember array for output
func (f *Formatter) FormatMembers(members []manifest.QuorumMember) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"alias":  m.Alias,
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

// FormatPatchMembers formats MemberPubKey array for output
func (f *Formatter) FormatPatchMembers(members []manifest.MemberPubKey) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

// FormatApprovals formats Approval array for output
func (f *Formatter) FormatApprovals(approvals []manifest.Approval) []map[string]interface{} {
	result := make([]map[string]interface{}, len(approvals))
	for i, approval := range approvals {
		result[i] = map[string]interface{}{
			"signature": hex.EncodeToString(approval.Signature),
			"member": map[string]string{
				"alias":  approval.Member.Alias,
				"pubKey": hex.EncodeToString(approval.Member.PubKey),
			},
		}
	}
	return result
}

// FormatVerificationResult formats a verification result for display
func (f *Formatter) FormatVerificationResult(result *VerifyResult) map[string]interface{} {
	output := map[string]interface{}{
		"valid":            result.Valid,
		"attestationValid": result.AttestationValid,
		"signatureValid":   result.SignatureValid,
		"moduleId":         result.ModuleID,
		"publicKey":        result.PublicKeyHex,
		"signablePayload":  result.SignablePayload,
		"message":          result.MessageHex,
		"signature":        result.SignatureHex,
	}

	// Add optional fields if present
	if result.QosManifestHash != "" {
		output["qosManifest"] = result.QosManifestHash
		output["pivotBinaryHash"] = result.PivotBinaryHash
	}

	if result.PCR4 != "" {
		output["pcr4"] = result.PCR4
	}

	return output
}

// FormatManifestJSON formats manifest for JSON output
func (f *Formatter) FormatManifestJSON(m *manifest.Manifest) map[string]interface{} {
	return map[string]interface{}{
		"namespace": map[string]interface{}{
			"name":      m.Namespace.Name,
			"nonce":     m.Namespace.Nonce,
			"quorumKey": hex.EncodeToString(m.Namespace.QuorumKey),
		},
		"pivot": map[string]interface{}{
			"hash":    hex.EncodeToString(m.Pivot.Hash[:]),
			"restart": m.Pivot.Restart,
			"args":    m.Pivot.Args,
		},
		"manifestSet": map[string]interface{}{
			"threshold": m.ManifestSet.Threshold,
			"members":   f.FormatMembers(m.ManifestSet.Members),
		},
		"shareSet": map[string]interface{}{
			"threshold": m.ShareSet.Threshold,
			"members":   f.FormatMembers(m.ShareSet.Members),
		},
		"enclave": map[string]interface{}{
			"pcr0":               hex.EncodeToString(m.Enclave.Pcr0),
			"pcr1":               hex.EncodeToString(m.Enclave.Pcr1),
			"pcr2":               hex.EncodeToString(m.Enclave.Pcr2),
			"pcr3":               hex.EncodeToString(m.Enclave.Pcr3),
			"awsRootCertificate": hex.EncodeToString(m.Enclave.AwsRootCertificate),
			"qosCommit":          m.Enclave.QosCommit,
		},
		"patchSet": map[string]interface{}{
			"threshold": m.PatchSet.Threshold,
			"members":   f.FormatPatchMembers(m.PatchSet.Members),
		},
	}
}

// FormatManifestEnvelopeJSON formats manifest envelope for JSON output
func (f *Formatter) FormatManifestEnvelopeJSON(env *manifest.ManifestEnvelope) map[string]interface{} {
	return map[string]interface{}{
		"manifest":              f.FormatManifestJSON(&env.Manifest),
		"manifestSetApprovals":  f.FormatApprovals(env.ManifestSetApprovals),
		"shareSetApprovals":     f.FormatApprovals(env.ShareSetApprovals),
	}
}
