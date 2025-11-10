package main

import (
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/verify"
	"github.com/stretchr/testify/require"
)

// TestPrintPCRValuesBasic tests basic PCR value printing
func TestPrintPCRValuesBasic(t *testing.T) {
	pcrs := map[uint][]byte{
		0: make([]byte, 48), // SHA384 hash
		1: make([]byte, 48),
		2: make([]byte, 48),
		3: make([]byte, 48),
	}
	// Fill with some test data
	for i := 0; i < 48; i++ {
		pcrs[0][i] = byte(i % 256)
		pcrs[1][i] = byte((i + 1) % 256)
		pcrs[2][i] = byte((i + 2) % 256)
		pcrs[3][i] = byte((i + 3) % 256)
	}

	formatter := verify.NewFormatter()
	outputStr := formatter.FormatPCRValues(pcrs, "Test PCRs", "")

	// Verify output contains expected content
	require.Contains(t, outputStr, "Test PCRs")
	require.Contains(t, outputStr, "PCR[0]")
	require.Contains(t, outputStr, "PCR[1]")
	require.Contains(t, outputStr, "PCR[2]")
	require.Contains(t, outputStr, "PCR[3]")
}

// TestPrintPCRValuesWithZeros tests PCR printing with zero values
func TestPrintPCRValuesWithZeros(t *testing.T) {
	pcrs := map[uint][]byte{
		0: make([]byte, 48), // Non-zero
		5: make([]byte, 48), // All zeros
		6: make([]byte, 48), // All zeros
		7: make([]byte, 48), // All zeros
	}
	// Fill PCR 0 with data
	for i := 0; i < 48; i++ {
		pcrs[0][i] = byte(i % 256)
	}

	formatter := verify.NewFormatter()
	outputStr := formatter.FormatPCRValues(pcrs, "PCRs with Zeros", "")

	// Verify output
	require.Contains(t, outputStr, "PCRs with Zeros")
	require.Contains(t, outputStr, "PCR[0]")
	// Zero PCRs should be marked as "all zeros"
	require.Contains(t, outputStr, "all zeros")
}

// TestPrintPCRValuesIndentation tests proper indentation
func TestPrintPCRValuesIndentation(t *testing.T) {
	pcrs := map[uint][]byte{
		0: make([]byte, 48),
	}

	indent := "    "
	formatter := verify.NewFormatter()
	outputStr := formatter.FormatPCRValues(pcrs, "Indented PCRs", indent)

	// Verify indentation is applied
	require.Contains(t, outputStr, "    Indented PCRs")
	require.Contains(t, outputStr, "    PCR[0]")
}

// TestPrintPCRValuesConsecutiveZeros tests handling of consecutive zero PCRs
func TestPrintPCRValuesConsecutiveZeros(t *testing.T) {
	pcrs := map[uint][]byte{
		0:  make([]byte, 48), // Non-zero
		5:  make([]byte, 48), // All zeros (start of range)
		6:  make([]byte, 48), // All zeros
		7:  make([]byte, 48), // All zeros
		8:  make([]byte, 48), // All zeros (end of range)
		15: make([]byte, 48), // Non-zero
	}
	// Fill non-zero entries
	for i := 0; i < 48; i++ {
		pcrs[0][i] = byte(i)
		pcrs[15][i] = byte(i)
	}

	formatter := verify.NewFormatter()
	outputStr := formatter.FormatPCRValues(pcrs, "Range Test", "")

	// Verify output contains range notation for consecutive zeros
	require.Contains(t, outputStr, "PCR[0]")
	require.Contains(t, outputStr, "PCR[15]")
	require.Contains(t, outputStr, "all zeros")
}

// TestPrintPCRValuesSpecialLabels tests special labels for specific PCRs
func TestPrintPCRValuesSpecialLabels(t *testing.T) {
	pcrs := map[uint][]byte{
		0: make([]byte, 48), // QoS hash
		1: make([]byte, 48), // QoS hash
		2: make([]byte, 48), // General
		3: make([]byte, 48), // AWS Role hash
	}

	// Fill with some test data
	for i := 0; i < 48; i++ {
		pcrs[0][i] = byte(i)
		pcrs[1][i] = byte(i + 1)
		pcrs[2][i] = byte(i + 2)
		pcrs[3][i] = byte(i + 3)
	}

	formatter := verify.NewFormatter()
	outputStr := formatter.FormatPCRValues(pcrs, "PCRs with Labels", "")

	// Verify special labels are included
	require.Contains(t, outputStr, "QoS hash")
	require.Contains(t, outputStr, "AWS Role")
}
