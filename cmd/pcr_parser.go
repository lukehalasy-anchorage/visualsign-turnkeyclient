package cmd

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
)

// ParsePCRs parses PCR specification string in format "0:<hex>,1:<hex>,..."
// and returns a slice of PCRRule for use with awsnitroverifier
//
// Example input: "0:f2479c809cbfa117cfa3f9a91c12faf602a8d8f5c06afd8d3c7d9f48c49fe048385802da593e6cc7c70c0b8c519625de,1:abc123"
func ParsePCRs(pcrSpec string) ([]nitroverifier.PCRRule, error) {
	if pcrSpec == "" {
		return nil, nil
	}

	// Split by comma to get individual PCR specifications
	pcrSpecs := strings.Split(pcrSpec, ",")
	rules := make([]nitroverifier.PCRRule, 0, len(pcrSpecs))

	for _, spec := range pcrSpecs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		// Split by colon to get index and value
		parts := strings.SplitN(spec, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid PCR specification '%s': expected format 'index:hex_value'", spec)
		}

		// Parse index
		index, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index '%s': %w", parts[0], err)
		}

		// Parse hex value
		hexValue := strings.TrimSpace(parts[1])
		value, err := hex.DecodeString(hexValue)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR hex value '%s' for index %d: %w", hexValue, index, err)
		}

		rules = append(rules, nitroverifier.PCRRule{
			Index: uint(index),
			Value: value,
		})
	}

	return rules, nil
}
