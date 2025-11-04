package manifest

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeHash computes SHA256 hash of manifest bytes
func ComputeHash(manifestBytes []byte) string {
	sum := sha256.Sum256(manifestBytes)
	return hex.EncodeToString(sum[:])
}
