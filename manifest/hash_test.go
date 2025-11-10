package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeHash(t *testing.T) {
	// Test basic hash computation
	input := []byte("test manifest data")
	hash := ComputeHash(input)

	// SHA256 should produce 64 hex characters
	assert.Len(t, hash, 64)

	// Same input should produce same hash
	hash2 := ComputeHash(input)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	hash3 := ComputeHash([]byte("different data"))
	assert.NotEqual(t, hash, hash3)

	// Empty input should work
	emptyHash := ComputeHash([]byte{})
	assert.Len(t, emptyHash, 64)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash)
}
