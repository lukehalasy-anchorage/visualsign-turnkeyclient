package manifest

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestartPolicyMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		policy   RestartPolicy
		expected string
	}{
		{
			name:     "RestartPolicyNever",
			policy:   RestartPolicyNever,
			expected: `"Never"`,
		},
		{
			name:     "RestartPolicyAlways",
			policy:   RestartPolicyAlways,
			expected: `"Always"`,
		},
		{
			name:     "Unknown policy",
			policy:   RestartPolicy(99),
			expected: `"Unknown(99)"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := tt.policy.MarshalJSON()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, string(jsonBytes))
		})
	}
}

func TestRestartPolicyString(t *testing.T) {
	tests := []struct {
		name     string
		policy   RestartPolicy
		expected string
	}{
		{
			name:     "RestartPolicyNever",
			policy:   RestartPolicyNever,
			expected: "Never",
		},
		{
			name:     "RestartPolicyAlways",
			policy:   RestartPolicyAlways,
			expected: "Always",
		},
		{
			name:     "Unknown policy",
			policy:   RestartPolicy(255),
			expected: "Unknown(255)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRestartPolicyInStruct(t *testing.T) {
	// Test that RestartPolicy works correctly when embedded in a struct
	type TestStruct struct {
		Policy RestartPolicy `json:"policy"`
	}

	t.Run("marshal struct with policy", func(t *testing.T) {
		s := TestStruct{Policy: RestartPolicyAlways}
		jsonBytes, err := json.Marshal(s)
		assert.NoError(t, err)
		assert.Equal(t, `{"policy":"Always"}`, string(jsonBytes))
	})

	t.Run("marshal struct with unknown policy", func(t *testing.T) {
		s := TestStruct{Policy: RestartPolicy(42)}
		jsonBytes, err := json.Marshal(s)
		assert.NoError(t, err)
		assert.Equal(t, `{"policy":"Unknown(42)"}`, string(jsonBytes))
	})
}

func TestRestartPolicyValues(t *testing.T) {
	// Test that the constants have the expected values
	assert.Equal(t, RestartPolicy(0), RestartPolicyNever)
	assert.Equal(t, RestartPolicy(1), RestartPolicyAlways)
}
