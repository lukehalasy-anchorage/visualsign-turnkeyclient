package cmd

import (
	"encoding/hex"
	"testing"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePCRs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []nitroverifier.PCRRule
		wantError bool
	}{
		{
			name:      "empty string",
			input:     "",
			want:      nil,
			wantError: false,
		},
		{
			name:  "single PCR",
			input: "0:abc123",
			want: []nitroverifier.PCRRule{
				{Index: 0, Value: mustDecodeHex("abc123")},
			},
			wantError: false,
		},
		{
			name:  "multiple PCRs",
			input: "0:abc123,1:def456",
			want: []nitroverifier.PCRRule{
				{Index: 0, Value: mustDecodeHex("abc123")},
				{Index: 1, Value: mustDecodeHex("def456")},
			},
			wantError: false,
		},
		{
			name:  "PCRs with whitespace",
			input: " 0:abc123 , 1:def456 ",
			want: []nitroverifier.PCRRule{
				{Index: 0, Value: mustDecodeHex("abc123")},
				{Index: 1, Value: mustDecodeHex("def456")},
			},
			wantError: false,
		},
		{
			name:  "long PCR values (SHA384)",
			input: "0:f2479c809cbfa117cfa3f9a91c12faf602a8d8f5c06afd8d3c7d9f48c49fe048385802da593e6cc7c70c0b8c519625de",
			want: []nitroverifier.PCRRule{
				{Index: 0, Value: mustDecodeHex("f2479c809cbfa117cfa3f9a91c12faf602a8d8f5c06afd8d3c7d9f48c49fe048385802da593e6cc7c70c0b8c519625de")},
			},
			wantError: false,
		},
		{
			name:  "PCR indices out of order",
			input: "3:abc123,0:def456,1:111111",
			want: []nitroverifier.PCRRule{
				{Index: 3, Value: mustDecodeHex("abc123")},
				{Index: 0, Value: mustDecodeHex("def456")},
				{Index: 1, Value: mustDecodeHex("111111")},
			},
			wantError: false,
		},
		{
			name:      "invalid format - no colon",
			input:     "0abc123",
			wantError: true,
		},
		{
			name:      "invalid format - multiple colons",
			input:     "0:abc:123",
			wantError: true, // Colon is not a valid hex character
		},
		{
			name:      "invalid PCR index",
			input:     "invalid:abc123",
			wantError: true,
		},
		{
			name:      "negative PCR index",
			input:     "-1:abc123",
			wantError: true,
		},
		{
			name:      "invalid hex value",
			input:     "0:xyz123",
			wantError: true,
		},
		{
			name:      "odd-length hex value",
			input:     "0:abc",
			wantError: true,
		},
		{
			name:  "empty PCR entries ignored",
			input: "0:abc123,,1:def456",
			want: []nitroverifier.PCRRule{
				{Index: 0, Value: mustDecodeHex("abc123")},
				{Index: 1, Value: mustDecodeHex("def456")},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePCRs(tt.input)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, len(tt.want), len(got), "number of PCR rules should match")

			for i := range tt.want {
				assert.Equal(t, tt.want[i].Index, got[i].Index, "PCR index should match")
				assert.Equal(t, tt.want[i].Value, got[i].Value, "PCR value should match")
			}
		})
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
