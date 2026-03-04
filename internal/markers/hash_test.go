// Copyright 2026 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing
// permissions and limitations under the License.

package markers

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	defer DisableHashing()

	testCases := []struct {
		name     string
		input    string
		salt     []byte
		expected string
	}{
		{
			name:     "simple string",
			input:    "test",
			salt:     nil,
			expected: "9f86d081",
		},
		{
			name:     "empty string",
			input:    "",
			salt:     nil,
			expected: "e3b0c442",
		},
		{
			name:     "input exceeding hash length",
			input:    strings.Repeat("long-input-", 100),
			salt:     nil,
			expected: "130ca5ec",
		},
		{
			name:     "numeric string",
			input:    "12345",
			salt:     nil,
			expected: "5994471a",
		},
		{
			name:     "simple string with salt",
			input:    "test",
			salt:     []byte("my-salt"),
			expected: "ac2fdbab",
		},
		{
			name:     "empty string with salt",
			input:    "",
			salt:     []byte("my-salt"),
			expected: "e5d13fde",
		},
	}

	t.Run("string", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				EnableHashing(tc.salt)

				resultString := hashString(tc.input)
				if resultString != tc.expected {
					t.Errorf("hashString(%q) = %q, expected %q", tc.input, resultString, tc.expected)
				}
				if len(resultString) != 8 {
					t.Errorf("hashString(%q) returned %d characters, expected 8", tc.input, len(resultString))
				}
			})
		}
	})

	t.Run("bytes", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				EnableHashing(tc.salt)
				resultBytes := hashBytes([]byte(tc.input))
				if string(resultBytes) != tc.expected {
					t.Errorf("hashBytes(%q) = %q, expected %q", tc.input, resultBytes, tc.expected)
				}
				if len(resultBytes) != 8 {
					t.Errorf("hashBytes(%q) returned %d bytes, expected 8", tc.input, len(resultBytes))
				}
			})
		}
	})
}

func TestHashDeterminism(t *testing.T) {
	defer DisableHashing()

	EnableHashing(nil)

	input := "test-value"
	input2 := "different-value"

	t.Run("hashString", func(t *testing.T) {
		// Same input should always produce same output
		hash1 := hashString(input)
		hash2 := hashString(input)

		if hash1 != hash2 {
			t.Errorf("hashString is not deterministic: hashString(%q) returned %q and %q", input, hash1, hash2)
		}

		// Different inputs should produce different outputs
		hash3 := hashString(input2)

		if hash1 == hash3 {
			t.Errorf("Different inputs produced same hash: hashString(%q) = hashString(%q) = %q", input, input2, hash1)
		}
	})

	t.Run("hashBytes", func(t *testing.T) {
		// Same input should always produce same output
		hash1 := hashBytes([]byte(input))
		hash2 := hashBytes([]byte(input))

		if string(hash1) != string(hash2) {
			t.Errorf("hashBytes is not deterministic: hashBytes(%q) returned %q and %q", input, hash1, hash2)
		}

		// Different inputs should produce different outputs
		hash3 := hashBytes([]byte(input2))

		if string(hash1) == string(hash3) {
			t.Errorf("Different inputs produced same hash: hashBytes(%q) = hashBytes(%q) = %q", input, input2, hash1)
		}
	})
}
