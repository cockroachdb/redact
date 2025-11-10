// Copyright 2025 The Cockroach Authors.
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
	// Save original state and restore after test
	hashConfig.RLock()
	originalEnabled := hashConfig.enabled
	originalSalt := hashConfig.salt
	hashConfig.RUnlock()
	defer func() {
		hashConfig.Lock()
		hashConfig.enabled = originalEnabled
		hashConfig.salt = originalSalt
		hashConfig.Unlock()
	}()

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
			expected: "a94a8fe5",
		},
		{
			name:     "empty string",
			input:    "",
			salt:     nil,
			expected: "da39a3ee",
		},
		{
			name:     "input exceeding hash length",
			input:    strings.Repeat("long-input-", 100),
			salt:     nil,
			expected: "c375461f",
		},
		{
			name:     "numeric string",
			input:    "12345",
			salt:     nil,
			expected: "8cb2237d",
		},
		{
			name:     "simple string with salt",
			input:    "test",
			salt:     []byte("my-salt"),
			expected: "c48ce5fd",
		},
		{
			name:     "empty string with salt",
			input:    "",
			salt:     []byte("my-salt"),
			expected: "7b1829af",
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
	// Save original state and restore after test
	hashConfig.RLock()
	originalEnabled := hashConfig.enabled
	originalSalt := hashConfig.salt
	hashConfig.RUnlock()
	defer func() {
		hashConfig.Lock()
		hashConfig.enabled = originalEnabled
		hashConfig.salt = originalSalt
		hashConfig.Unlock()
	}()

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
