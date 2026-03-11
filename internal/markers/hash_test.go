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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			EnableHashing(tc.salt)

			result := string(appendHash(nil, []byte(tc.input)))
			if result != tc.expected {
				t.Errorf("appendHash(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
			if len(result) != 8 {
				t.Errorf("appendHash(%q) returned %d characters, expected 8", tc.input, len(result))
			}
		})
	}
}

func TestHashDeterminism(t *testing.T) {
	defer DisableHashing()

	EnableHashing(nil)

	input := "test-value"
	input2 := "different-value"

	// Same input should always produce same output.
	hash1 := string(appendHash(nil, []byte(input)))
	hash2 := string(appendHash(nil, []byte(input)))

	if hash1 != hash2 {
		t.Errorf("appendHash is not deterministic: returned %q and %q for %q", hash1, hash2, input)
	}

	// Different inputs should produce different outputs.
	hash3 := string(appendHash(nil, []byte(input2)))

	if hash1 == hash3 {
		t.Errorf("Different inputs produced same hash: appendHash(%q) = appendHash(%q) = %q", input, input2, hash1)
	}
}
