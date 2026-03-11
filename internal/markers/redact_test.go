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

func TestRedact(t *testing.T) {
	// Pre-compute known hashes for use in expected outputs.
	EnableHashing(nil)
	aliceHash := string(appendHash(nil, []byte("alice")))
	emptyHash := string(appendHash(nil, []byte("")))
	DisableHashing()

	testCases := []struct {
		name        string
		input       string
		hashEnabled bool
		expected    string
	}{
		// --- Empty and no-marker inputs ---
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "x",
			expected: "x",
		},
		{
			name:     "two characters",
			input:    "ab",
			expected: "ab",
		},
		{
			name:     "plain text no markers",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "long plain text",
			input:    strings.Repeat("abcdefghij", 100),
			expected: strings.Repeat("abcdefghij", 100),
		},

		// --- Single regular marker ---
		{
			name:     "single marker alone",
			input:    StartS + "secret" + EndS,
			expected: RedactedS,
		},
		{
			name:     "marker with leading safe text",
			input:    "safe " + StartS + "secret" + EndS,
			expected: "safe " + RedactedS,
		},
		{
			name:     "marker with trailing safe text",
			input:    StartS + "secret" + EndS + " safe",
			expected: RedactedS + " safe",
		},
		{
			name:     "marker with surrounding safe text",
			input:    "before " + StartS + "secret" + EndS + " after",
			expected: "before " + RedactedS + " after",
		},
		{
			name:     "empty marker contents",
			input:    StartS + EndS,
			expected: RedactedS,
		},
		{
			name:     "single-char marker contents",
			input:    StartS + "x" + EndS,
			expected: RedactedS,
		},

		// --- Multiple regular markers ---
		{
			name:     "two adjacent markers",
			input:    StartS + "a" + EndS + StartS + "b" + EndS,
			expected: RedactedS + RedactedS,
		},
		{
			name:     "two markers with safe text between",
			input:    StartS + "a" + EndS + " mid " + StartS + "b" + EndS,
			expected: RedactedS + " mid " + RedactedS,
		},
		{
			name:     "three markers",
			input:    StartS + "1" + EndS + StartS + "2" + EndS + StartS + "3" + EndS,
			expected: RedactedS + RedactedS + RedactedS,
		},
		{
			name:     "many markers interleaved with safe text",
			input:    "a" + StartS + "1" + EndS + "b" + StartS + "2" + EndS + "c" + StartS + "3" + EndS + "d",
			expected: "a" + RedactedS + "b" + RedactedS + "c" + RedactedS + "d",
		},

		// --- Unclosed markers (no closing ›) ---
		{
			name:     "bare start marker at end",
			input:    "hello " + StartS,
			expected: "hello " + StartS,
		},
		{
			name:     "start marker with content but no close",
			input:    "hello " + StartS + "open",
			expected: "hello " + StartS + "open",
		},
		{
			name:     "closed marker then unclosed marker",
			input:    StartS + "a" + EndS + " " + StartS + "open",
			expected: RedactedS + " " + StartS + "open",
		},

		// --- Marker ending exactly at string boundary ---
		{
			name:     "marker consumes entire remaining string",
			input:    "prefix " + StartS + "val" + EndS,
			expected: "prefix " + RedactedS,
		},

		// --- Already-redacted marker (‹×›) ---
		{
			name:     "already redacted marker",
			input:    RedactedS,
			expected: RedactedS,
		},
		{
			name:     "safe text around already-redacted marker",
			input:    "x " + RedactedS + " y",
			expected: "x " + RedactedS + " y",
		},

		// --- Lone end markers (pass through as safe text) ---
		{
			name:     "lone end marker",
			input:    EndS + " trailing",
			expected: EndS + " trailing",
		},
		{
			name:     "end marker before start marker",
			input:    EndS + StartS + "val" + EndS,
			expected: EndS + RedactedS,
		},

		// --- Unicode content ---
		{
			name:     "unicode content inside markers",
			input:    StartS + "日本語" + EndS,
			expected: RedactedS,
		},
		{
			name:     "safe unicode text around markers",
			input:    "こんにちは " + StartS + "secret" + EndS + " 世界",
			expected: "こんにちは " + RedactedS + " 世界",
		},

		// --- Hash markers with hashing DISABLED ---
		{
			name:     "hash marker hashing disabled",
			input:    StartS + HashPrefixS + "alice" + EndS,
			expected: RedactedS,
		},
		{
			name:     "mixed hash and regular markers hashing disabled",
			input:    StartS + "regular" + EndS + " " + StartS + HashPrefixS + "alice" + EndS,
			expected: RedactedS + " " + RedactedS,
		},

		// --- Hash markers with hashing ENABLED ---
		{
			name:        "hash marker hashing enabled",
			input:       StartS + HashPrefixS + "alice" + EndS,
			hashEnabled: true,
			expected:    StartS + aliceHash + EndS,
		},
		{
			name:        "regular marker with hashing enabled",
			input:       StartS + "secret" + EndS,
			hashEnabled: true,
			expected:    RedactedS,
		},
		{
			name:        "mixed regular and hash markers hashing enabled",
			input:       StartS + "secret" + EndS + " " + StartS + HashPrefixS + "alice" + EndS,
			hashEnabled: true,
			expected:    RedactedS + " " + StartS + aliceHash + EndS,
		},
		{
			name:        "hash marker then regular marker hashing enabled",
			input:       StartS + HashPrefixS + "alice" + EndS + StartS + "secret" + EndS,
			hashEnabled: true,
			expected:    StartS + aliceHash + EndS + RedactedS,
		},
		{
			name:        "empty marker with hashing enabled",
			input:       StartS + EndS,
			hashEnabled: true,
			expected:    RedactedS,
		},
		{
			name:        "hash prefix only no value hashing enabled",
			input:       StartS + HashPrefixS + EndS,
			hashEnabled: true,
			expected:    StartS + emptyHash + EndS,
		},
		{
			name:        "multiple identical hash markers hashing enabled",
			input:       "a=" + StartS + HashPrefixS + "alice" + EndS + " b=" + StartS + HashPrefixS + "alice" + EndS,
			hashEnabled: true,
			expected:    "a=" + StartS + aliceHash + EndS + " b=" + StartS + aliceHash + EndS,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hashEnabled {
				EnableHashing(nil)
				defer DisableHashing()
			}

			// Test RedactableString.Redact().
			got := RedactableString(tc.input).Redact()
			if string(got) != tc.expected {
				t.Errorf("RedactableString(%q).Redact()\n  got:  %q\n  want: %q",
					tc.input, got, tc.expected)
			}

			// Test RedactableBytes.Redact() produces equivalent output.
			gotBytes := RedactableBytes(tc.input).Redact()
			if string(gotBytes) != tc.expected {
				t.Errorf("RedactableBytes(%q).Redact()\n  got:  %q\n  want: %q",
					tc.input, string(gotBytes), tc.expected)
			}
		})
	}
}
