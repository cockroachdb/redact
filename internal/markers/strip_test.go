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
// See the License for the specific language governing permissions and
// limitations under the License.

package markers

import (
	"strings"
	"testing"
)

func TestStripMarkers(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
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
			name:     "plain text no markers",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "long plain text",
			input:    strings.Repeat("abcdefghij", 100),
			expected: strings.Repeat("abcdefghij", 100),
		},

		// --- Single marker characters ---
		{
			name:     "lone start marker",
			input:    StartS,
			expected: "",
		},
		{
			name:     "lone end marker",
			input:    EndS,
			expected: "",
		},
		{
			name:     "lone hash prefix",
			input:    HashPrefixS,
			expected: "",
		},

		// --- Markers around text ---
		{
			name:     "start and end around text",
			input:    StartS + "secret" + EndS,
			expected: "secret",
		},
		{
			name:     "markers with leading safe text",
			input:    "safe " + StartS + "secret" + EndS,
			expected: "safe secret",
		},
		{
			name:     "markers with trailing safe text",
			input:    StartS + "secret" + EndS + " safe",
			expected: "secret safe",
		},
		{
			name:     "markers with surrounding safe text",
			input:    "before " + StartS + "secret" + EndS + " after",
			expected: "before secret after",
		},
		{
			name:     "empty marker contents",
			input:    StartS + EndS,
			expected: "",
		},

		// --- Multiple markers ---
		{
			name:     "two adjacent markers",
			input:    StartS + "a" + EndS + StartS + "b" + EndS,
			expected: "ab",
		},
		{
			name:     "two markers with safe text between",
			input:    StartS + "a" + EndS + " mid " + StartS + "b" + EndS,
			expected: "a mid b",
		},
		{
			name:     "many markers interleaved with safe text",
			input:    "a" + StartS + "1" + EndS + "b" + StartS + "2" + EndS + "c",
			expected: "a1b2c",
		},

		// --- Hash prefix marker ---
		{
			name:     "hash marker stripped",
			input:    StartS + HashPrefixS + "alice" + EndS,
			expected: "alice",
		},
		{
			name:     "hash prefix in middle of text",
			input:    "user=" + StartS + HashPrefixS + "alice" + EndS,
			expected: "user=alice",
		},
		{
			name:     "multiple hash prefixes",
			input:    StartS + HashPrefixS + "a" + EndS + " " + StartS + HashPrefixS + "b" + EndS,
			expected: "a b",
		},

		// --- Redacted marker (‹×›) ---
		{
			name:     "redacted marker stripped",
			input:    RedactedS,
			expected: "×",
		},
		{
			name:     "redacted marker with safe text",
			input:    "x " + RedactedS + " y",
			expected: "x × y",
		},

		// --- Unicode content ---
		{
			name:     "unicode content inside markers",
			input:    StartS + "日本語" + EndS,
			expected: "日本語",
		},
		{
			name:     "safe unicode text around markers",
			input:    "こんにちは " + StartS + "secret" + EndS + " 世界",
			expected: "こんにちは secret 世界",
		},

		// --- Multiple marker characters in sequence ---
		{
			name:     "consecutive start markers",
			input:    StartS + StartS + StartS,
			expected: "",
		},
		{
			name:     "consecutive end markers",
			input:    EndS + EndS + EndS,
			expected: "",
		},
		{
			name:     "mixed consecutive markers",
			input:    StartS + EndS + HashPrefixS + StartS + EndS,
			expected: "",
		},

		// --- Markers at boundaries ---
		{
			name:     "start marker at beginning",
			input:    StartS + "rest of string",
			expected: "rest of string",
		},
		{
			name:     "end marker at end",
			input:    "rest of string" + EndS,
			expected: "rest of string",
		},
		{
			name:     "all three marker types",
			input:    "a" + StartS + "b" + HashPrefixS + "c" + EndS + "d",
			expected: "abcd",
		},

		// --- Newlines and whitespace ---
		{
			name:     "markers around whitespace",
			input:    StartS + " \t\n " + EndS,
			expected: " \t\n ",
		},
		{
			name:     "newlines between markers",
			input:    StartS + "a" + EndS + "\n" + StartS + "b" + EndS,
			expected: "a\nb",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test RedactableString.StripMarkers().
			got := RedactableString(tc.input).StripMarkers()
			if got != tc.expected {
				t.Errorf("RedactableString(%q).StripMarkers()\n  got:  %q\n  want: %q",
					tc.input, got, tc.expected)
			}

			// Test RedactableBytes.StripMarkers().
			gotBytes := RedactableBytes(tc.input).StripMarkers()
			if string(gotBytes) != tc.expected {
				t.Errorf("RedactableBytes(%q).StripMarkers()\n  got:  %q\n  want: %q",
					tc.input, string(gotBytes), tc.expected)
			}
		})
	}
}

func TestEscapeMarkers(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no markers",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "start marker escaped",
			input:    "a" + StartS + "b",
			expected: "a" + EscapeMarkS + "b",
		},
		{
			name:     "end marker escaped",
			input:    "a" + EndS + "b",
			expected: "a" + EscapeMarkS + "b",
		},
		{
			name:     "hash prefix escaped",
			input:    "a" + HashPrefixS + "b",
			expected: "a" + EscapeMarkS + "b",
		},
		{
			name:     "all markers escaped",
			input:    StartS + EndS + HashPrefixS,
			expected: EscapeMarkS + EscapeMarkS + EscapeMarkS,
		},
		{
			name:     "markers in context",
			input:    "a " + StartS + " b " + EndS + " c",
			expected: "a " + EscapeMarkS + " b " + EscapeMarkS + " c",
		},
		{
			name:     "unicode with markers",
			input:    "日本" + StartS + "語",
			expected: "日本" + EscapeMarkS + "語",
		},
		{
			name:     "long string with markers",
			input:    strings.Repeat("abc", 50) + StartS + strings.Repeat("def", 50),
			expected: strings.Repeat("abc", 50) + EscapeMarkS + strings.Repeat("def", 50),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := EscapeMarkers([]byte(tc.input))
			if string(got) != tc.expected {
				t.Errorf("EscapeMarkers(%q)\n  got:  %q\n  want: %q",
					tc.input, string(got), tc.expected)
			}
		})
	}
}

func BenchmarkStripMarkers_String(b *testing.B) {
	s := RedactableString("user=" + StartS + "alice" + EndS + " action=" + StartS + "login" + EndS + " status=ok")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.StripMarkers()
	}
}

func BenchmarkStripMarkers_Bytes(b *testing.B) {
	s := RedactableBytes("user=" + StartS + "alice" + EndS + " action=" + StartS + "login" + EndS + " status=ok")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.StripMarkers()
	}
}

func BenchmarkStripMarkers_NoMarkers(b *testing.B) {
	s := RedactableString("hello world this is a plain string with no markers at all")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.StripMarkers()
	}
}

func BenchmarkEscapeMarkers(b *testing.B) {
	s := []byte("a " + StartS + " b " + EndS + " c " + HashPrefixS + " d")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EscapeMarkers(s)
	}
}
