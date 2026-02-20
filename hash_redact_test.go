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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package redact

import (
	"reflect"
	"testing"
)

// TestHashRedact_EndToEnd tests the full Sprintf → Redact pipeline for hash types.
func TestHashRedact_EndToEnd(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	if expected := RedactableString("user=‹†alice›"); s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}

	redacted := s.Redact()
	if expected := RedactableString("user=‹2bd806c9›"); redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
}

// TestHashRedact_DisabledHashing verifies hash markers are fully redacted when hashing is disabled.
func TestHashRedact_DisabledHashing(t *testing.T) {
	s := Sprintf("user=%s", HashString("alice"))

	redacted := s.Redact()
	expected := RedactableString("user=‹×›")
	if redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
}

// TestHashRedact_MixedMarkers verifies that regular and hash markers in the same string
// are handled correctly: regular markers become ‹×›, hash markers become ‹hash›.
func TestHashRedact_MixedMarkers(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s action=%s", HashString("alice"), "login")
	redacted := s.Redact()

	expected := RedactableString("user=‹2bd806c9› action=‹×›")
	if redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
}

// TestHashRedact_FormatVerbs verifies that format verbs are respected for hash types.
func TestHashRedact_FormatVerbs(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	testData := []struct {
		name         string
		format       RedactableString
		expectedPre  RedactableString
		expectedPost RedactableString
	}{
		{"padded int", Sprintf("%05d", HashInt(42)), "‹†00042›", "‹be9c43d5›"},
		{"hex int", Sprintf("%x", HashInt(255)), "‹†ff›", "‹05a9bf22›"},
		{"quoted string", Sprintf("%q", HashString("hello")), "‹†\"hello\"›", "‹5aa762ae›"},
		{"default int", Sprintf("%d", HashInt(123)), "‹†123›", "‹a665a459›"},
		{"float", Sprintf("%f", HashFloat(3.14)), "‹†3.140000›", "‹f0f4a726›"},
		{"float precision", Sprintf("%.2f", HashFloat(3.14159)), "‹†3.14›", "‹2efff126›"},
	}

	for _, tc := range testData {
		t.Run(tc.name, func(t *testing.T) {
			if tc.format != tc.expectedPre {
				t.Errorf("pre-redaction: expected %q, got %q", tc.expectedPre, tc.format)
			}
			if redacted := tc.format.Redact(); redacted != tc.expectedPost {
				t.Errorf("post-redaction: expected %q, got %q", tc.expectedPost, redacted)
			}
		})
	}
}

// TestHashRedact_SafeWrapping verifies that Safe() takes priority over HashValue.
func TestHashRedact_SafeWrapping(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", Safe(HashString("alice")))
	expected := RedactableString("user=alice")
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

// TestHashRedact_UnsafeWrapping verifies that Unsafe() takes priority over HashValue.
func TestHashRedact_UnsafeWrapping(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", Unsafe(HashString("alice")))
	if expected := RedactableString("user=‹alice›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("user=‹×›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("user=‹×›"), redacted)
	}
}

// TestHashRedact_AllHashTypes verifies all concrete Hash* types work end-to-end.
func TestHashRedact_AllHashTypes(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	testData := []struct {
		name         string
		format       RedactableString
		expectedPre  RedactableString
		expectedPost RedactableString
	}{
		{"HashString", Sprintf("%s", HashString("test")), "‹†test›", "‹9f86d081›"},
		{"HashInt", Sprintf("%d", HashInt(42)), "‹†42›", "‹73475cb4›"},
		{"HashUint", Sprintf("%d", HashUint(42)), "‹†42›", "‹73475cb4›"},
		{"HashFloat", Sprintf("%f", HashFloat(3.14)), "‹†3.140000›", "‹f0f4a726›"},
		{"HashRune", Sprintf("%c", HashRune('A')), "‹†A›", "‹559aead0›"},
		{"HashByte", Sprintf("%d", HashByte(0xFF)), "‹†255›", "‹9556b824›"},
	}

	for _, tc := range testData {
		t.Run(tc.name, func(t *testing.T) {
			if tc.format != tc.expectedPre {
				t.Errorf("pre-redaction: expected %q, got %q", tc.expectedPre, tc.format)
			}
			if redacted := tc.format.Redact(); redacted != tc.expectedPost {
				t.Errorf("post-redaction: expected %q, got %q", tc.expectedPost, redacted)
			}
		})
	}
}

// TestHashRedact_RedactableBytes verifies the RedactableBytes.Redact() hash path.
func TestHashRedact_RedactableBytes(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	redacted := s.ToBytes().Redact()

	expected := RedactableBytes("user=‹2bd806c9›")
	if string(redacted) != string(expected) {
		t.Errorf("expected %q, got %q", expected, redacted)
	}

	// String and bytes redaction should produce the same result.
	if string(redacted) != string(s.Redact()) {
		t.Errorf("string and bytes redaction differ: %q vs %q", s.Redact(), redacted)
	}
}

// TestHashRedact_StripMarkers verifies StripMarkers on hash-marked strings.
func TestHashRedact_StripMarkers(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	if stripped := s.StripMarkers(); stripped != "user=alice" {
		t.Errorf("expected %q, got %q", "user=alice", stripped)
	}
}

// TestHashRedact_EnableAfterFormat verifies that hash markers written before
// EnableHashing are correctly hashed when Redact() is called after enabling.
func TestHashRedact_EnableAfterFormat(t *testing.T) {
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	if expected := RedactableString("user=‹†alice›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	EnableHashing(nil)
	if redacted := s.Redact(); redacted != RedactableString("user=‹2bd806c9›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("user=‹2bd806c9›"), redacted)
	}
}

// TestHashRedact_MultipleHashMarkers verifies multiple hash markers in one string.
func TestHashRedact_MultipleHashMarkers(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("a=%s b=%s c=%s", HashString("x"), HashString("y"), HashString("z"))
	if expected := RedactableString("a=‹†x› b=‹†y› c=‹†z›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("a=‹2d711642› b=‹a1fce436› c=‹594e519a›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("a=‹2d711642› b=‹a1fce436› c=‹594e519a›"), redacted)
	}
}

// TestHashRedact_WithSalt verifies that salted hashing produces different output than unsalted.
func TestHashRedact_WithSalt(t *testing.T) {
	defer DisableHashing()

	EnableHashing(nil)
	unsalted := Sprintf("%s", HashString("alice")).Redact()
	if expected := RedactableString("‹2bd806c9›"); unsalted != expected {
		t.Errorf("unsalted: expected %q, got %q", expected, unsalted)
	}

	EnableHashing([]byte("my-secret-salt"))
	salted := Sprintf("%s", HashString("alice")).Redact()
	if expected := RedactableString("‹cffebd45›"); salted != expected {
		t.Errorf("salted: expected %q, got %q", expected, salted)
	}
}

// TestHashRedact_StructWithHashField exercises printValue
// where a struct contains a HashValue field alongside a regular unsafe field.
func TestHashRedact_StructWithHashField(t *testing.T) {
	type User struct {
		Name HashString
		Age  int
	}

	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("%v", User{Name: "alice", Age: 30})
	if expected := RedactableString("{‹†alice› ‹30›}"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("{‹2bd806c9› ‹×›}") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("{‹2bd806c9› ‹×›}"), redacted)
	}
}

// TestHashRedact_ReflectValue exercises the reflect.Value case in printArg,
// where a reflect.Value wrapping a HashValue is passed as an argument.
func TestHashRedact_ReflectValue(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	v := reflect.ValueOf(HashString("alice"))
	s := Sprintf("%v", v)
	if expected := RedactableString("‹†alice›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("‹2bd806c9›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("‹2bd806c9›"), redacted)
	}
}

// TestHashRedact_Sprint verifies Sprint with HashValue.
func TestHashRedact_Sprint(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprint(HashString("alice"))
	if expected := RedactableString("‹†alice›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("‹2bd806c9›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("‹2bd806c9›"), redacted)
	}
}

// TestHashRedact_HashBytes verifies HashBytes ([]byte type) end-to-end.``
func TestHashRedact_HashBytes(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("%s", HashBytes([]byte("secret")))
	if expected := RedactableString("‹†secret›"); s != expected {
		t.Errorf("pre-redaction: expected %q, got %q", expected, s)
	}

	if redacted := s.Redact(); redacted != RedactableString("‹2bb80d53›") {
		t.Errorf("post-redaction: expected %q, got %q", RedactableString("‹2bb80d53›"), redacted)
	}
}

// TestHashRedact_ToggleTransitions verifies Enable -> Disable -> Enable transitions.
func TestHashRedact_ToggleTransitions(t *testing.T) {
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))

	EnableHashing(nil)
	if redacted := s.Redact(); redacted != RedactableString("user=‹2bd806c9›") {
		t.Errorf("unsalted enabled: expected %q, got %q", RedactableString("user=‹2bd806c9›"), redacted)
	}

	DisableHashing()
	if redacted := s.Redact(); redacted != RedactableString("user=‹×›") {
		t.Errorf("disabled: expected %q, got %q", RedactableString("user=‹×›"), redacted)
	}

	EnableHashing([]byte("my-secret-salt"))
	if redacted := s.Redact(); redacted != RedactableString("user=‹cffebd45›") {
		t.Errorf("salted re-enabled: expected %q, got %q", RedactableString("user=‹cffebd45›"), redacted)
	}
}

// TestHashRedact_RedactableBytesDisabled verifies bytes-path behavior when hashing is disabled.
func TestHashRedact_RedactableBytesDisabled(t *testing.T) {
	defer DisableHashing()
	DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	if redacted := s.ToBytes().Redact(); string(redacted) != string(RedactableBytes("user=‹×›")) {
		t.Errorf("expected %q, got %q", RedactableBytes("user=‹×›"), redacted)
	}
}
