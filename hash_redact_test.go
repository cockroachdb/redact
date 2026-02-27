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
	"strings"
	"sync"
	"testing"
)

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

func TestHashRedact_DisabledHashing(t *testing.T) {
	s := Sprintf("user=%s", HashString("alice"))

	redacted := s.Redact()
	expected := RedactableString("user=‹×›")
	if redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
}

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

func TestHashRedact_SafeWrapping(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", Safe(HashString("alice")))
	expected := RedactableString("user=alice")
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

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

func TestHashRedact_RedactableBytes(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	redacted := s.ToBytes().Redact()

	expected := RedactableBytes("user=‹2bd806c9›")
	if string(redacted) != string(expected) {
		t.Errorf("expected %q, got %q", expected, redacted)
	}

	if string(redacted) != string(s.Redact()) {
		t.Errorf("string and bytes redaction differ: %q vs %q", s.Redact(), redacted)
	}
}

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

func TestHashRedact_RedactableBytesDisabled(t *testing.T) {
	DisableHashing()

	s := Sprintf("user=%s", HashString("alice"))
	if redacted := s.ToBytes().Redact(); string(redacted) != string(RedactableBytes("user=‹×›")) {
		t.Errorf("expected %q, got %q", RedactableBytes("user=‹×›"), redacted)
	}
}

// TestHashRedact_ConcurrentToggle exercises concurrent Enable/Disable/Redact
// calls to verify there are no races or panics under contention.
func TestHashRedact_ConcurrentToggle(t *testing.T) {
	defer DisableHashing()

	s := Sprintf("user=%s action=%s", HashString("alice"), "login")

	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 500

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch id % 3 {
				case 0:
					EnableHashing(nil)
				case 1:
					EnableHashing([]byte("salt"))
				case 2:
					DisableHashing()
				}
				redacted := s.Redact()
				// The raw value must never leak through redaction.
				if strings.Contains(string(redacted), "alice") {
					t.Errorf("raw value leaked: %q", redacted)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestHashRedact_AdjacentZones verifies that the buffer's zone-merging
// optimization does not combine a hash zone with an adjacent unsafe zone.
func TestHashRedact_AdjacentZones(t *testing.T) {
	EnableHashing(nil)
	defer DisableHashing()

	tests := []struct {
		name         string
		input        RedactableString
		expectedPre  string
		expectedPost string
	}{
		{
			"hash then unsafe (no separator)",
			Sprintf("%s%s", HashString("alice"), "bob"),
			"‹†alice›‹bob›",
			"‹2bd806c9›‹×›",
		},
		{
			"unsafe then hash (no separator)",
			Sprintf("%s%s", "bob", HashString("alice")),
			"‹bob›‹†alice›",
			"‹×›‹2bd806c9›",
		},
		{
			"hash then hash (no separator)",
			Sprintf("%s%s", HashString("alice"), HashString("bob")),
			"‹†alice›‹†bob›",
			"‹2bd806c9›‹81b637d8›",
		},
		{
			"unsafe then unsafe (merge is ok)",
			Sprintf("%s%s", "alice", "bob"),
			"‹alicebob›",
			"‹×›",
		},
		{
			"hash with space separator",
			Sprintf("%s%s", "alice", HashString("bob")),
			"‹alice›‹†bob›",
			"‹×›‹81b637d8›",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.input) != tc.expectedPre {
				t.Errorf("pre-redaction:\n  expected %q\n  got      %q", tc.expectedPre, tc.input)
			}
			if redacted := tc.input.Redact(); string(redacted) != tc.expectedPost {
				t.Errorf("post-redaction:\n  expected %q\n  got      %q", tc.expectedPost, redacted)
			}
		})
	}
}
