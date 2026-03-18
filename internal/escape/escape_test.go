// Copyright 2021 The Cockroach Authors.
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

package escape

import "testing"

func TestInternalEscape(t *testing.T) {
	testCases := []struct {
		input    []byte
		start    int
		bnl      bool
		strip    bool
		expected string
	}{
		// Empty / nil inputs.
		{nil, 0, false, false, ""},
		{[]byte(""), 0, false, false, ""},

		// Pure ASCII, no markers.
		{[]byte("abc"), 0, false, false, "abc"},
		{[]byte("hello world 12345"), 0, false, false, "hello world 12345"},

		// Start marker escaping.
		{[]byte("‹abc›"), 0, false, false, "?abc?"},
		{[]byte("‹abc›"), 3, false, false, "‹abc?"},
		{[]byte("‹abc›def›ghi"), 3, false, false, "‹abc?def?ghi"},
		{[]byte("‹abc›"), len([]byte("‹abc›")), false, false, "‹abc›"},
		{[]byte("‹abc›‹def›"), len([]byte("‹abc›")), false, false, "‹abc›?def?"},

		// Multiple markers in sequence.
		{[]byte("‹‹‹"), 0, false, false, "???"},
		{[]byte("›››"), 0, false, false, "???"},
		{[]byte("‹›‹›"), 0, false, false, "????"},

		// Markers with surrounding text.
		{[]byte("before‹mid›after"), 0, false, false, "before?mid?after"},
		{[]byte("a‹b›c‹d›e"), 0, false, false, "a?b?c?d?e"},

		// Newline handling (breakNewLines=false, should not break).
		{[]byte("‹abc›\n‹d\nef›"), len([]byte("‹abc›")), false, false, "‹abc›\n?d\nef?"},

		// Newline handling (breakNewLines=true).
		{[]byte("abc\n‹d\nef›\n \n\n "), len([]byte("abc")), true, false, "abc›\n‹?d›\n‹ef?›\n‹ ›\n\n‹ "},
		{[]byte("abc\n‹d\nef›\n \n\n "), len([]byte("abc")), true, true, "abc›\n‹?d›\n‹ef?"},
		{[]byte("‹abc› ‹def›"), len([]byte("‹abc› ")), true, true, "‹abc› ?def?"},
		{[]byte("abc‹\ndef"), len([]byte("abc‹")), true, true, "abc\n‹def"},

		// Multiple consecutive newlines with breakNewLines.
		{[]byte("a\n\n\nb"), 0, true, false, "a›\n\n\n‹b"},
		{[]byte("\nabc"), 0, true, false, "›\n‹abc"},

		// Hash prefix escaping.
		{[]byte("†abc"), 0, false, false, "?abc"},
		{[]byte("‹†abc›"), 3, false, false, "‹?abc?"},
		{[]byte("hello†world"), 0, false, false, "hello?world"},
		{[]byte("†"), 0, false, false, "?"},
		{[]byte("a†b†c"), 0, false, false, "a?b?c"},

		// All three marker types together.
		{[]byte("‹†›"), 0, false, false, "???"},

		// Truncated lead byte at end of input (0xE2 without enough following bytes).
		// 0xE2 alone at end — not a complete marker, should pass through.
		{[]byte("abc\xe2"), 0, false, false, "abc\xe2?"},
		// 0xE2 0x80 at end — still not a complete marker.
		{[]byte("abc\xe2\x80"), 0, false, false, "abc\xe2\x80?"},

		// Lead byte 0xE2 with wrong second byte (not 0x80).
		// This is a valid UTF-8 sequence but not a marker.
		{[]byte("café"), 0, false, false, "café"},                   // é = 0xC3 0xA9, no lead byte
		{[]byte("abc\xe2\x82\xac def"), 0, false, false, "abc€ def"}, // € = E2 82 AC, lead matches but mid doesn't

		// Lead byte 0xE2 0x80 followed by non-marker third byte.
		// U+2014 EM DASH = E2 80 94, shares lead+mid but third byte doesn't match.
		{[]byte("hello\xe2\x80\x94world"), 0, false, false, "hello—world"},
		// U+2026 ELLIPSIS = E2 80 A6.
		{[]byte("wait\xe2\x80\xa6"), 0, false, false, "wait…"},

		// Trailing invalid UTF-8 (RuneError) — single invalid byte at end.
		{[]byte("abc\xff"), 0, false, false, "abc\xff?"},
		// Invalid byte at end with no prior escaping needed.
		{[]byte("hello\x80"), 0, false, false, "hello\x80?"},

		// Invalid trailing byte combined with markers.
		{[]byte("‹x›\xff"), 0, false, false, "?x?\xff?"},

		// Strip mode.
		{[]byte("abc \n"), 0, false, true, "abc"},
		{[]byte("abc   "), 0, false, true, "abc"},
		{[]byte("abc\n\n\n"), 0, false, true, "abc"},

		// Start offset beyond input length.
		{[]byte("abc"), 5, false, false, "abc"},

		// Start offset at exact end.
		{[]byte("abc"), 3, false, false, "abc"},

		// Markers only after start offset.
		{[]byte("‹abc›‹def›"), 0, false, false, "?abc??def?"},

		// breakNewLines with markers and newlines interleaved.
		{[]byte("‹a\nb›"), 0, true, false, "?a›\n‹b?"},
		{[]byte("x\n‹y›\nz"), 0, true, false, "x›\n‹?y?›\n‹z"},
	}

	for _, tc := range testCases {
		actual := string(InternalEscapeBytes(tc.input, tc.start, tc.bnl, tc.strip))
		if actual != tc.expected {
			t.Errorf("%q/%d: expected %q, got %q", string(tc.input), tc.start, tc.expected, actual)
		}
	}
}
