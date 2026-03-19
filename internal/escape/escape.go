// Copyright 2020 The Cockroach Authors.
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

import (
	"bytes"
	"unicode/utf8"

	m "github.com/cockroachdb/redact/internal/markers"
)

// InternalEscapeBytes escapes redaction markers in the provided buf
// starting at the location startLoc.
// The bytes before startLoc are considered safe (already escaped).
//
// If breakNewLines is set, a closing redaction marker
// is placed before sequences of one or more newline characters,
// and an open redaction marker is placed afterwards.
//
// If strip is set, final newlines and spaces are trimmed from the
// output.
func InternalEscapeBytes(b []byte, startLoc int, breakNewLines, strip bool) (res []byte) {
	// Note: we use len(...RedactableS) and not len(...RedactableBytes)
	// because the ...S variant is a compile-time constant so this
	// accelerates the loops below.
	start := m.StartBytes
	ls := len(m.StartS)
	end := m.EndBytes
	le := len(m.EndS)
	hashPrefix := m.HashPrefixBytes
	lh := len(m.HashPrefixS)
	escape := m.EscapeMarkBytes

	// All markers share the same lead byte (0xE2) and second byte (0x80).
	// This invariant is verified by the init() check in markers.go.
	// We use this to skip over ASCII data quickly.
	lead := start[0]
	mid := start[1]
	b2Start := start[2]
	b2End := end[2]
	b2Hash := hashPrefix[2]

	// Trim final newlines/spaces, for convenience.
	if strip {
		end := len(b)
		for i := end - 1; i >= startLoc; i-- {
			if b[i] == '\n' || b[i] == ' ' {
				end = i
			} else {
				break
			}
		}
		b = b[:end]
	}

	// res is the output slice. In the common case where there is
	// nothing to escape, the input slice is returned directly
	// and no allocation takes place.
	res = b
	// copied is true if and only if `res` is a copy of `b`.  It only
	// turns to true if the loop below finds something to escape.
	copied := false
	// k is the index in b up to (and excluding) the byte which we've
	// already copied into res (if copied=true).
	k := 0

	for i := startLoc; i < len(b); {
		// Use bytes.IndexByte to skip over runs of bytes that can't
		// start a marker. The lead byte (0xE2) starts all marker
		// sequences. When breakNewLines is false, we only need to find
		// the lead byte. When true, we need to handle newlines too.
		remaining := b[i:]
		var idx int
		if !breakNewLines {
			idx = bytes.IndexByte(remaining, lead)
		} else {
			// Find the first byte that could be interesting: lead or newline.
			// Use two IndexByte calls and take the minimum.
			idxLead := bytes.IndexByte(remaining, lead)
			idxNL := bytes.IndexByte(remaining, '\n')
			if idxLead < 0 {
				idx = idxNL
			} else if idxNL < 0 {
				idx = idxLead
			} else if idxLead < idxNL {
				idx = idxLead
			} else {
				idx = idxNL
			}
		}
		if idx < 0 {
			break
		}
		i += idx
		c := b[i]

		if breakNewLines && c == '\n' {
			if !copied {
				res = make([]byte, 0, len(b))
				copied = true
			}
			res = append(res, b[k:i]...)

			// Close the current redaction section before the newline.
			// If the last thing we emitted was a start marker, remove
			// it instead of producing an empty ‹› pair.
			if bytes.HasSuffix(res, start) {
				res = res[:len(res)-ls]
			} else {
				res = append(res, end...)
			}

			// Emit all consecutive newlines as-is, outside any
			// redaction envelope.
			lastNewLine := i
			for lastNewLine < len(b) && b[lastNewLine] == '\n' {
				lastNewLine++
			}
			res = append(res, b[i:lastNewLine]...)

			// Reopen the redaction section for content after the
			// newline(s). The caller will emit the closing marker.
			res = append(res, start...)
			k = lastNewLine
			i = lastNewLine
			continue
		}

		// c == lead (0xE2). Check if we have a full marker.
		if i+2 >= len(b) || b[i+1] != mid {
			i++
			continue
		}

		b2 := b[i+2]
		markerLen := 0
		if b2 == b2Start {
			markerLen = ls
		} else if b2 == b2End {
			markerLen = le
		} else if b2 == b2Hash {
			markerLen = lh
		}

		if markerLen > 0 {
			if !copied {
				res = make([]byte, 0, len(b)+len(escape))
				copied = true
			}
			res = append(res, b[k:i]...)
			res = append(res, escape...)
			k = i + markerLen
			i += markerLen
		} else {
			i++
		}
	}
	// If the string terminates with an invalid utf-8 sequence, we
	// want to avoid a run-in with a subsequent redaction marker.
	if r, s := utf8.DecodeLastRune(b); s == 1 && r == utf8.RuneError {
		if !copied {
			// See the comment above about res allocation.
			res = make([]byte, 0, len(b)+len(escape))
			copied = true
		}
		res = append(res, b[k:]...)
		res = append(res, escape...)
		k = len(b)
	}
	if copied {
		res = append(res, b[k:]...)
	}
	return
}
