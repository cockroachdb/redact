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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package markers

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
)

// defaultHashLength is the number of hex characters to use from the SHA-1 hash.
// 8 hex chars = 32 bits = ~4.3 billion unique values.
// This provides a good balance between collision resistance and output brevity.
// For typical logging scenarios with fewer unique sensitive values per analysis window,
// this collision risk should be acceptable. If not, we can make this configurable in the future.
const defaultHashLength = 8

// hashingEnabled controls whether hash-based redaction is enabled.
// When false, hash markers (‹†value›) are fully redacted like regular markers.
// When true, hash markers are replaced with hashes.
var hashingEnabled bool

// hashingSalt is an optional salt for HMAC-SHA1 hashing.
// When nil, uses plain SHA1.
// When set, uses HMAC-SHA1 for better security.
var hashingSalt []byte

// EnableHashing enables hash-based redaction with an optional salt.
// When salt is nil, hash markers use plain SHA1.
// When salt is provided, hash markers use HMAC-SHA1 for better security.
// This function should be called during initialization before any redaction operations.
// The caller must not modify the salt slice after passing it to this function.
func EnableHashing(salt []byte) {
	hashingEnabled = true
	hashingSalt = salt
}

// IsHashingEnabled returns true if hash-based redaction is enabled.
func IsHashingEnabled() bool {
	return hashingEnabled
}

// hashString computes a truncated hash of the input string.
// Uses HMAC-SHA1 if salt is set, otherwise plain SHA1.
// Must only be called when hashing is enabled (IsHashingEnabled() == true).
func hashString(value string) string {
	var h []byte
	if len(hashingSalt) > 0 {
		mac := hmac.New(sha1.New, hashingSalt)
		mac.Write([]byte(value))
		h = mac.Sum(nil)
	} else {
		hasher := sha1.New()
		hasher.Write([]byte(value))
		h = hasher.Sum(nil)
	}

	fullHash := hex.EncodeToString(h)
	if len(fullHash) > defaultHashLength {
		return fullHash[:defaultHashLength]
	}
	return fullHash
}

// hashBytes computes a truncated hash of the input byte slice.
// Uses HMAC-SHA1 if salt is set, otherwise plain SHA1.
// Must only be called when hashing is enabled (IsHashingEnabled() == true).
func hashBytes(value []byte) []byte {
	var h []byte
	if len(hashingSalt) > 0 {
		mac := hmac.New(sha1.New, hashingSalt)
		mac.Write(value)
		h = mac.Sum(nil)
	} else {
		hasher := sha1.New()
		hasher.Write(value)
		h = hasher.Sum(nil)
	}

	fullHash := make([]byte, sha1.Size*2)
	_ = hex.Encode(fullHash, h)

	if len(fullHash) > defaultHashLength {
		return fullHash[:defaultHashLength]
	}
	return fullHash
}
