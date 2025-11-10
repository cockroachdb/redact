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
	"sync"
)

/*
	Hash function implementation notes:

	We use SHA-1 because it provides a good balance of performance and output size
	for the log correlation use case. SHA-1 is fast and produces compact hashes,
	making it well-suited for high-throughput logging scenarios.

	When a salt is provided via EnableHashing(), we use HMAC-SHA1 which provides
	additional security properties and domain separation.

	The hash output is truncated to 8 hex characters (32 bits) to keep log output
	concise while still providing sufficient collision resistance for typical logging
	workloads.
*/

// defaultHashLength is the number of hex characters to use from the SHA-1 hash.
// 8 hex chars = 32 bits = ~4.3 billion unique values.
// This provides a good balance between collision resistance and output brevity.
// For typical logging scenarios with fewer unique sensitive values per analysis window,
// this collision risk should be acceptable. If not, we can make this configurable in the future.
const defaultHashLength = 8

var hashConfig = struct {
	sync.RWMutex
	enabled bool
	salt    []byte
}{
	enabled: false,
	salt:    nil,
}

// EnableHashing enables hash-based redaction with an optional salt.
// When salt is nil, hash markers use plain SHA1.
// When salt is provided, hash markers use HMAC-SHA1 for better security.
func EnableHashing(salt []byte) {
	hashConfig.Lock()
	defer hashConfig.Unlock()
	hashConfig.enabled = true
	hashConfig.salt = salt
}

// IsHashingEnabled returns true if hash-based redaction is enabled.
func IsHashingEnabled() bool {
	hashConfig.RLock()
	defer hashConfig.RUnlock()
	return hashConfig.enabled
}

// hashString computes a truncated hash of the input string.
// Uses HMAC-SHA1 if salt is set, otherwise plain SHA1.
// Must only be called when hashing is enabled (IsHashingEnabled() == true).
func hashString(value string) string {
	hashConfig.RLock()
	salt := hashConfig.salt
	hashConfig.RUnlock()

	var h []byte
	if len(salt) > 0 {
		mac := hmac.New(sha1.New, salt)
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
	hashConfig.RLock()
	salt := hashConfig.salt
	hashConfig.RUnlock()

	var h []byte
	if len(salt) > 0 {
		mac := hmac.New(sha1.New, salt)
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
