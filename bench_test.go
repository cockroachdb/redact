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

package redact

import "testing"

func BenchmarkRedact(b *testing.B) {
	x := struct {
		a int
	}{456}
	for i := 0; i < b.N; i++ {
		_ = Sprintf("hello %v %v %v", 123, x, Safe("world"), Unsafe("universe"))
	}
}

// BenchmarkRedactCall_PlainMarkers calls .Redact() on a string with only
// regular ‹...› markers (no hash markers). This is the baseline.
func BenchmarkRedactCall_RegularRedaction(b *testing.B) {
	s := Sprintf("user=%s action=%s", "alice", Safe("login"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Redact()
	}
}

// BenchmarkRedactCall_HashMarkers calls .Redact() on a string with ‹†...›
// hash markers and hashing enabled. This exercises the SHA-256 path.
func BenchmarkRedactCall_HashEnabled(b *testing.B) {
	EnableHashing(nil)
	defer DisableHashing()
	s := Sprintf("user=%s action=%s %s", HashString("alice"), SafeString("login"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Redact()
	}
}

// BenchmarkRedactCall_SingleHashWithSalt — 1 ‹†alice› marker, HMAC-SHA256.
func BenchmarkRedactCall_HashWithSalt(b *testing.B) {
	EnableHashing([]byte("my-secret-salt"))
	defer DisableHashing()
	s := Sprintf("user=%s action=%s", HashString("alice"), Safe("login"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Redact()
	}
}

