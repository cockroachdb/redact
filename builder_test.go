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

package redact

import (
	"fmt"
	"testing"
)

func TestBuilder(t *testing.T) {
	var b StringBuilder

	fmt.Fprint(&b, "unsafe")
	b.SafeRune('\n')

	b.Print("unsafe")
	b.SafeRune('\n')

	b.Print(Safe("safe"))
	b.SafeRune('\n')

	b.Printf("safe")
	b.SafeRune('\n')

	b.Printf("hello %v %v", Safe("safe"), "unsafe")
	b.SafeRune('\n')

	b.SafeString("safe\n")

	b.SafeRune('S')
	b.SafeRune('\n')

	b.UnsafeString("unsafe")
	b.SafeRune('\n')

	b.UnsafeRune('U')
	b.SafeRune('\n')

	b.UnsafeByte('U')
	b.SafeRune('\n')

	b.UnsafeByte(startRedactableBytes[0])
	b.SafeRune('\n')

	b.UnsafeBytes([]byte("UUU"))
	b.SafeRune('\n')

	actualR := b.RedactableString()
	const expectedR = `‹unsafe›
‹unsafe›
safe
safe
hello safe ‹unsafe›
safe
S
‹unsafe›
‹U›
‹U›
‹?›
‹UUU›
`
	if actualR != expectedR {
		t.Errorf("expected:\n%s\n\ngot:\n%s", expectedR, actualR)
	}
	if actualB := b.RedactableBytes(); string(actualB) != expectedR {
		t.Errorf("expected:\n%s\n\ngot:\n%s", expectedR, actualB)
	}

	if actualR2 := Sprint(&b); actualR2 != expectedR {
		t.Errorf("expected:\n%s\n\ngot:\n%s", expectedR, actualR2)
	}

	actual := b.String()
	const expected = `unsafe
unsafe
safe
safe
hello safe unsafe
safe
S
unsafe
U
U
?
UUU
`
	if actual != expected {
		t.Errorf("expected:\n%s\n\ngot:\n%s", expected, actual)
	}
}
