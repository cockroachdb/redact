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
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type p = SafePrinter

func TestPrinter(t *testing.T) {
	testData := []struct {
		fn       func(p)
		expected string
	}{
		{func(w p) { w.SafeString("ab") }, `ab`},
		{func(w p) { w.SafeRune('☃') }, `☃`},
		{func(w p) { w.UnsafeString("rs") }, `‹rs›`},
		{func(w p) { w.UnsafeByte('t') }, `‹t›`},
		{func(w p) { w.UnsafeByte(startRedactableBytes[0]) }, `‹?›`},
		{func(w p) { w.UnsafeBytes([]byte("uv")) }, `‹uv›`},
		{func(w p) { w.UnsafeRune('🛑') }, `‹🛑›`},
		{func(w p) { w.Print("fg", safe("hi")) }, `‹fg›hi`},
		{func(w p) { w.Printf("jk %s %s", "lm", safe("no")) }, `jk ‹lm› no`},
		// Direct access to the fmt.State.
		{func(w p) { _, _ = w.Write([]byte("pq")) }, `‹pq›`},
		// Safe strings and runes containing the delimiters get escaped.
		{func(w p) { w.SafeString("a ‹ b › c") }, `a ? b ? c`},
		{func(w p) { w.SafeRune('‹') }, `?`},
		{func(w p) { w.SafeRune('›') }, `?`},
		{func(w p) { w.Print("a ‹ b › c", safe("d ‹ e › f")) },
			`‹a ? b ? c›d ? e ? f`},
		{func(w p) { w.Printf("f %s %s", "a ‹ b › c", safe("d ‹ e › f")) },
			`f ‹a ? b ? c› d ? e ? f`},
		// Space and newlines at the end of an unsafe string get removed,
		// but not at the end of a safe string.
		{func(w p) { w.SafeString("ab \n ") }, "ab \n "},
		{func(w p) { w.UnsafeString("cd \n ") }, `‹cd›`},
		{func(w p) { w.Print("ab ", safe("cd ")) }, "‹ab›cd "},
		{func(w p) { w.Printf("ab :%s: :%s: ", "cd ", safe("de ")) }, "ab :‹cd›: :de : "},
		// Spaces as runes get preserved.
		{func(w p) { w.SafeRune(' ') }, ` `},
		{func(w p) { w.SafeRune('\n') }, "\n"},
		{func(w p) { w.UnsafeRune(' ') }, `‹ ›`},
		{func(w p) { w.UnsafeRune('\n') }, "‹\n›"},
		// The Safe() API turns anything into something safe. However, the contents
		// still get escaped as needed.
		{func(w p) { w.Print("ab ", Safe("c‹d›e ")) }, "‹ab›c?d?e "},
		{func(w p) { w.Printf("ab %03d ", Safe(12)) }, "ab 012 "},
		// Something that'd be otherwise safe, becomes unsafe with Unsafe().
		{func(w p) { w.Print(Unsafe(SafeString("abc"))) }, "‹abc›"},
		{func(w p) { w.Print(Unsafe(SafeRune('a'))) }, "‹97›"},
		{func(w p) { w.Print(Unsafe(Sprint("abc"))) }, "‹?abc?›"},
		{func(w p) { w.Print(Unsafe(Safe("abc"))) }, "‹abc›"},
		{func(w p) { w.Printf("%v", Unsafe(SafeString("abc"))) }, "‹abc›"},
		{func(w p) { w.Printf("%v", Unsafe(SafeRune('a'))) }, "‹97›"},
		{func(w p) { w.Printf("%v", Unsafe(Sprint("abc"))) }, "‹?abc?›"},
		{func(w p) { w.Printf("%v", Unsafe(Safe("abc"))) }, "‹abc›"},
		{func(w p) { w.Printf("%03d", Unsafe(12)) }, "‹012›"},
		// A string that's already redactable gets included as-is;
		// in that case, the printf verb and flags are ignored.
		{func(w p) { w.Print("ab ", Sprint(12, Safe(34))) }, "‹ab›‹12› 34"},
		{func(w p) { w.Printf("ab %q", Sprint(12, Safe(34))) }, "ab ‹12› 34"},
		{func(w p) { w.Printf("ab %d", Sprint(12, Safe(34))) }, "ab ‹12› 34"},
		// Nil untyped objects get formatted as redactable unless marked safe.
		{func(w p) { w.Printf("ab %v", nil) }, "ab ‹<nil>›"},
		{func(w p) { w.Printf("ab %v", Safe(nil)) }, "ab <nil>"},
		// Reflected values can be formatted too.
		{func(w p) { w.Printf("ab %.1f", reflect.ValueOf(12.3456)) }, "ab ‹12.3›"},
		{func(w p) { w.Printf("ab %.1f", Safe(reflect.ValueOf(12.3456))) }, "ab 12.3"},

		// Check for bad verbs.
		{func(w p) { w.Printf("ab %d", true) }, "ab ‹%!d(bool=true)›"},
		{func(w p) { w.Printf("ab %d", Safe(true)) }, "ab %!d(bool=true)"},
		{func(w p) { w.Printf("ab %d") }, "ab %!d(MISSING)"},
		{func(w p) { w.Printf("ab %[2]d", 123) }, "ab %!d(BADINDEX)"},
		{func(w p) { w.Printf("ab %.*d", -1, 123) }, "ab %!(BADPREC)‹123›"},
		// A badly formed verb does not leak information.
		{func(w p) { w.Printf("ab %2", 123) }, "ab %!(NOVERB)%!(EXTRA int=‹123›)"},

		// The %T verb does what it says on the label. The type itself is
		// considered safe.
		{func(w p) { w.Printf("ab %T", 123) }, "ab int"},
		{func(w p) { w.Printf("ab %T", Safe(123)) }, "ab int"},
		{func(w p) { w.Printf("ab %T", Unsafe(123)) }, "ab int"},

		// A struct does not get recursively redacted, for now.
		{func(w p) { w.Print(&complexObj{"somestring"}) }, "‹&{somestring}›"},
		{func(w p) { w.Printf("%v", &complexObj{"somestring"}) }, "‹&{somestring}›"},
		{func(w p) { w.Printf("%+v", &complexObj{"somestring"}) }, "‹&{v:somestring}›"},
		{func(w p) { w.Printf("%#v", &complexObj{"somestring"}) }, `‹&redact.complexObj{v:"somestring"}›`},
		// However it can be marked safe.
		{func(w p) { w.Print(Safe(&complexObj{"somestring"})) }, "&{somestring}"},
		{func(w p) { w.Printf("%v", Safe(&complexObj{"somestring"})) }, "&{somestring}"},
		{func(w p) { w.Printf("%+v", Safe(&complexObj{"somestring"})) }, "&{v:somestring}"},
		{func(w p) { w.Printf("%#v", Safe(&complexObj{"somestring"})) }, `&redact.complexObj{v:"somestring"}`},
	}

	var methods = []struct {
		name string
		fn   func(interface{}) string
	}{
		{"sprint", func(a interface{}) string { return string(Sprint(a)) }},
		{"sprintf", func(a interface{}) string { return string(Sprintf("%v", a)) }},
		{"fprint", func(a interface{}) string { var b strings.Builder; _, _ = Fprint(&b, a); return b.String() }},
		{"fprintf", func(a interface{}) string { var b strings.Builder; _, _ = Fprintf(&b, "%v", a); return b.String() }},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			for i, tc := range testData {
				res := m.fn(compose{fn: tc.fn})

				if res != tc.expected {
					t.Errorf("%d: expected:\n  %s\n\ngot:\n%s", i,
						strings.ReplaceAll(tc.expected, "\n", "\n  "),
						strings.ReplaceAll(res, "\n", "\n  "))
				}
			}
		})
	}
}

func TestInternalEscape(t *testing.T) {
	testCases := []struct {
		input    []byte
		start    int
		expected string
	}{
		{nil, 0, ""},
		{[]byte(""), 0, ""},
		{[]byte("abc"), 0, "abc"},
		{[]byte("‹abc›"), 0, "?abc?"},
		{[]byte("‹abc›"), 3, "‹abc?"},
		{[]byte("‹abc›def›ghi"), 3, "‹abc?def?ghi"},
		{[]byte("‹abc›"), len([]byte("‹abc›")), "‹abc›"},
		{[]byte("‹abc›‹def›"), len([]byte("‹abc›")), "‹abc›?def?"},
	}

	for _, tc := range testCases {
		actual := string(internalEscapeBytes(tc.input, tc.start))
		if actual != tc.expected {
			t.Errorf("%q/%d: expected %q, got %q", string(tc.input), tc.start, tc.expected, actual)
		}
	}
}

func TestCustomSafeTypes(t *testing.T) {
	defer func(prev map[reflect.Type]bool) { safeTypeRegistry = prev }(safeTypeRegistry)
	RegisterSafeType(reflect.TypeOf(int32(123)))

	actual := Sprint(123, int32(456))
	const expected = `‹123› 456`
	if actual != expected {
		t.Errorf("expected %q, got %q", expected, actual)
	}

	// Unsafe can override.
	actual = Sprint(123, Unsafe(int32(456)))
	const expected2 = `‹123› ‹456›`
	if actual != expected2 {
		t.Errorf("expected %q, got %q", expected2, actual)
	}
}

func TestConversions(t *testing.T) {
	const data = `‹123› 456`
	s := RedactableString(data)

	bconv := s.ToBytes()
	expected := []byte(data)
	if !bytes.Equal(bconv, expected) {
		t.Errorf("\nexpected: %+v,\n     got: %+v", expected, bconv)
	}

	sconv := bconv.ToString()
	if s != sconv {
		t.Errorf("expected %q, got %q", s, sconv)
	}
}

func TestFormatPropagation(t *testing.T) {
	testData := []struct {
		actual   RedactableString
		expected RedactableString
	}{
		{Sprintf(":%10s:", safe("abc")), `:       abc:`},
		{Sprintf(":%10s:", "abc"), `:‹       abc›:`},
		{Sprintf(":%+#03x:", safeint(123)), `:+0x7b:`},
		{Sprintf(":%+#03x:", 123), `:‹+0x7b›:`},
	}

	for _, tc := range testData {
		if tc.actual != tc.expected {
			t.Errorf("expected %q, got %q", tc.expected, tc.actual)
		}
	}
}

type compose struct {
	fn func(p)
}

func (c compose) SafeFormat(w SafePrinter, _ rune) {
	c.fn(w)
}

type safe string

func (safe) SafeValue() {}

type safeint int

func (safeint) SafeValue() {}

func TestTransform(t *testing.T) {
	testData := []struct {
		actual   string
		expected string
	}{
		{string(StartMarker()), `‹`},
		{string(EndMarker()), `›`},
		{string(RedactedMarker()), `‹×›`},
		{string(EscapeMarkers([]byte(`a ‹ b › c`))), `a ? b ? c`},
		{string(RedactableBytes([]byte(`a ‹ b › c`)).Redact()), `a ‹×› c`},
		{string(RedactableBytes([]byte(`a ‹ b › c`)).StripMarkers()), `a  b  c`},
		{string(RedactableString(`a ‹ b › c`).Redact()), `a ‹×› c`},
		{RedactableString(`a ‹ b › c`).StripMarkers(), `a  b  c`},
	}

	for _, tc := range testData {
		if tc.actual != tc.expected {
			t.Errorf("expected %q, got %q", tc.expected, tc.actual)
		}
	}
}

// TestRedactStream verifies that the redaction logic is able to both
// add the redaction quotes and also respects the format parameters
// and verb.
func TestRedactStream(t *testing.T) {
	testData := []struct {
		f        string
		input    interface{}
		expected string
	}{
		{"%v", "", "‹›"},
		{"%v", " ", "‹›"},
		{"‹› %v ›››", "abc", "?? ‹abc› ???"},
		{"%v", "abc ", "‹abc›"},
		{"%q", "abc ", `‹"abc "›`},
		{"%v", "abc\n ", "‹abc›"},
		{"%v", "abc \n\n", "‹abc›"},
		{"%v", " \n\nabc", "‹ ›\n\n‹abc›"},
		{"%v", "‹abc›", "‹?abc?›"},
		{"%v", 123, "‹123›"},
		{"%05d", 123, "‹00123›"},
		{"%v", Safe(123), "123"},
		{"%05d", Safe(123), "00123"},
		{"%#x", 17, "‹0x11›"},
		{"%+v", &complexObj{"‹›"}, "‹&{v:??}›"},
		{"%v", &safestringer{"as"}, "as"},
		{"%v", &stringer{"as"}, "‹as›"},
		{"%v", &safefmtformatter{"af"}, "af"},
		{"%v", &fmtformatter{"af"}, "‹af›"},
		{"%v", &safemsg{"az"}, "az"},
		// Printers that cause panics during rendering.
		{"%v", &safepanicObj1{"s1-x‹y›z"}, `%!v(PANIC=String method: s1-x?y?z)`},
		{"%v", &safepanicObj2{"s2-x‹y›z"}, `%!v(PANIC=Format method: s2-x?y?z)`},
		{"%v", &panicObj1{"p1-x‹y›z"}, `‹%!v(PANIC=String method: p1-x?y?z)›`},
		{"%v", &panicObj2{"p2-x‹y›z"}, `‹%!v(PANIC=Format method: p2-x?y?z)›`},
		{"%v", &panicObj3{"p3-x‹y›z"}, `%!v(PANIC=SafeFormatter method: p3-x?y?z)`},
	}

	for i, tc := range testData {
		var buf strings.Builder
		n, _ := Fprintf(&buf, tc.f, tc.input)
		result := buf.String()
		if result != tc.expected {
			t.Errorf("%d: expected %q, got %q", i, tc.expected, result)
		}
		if n != len(result) {
			t.Errorf("%d: expected len %d, got %d", i, n, len(result))
		}
	}
}

type complexObj struct {
	v string
}

type stringer struct{ s string }

var _ fmt.Stringer = (*stringer)(nil)

func (s *stringer) String() string { return s.s }

type safestringer struct{ s string }

var _ SafeValue = (*safestringer)(nil)
var _ fmt.Stringer = (*safestringer)(nil)

func (*safestringer) SafeValue()       {}
func (s *safestringer) String() string { return s.s }

type fmtformatter struct{ s string }

var _ fmt.Formatter = (*fmtformatter)(nil)

func (s *fmtformatter) Format(w fmt.State, _ rune) { fmt.Fprint(w, s.s) }

type safefmtformatter struct{ s string }

var _ SafeValue = (*safefmtformatter)(nil)
var _ fmt.Formatter = (*safefmtformatter)(nil)

func (*safefmtformatter) SafeValue()                   {}
func (s *safefmtformatter) Format(w fmt.State, _ rune) { fmt.Fprint(w, s.s) }

type panicObj1 struct{ s string }

var _ fmt.Stringer = (*panicObj1)(nil)

func (p *panicObj1) String() string { panic(p.s) }

type panicObj2 struct{ s string }

var _ fmt.Formatter = (*panicObj2)(nil)

func (p *panicObj2) Format(fmt.State, rune) { panic(p.s) }

type safepanicObj1 struct{ s string }

var _ SafeValue = (*safepanicObj1)(nil)
var _ fmt.Stringer = (*safepanicObj1)(nil)

func (*safepanicObj1) SafeValue()       {}
func (p *safepanicObj1) String() string { panic(p.s) }

type safepanicObj2 struct{ s string }

var _ SafeValue = (*safepanicObj2)(nil)
var _ fmt.Formatter = (*safepanicObj2)(nil)

func (*safepanicObj2) SafeValue()               {}
func (p *safepanicObj2) Format(fmt.State, rune) { panic(p.s) }

type panicObj3 struct{ s string }

var _ SafeFormatter = (*panicObj3)(nil)

func (p *panicObj3) SafeFormat(SafePrinter, rune) { panic(p.s) }

type safemsg struct {
	s string
}

var _ SafeMessager = (*safemsg)(nil)

func (p *safemsg) SafeMessage() string { return p.s }

// TestFormatRedirect checks that the count return from the
// (*escapeWriter).Write() method is correct when there are newline
// characters.
func TestFormatRedirect(t *testing.T) {
	v := &fmter{}
	if expected, actual := "‹hello›\n‹world›", string(Sprintf("%v", v)); expected != actual {
		t.Errorf("expected %q, got %q", expected, actual)
	}
	if expected, actual := "‹hello›\n‹world›", string(Sprintf("%+v", v)); expected != actual {
		t.Errorf("expected %q, got %q", expected, actual)
	}
}

type fmter struct{}

// Format implements the fmt.Formatter interface.
func (ef *fmter) Format(s fmt.State, verb rune) {
	var buf bytes.Buffer
	buf.WriteString("hello\nworld")
	_, _ = buf.WriteTo(s)
}
