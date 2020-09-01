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

	internalFmt "github.com/cockroachdb/redact/internal"
)

// printArgFn is the hook injected into the standard fmt logic
// by the printer functions in markers_print.go.
func printArgFn(p *internalFmt.InternalPrinter, arg interface{}, verb rune) (newState int) {
	redactLastWrites(p)

	if verb == 'T' {
		// If the value was wrapped, reveal its original type. Anything else is not very useful.
		switch v := arg.(type) {
		case safeWrapper:
			arg = v.a
		case unsafeWrap:
			arg = v.a
		}

		// Shortcut: %T is always safe to print as-is.
		internalFmt.PrintArg(p, arg, verb)
		return len(internalFmt.Buf(p))
	}

	// RedactableBytes/RedactableString are already formatted as
	// redactable. Include them as-is.
	//
	// NB: keep this logic synchronized with
	// (RedactableString/Bytes).SafeFormat().
	switch v := arg.(type) {
	case RedactableString:
		internalFmt.Append(p, []byte(v))
		return len(internalFmt.Buf(p))
	case RedactableBytes:
		internalFmt.Append(p, []byte(v))
		return len(internalFmt.Buf(p))
	}

	arg = annotateArg(arg)
	internalFmt.PrintArg(p, arg, verb)
	return len(internalFmt.Buf(p))
}

// redactLastWrites escapes any markers that were added by the
// internals of the printf functions, for example
// if markers were present in the format string.
func redactLastWrites(p *internalFmt.InternalPrinter) {
	state := internalFmt.GetState(p)
	newBuf := internalEscapeBytes(internalFmt.Buf(p), state)
	internalFmt.SetState(p, newBuf)
}

// annotateArg wraps the arguments to one of the print functions with
// an indirect formatter which ensures that redaction markers inside
// the representation of the object are escaped, and optionally
// encloses the result of the display between redaction markers.
func annotateArg(arg interface{}) interface{} {
	switch v := arg.(type) {
	case SafeFormatter:
		// calls to Format() by fmt.Print will be redirected to
		// v.SafeFormat(). This delegates the task of adding markers to
		// the object itself.
		return &redactFormatRedirect{
			func(p SafePrinter, verb rune) { v.SafeFormat(p, verb) },
		}

	case SafeValue:
		// calls to Format() by fmt.Print will be redirected to a
		// display of v without redaction markers.
		//
		// Note that we can't let the value be displayed as-is because
		// we must prevent any marker inside the value from leaking into
		// the result. (We want to avoid mismatched markers.)
		return &escapeArg{arg: arg, enclose: false}

	case SafeMessager:
		// Obsolete interface.
		// TODO(knz): Remove this.
		return &escapeArg{arg: v.SafeMessage(), enclose: false}

	default:
		if err, ok := v.(error); ok && redactErrorFn != nil {
			// We place this case after the other cases above, in case
			// the error object knows how to print itself safely already.
			return &redactFormatRedirect{
				func(p SafePrinter, verb rune) { redactErrorFn(err, p, verb) },
			}
		}
		// calls to Format() by fmt.Print will be redirected to a
		// display of v within redaction markers if the type is
		// considered unsafe, without markers otherwise. In any case,
		// occurrences of delimiters within are escaped.
		return &escapeArg{arg: v, enclose: !isSafeValue(v)}
	}
}

// redactFormatRedirect wraps a safe print callback and uses it to
// implement fmt.Formatter.
type redactFormatRedirect struct {
	printFn func(p SafePrinter, verb rune)
}

// Format implements fmt.Formatter.
func (r *redactFormatRedirect) Format(s fmt.State, verb rune) {
	defer func() {
		if p := recover(); p != nil {
			e := escapeWriter{w: s}
			fmt.Fprintf(&e, "%%!%c(PANIC=SafeFormatter method: %v)", verb, p)
		}
	}()
	p := &printer{}
	p.escapeState = makeEscapeState(s, &p.buf)
	r.printFn(p, verb)
	_, _ = s.Write(p.buf.Bytes())
}

// passthrough passes a pre-formatted string through.
type passthrough struct{ arg []byte }

// Format implements fmt.Formatter.
func (p *passthrough) Format(s fmt.State, _ rune) {
	_, _ = s.Write(p.arg)
}

// escapeArg wraps an arbitrary value and ensures that any occurrence
// of the redaction markers in its representation are escaped.
//
// The result of printing out the value is enclosed within markers or
// not depending on the value of the enclose bool.
type escapeArg struct {
	arg     interface{}
	enclose bool
}

func (r *escapeArg) Format(s fmt.State, verb rune) {
	switch t := r.arg.(type) {
	case fmt.Formatter:
		// This is a special case from the default case below, which
		// allows a shortcut through the layers of the fmt package.
		p := &escapeState{
			State: s,
			w: escapeWriter{
				w:       s,
				enclose: r.enclose,
				strip:   r.enclose,
			}}
		defer func() {
			if recovered := recover(); recovered != nil {
				fmt.Fprintf(p, "%%!%c(PANIC=Format method: %v)", verb, recovered)
			}
		}()
		t.Format(p, verb)

	default:
		// TODO(knz): It would be possible to implement struct formatting
		// with conditional redaction based on field tag annotations here.
		p := &escapeWriter{w: s, enclose: r.enclose, strip: r.enclose}
		reproducePrintf(p, s, verb, r.arg)
	}
}

// printerfn is a helper struct for use by Sprintfn.
type printerfn struct {
	fn func(SafePrinter)
}

// SafeFormat implements the SafeFormatter interface.
func (p printerfn) SafeFormat(w SafePrinter, _ rune) {
	p.fn(w)
}

// redactErrorFn can be injected from an error library
// to render error objects safely.
var redactErrorFn func(err error, p SafePrinter, verb rune)

// RegisterRedactErrorFn registers an error redaction function for use
// during automatic redaction by this package.
// Provided e.g. by cockroachdb/errors.
func RegisterRedactErrorFn(fn func(err error, p SafePrinter, verb rune)) {
	redactErrorFn = fn
}
