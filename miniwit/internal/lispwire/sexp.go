// SPDX-License-Identifier: Apache-2.0
//
// Package lispwire reads and writes the readable-Lisp forms that gr8s's
// RaftTransport carries inside RaftEnvelope.payload (see
// src/raft/transport/member.lisp: raft-lisp-message->octets). gr8s prints each
// Raft message plist with prin1 under with-standard-io-syntax and
// *print-readably*/*print-circle*/*print-pretty* bound off, then UTF-8 encodes
// it; the receiver reads it back with *read-eval* disabled. with-standard-io-syntax
// pins *print-case* to :upcase and *package* to COMMON-LISP-USER, so symbols and
// keywords print uppercase (:TYPE, :REQUEST-VOTE, T, NIL).
//
// This file is the generic S-expression layer: a Value tree plus a reader and a
// writer that round-trip that format. message.go builds the typed Raft messages
// on top of it. A witness never interprets a log command, so arbitrary command
// forms only need to survive the tree and print back identically; the reader
// therefore handles lists, dotted pairs, vectors, strings, integers and symbols.
package lispwire

import (
	"fmt"
	"math/big"
	"strings"
)

// Value is one node of a parsed Lisp form: Int, *big.Int, Str, Sym, List or Vec.
type Value interface{ isValue() }

// Int is a Lisp integer that fits in int64 (terms, indices, sequences).
type Int int64

// Big is a Lisp integer too large for int64 (defensive; terms never reach it).
type Big struct{ V *big.Int }

// Str is a Lisp string, "like this".
type Str string

// Sym is a Lisp symbol printed verbatim: a keyword (":TYPE"), "T", "NIL", or any
// other symbol. Case is preserved exactly as read so it prints back unchanged.
type Sym string

// List is a proper or dotted list. When Dotted is true the final element is the
// cdr of the last cons (an alist entry such as ("id" . :VOTER)).
type List struct {
	Items  []Value
	Dotted bool // ("a" "b" . "c") -> Items{a,b,c}, Dotted=true
}

// Vec is a simple-vector, #(a b c) — gr8s uses them in artifact envelopes.
type Vec struct{ Items []Value }

func (Int) isValue()  {}
func (Big) isValue()  {}
func (Str) isValue()  {}
func (Sym) isValue()  {}
func (List) isValue() {}
func (Vec) isValue()  {}

// --- Writer ---------------------------------------------------------------

// Write renders v in the exact format gr8s's reader accepts. It is the inverse
// of Read for every form this package produces.
func Write(v Value) string {
	var b strings.Builder
	writeValue(&b, v)
	return b.String()
}

func writeValue(b *strings.Builder, v Value) {
	switch x := v.(type) {
	case Int:
		fmt.Fprintf(b, "%d", int64(x))
	case Big:
		b.WriteString(x.V.String())
	case Str:
		b.WriteByte('"')
		for _, r := range string(x) {
			if r == '"' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
	case Sym:
		b.WriteString(string(x))
	case List:
		b.WriteByte('(')
		for i, it := range x.Items {
			if i > 0 {
				b.WriteByte(' ')
			}
			if x.Dotted && i == len(x.Items)-1 {
				b.WriteString(". ")
			}
			writeValue(b, it)
		}
		b.WriteByte(')')
	case Vec:
		b.WriteString("#(")
		for i, it := range x.Items {
			if i > 0 {
				b.WriteByte(' ')
			}
			writeValue(b, it)
		}
		b.WriteByte(')')
	default:
		panic(fmt.Sprintf("lispwire: cannot write %T", v))
	}
}

// --- Reader ---------------------------------------------------------------

// Read parses one Lisp form from s with *read-eval* semantics disabled (no "#."
// is honoured). Trailing whitespace is tolerated; trailing non-whitespace is an
// error, matching read-from-string on a single-form payload.
func Read(s string) (Value, error) {
	r := &reader{src: s}
	r.skipSpace()
	v, err := r.readValue()
	if err != nil {
		return nil, err
	}
	r.skipSpace()
	if r.pos != len(r.src) {
		return nil, fmt.Errorf("lispwire: trailing data at offset %d", r.pos)
	}
	return v, nil
}

type reader struct {
	src string
	pos int
}

func (r *reader) skipSpace() {
	for r.pos < len(r.src) {
		switch r.src[r.pos] {
		case ' ', '\t', '\n', '\r', '\f':
			r.pos++
		default:
			return
		}
	}
}

func (r *reader) readValue() (Value, error) {
	if r.pos >= len(r.src) {
		return nil, fmt.Errorf("lispwire: unexpected end of input")
	}
	switch c := r.src[r.pos]; {
	case c == '(':
		return r.readList()
	case c == '"':
		return r.readString()
	case c == '#':
		return r.readHash()
	case c == ')':
		return nil, fmt.Errorf("lispwire: unexpected ')' at offset %d", r.pos)
	default:
		return r.readAtom()
	}
}

func (r *reader) readList() (Value, error) {
	r.pos++ // consume '('
	var items []Value
	dotted := false
	for {
		r.skipSpace()
		if r.pos >= len(r.src) {
			return nil, fmt.Errorf("lispwire: unterminated list")
		}
		if r.src[r.pos] == ')' {
			r.pos++
			return List{Items: items, Dotted: dotted}, nil
		}
		// A lone "." introduces the dotted cdr: exactly one more value, then ')'.
		if r.src[r.pos] == '.' && r.pos+1 < len(r.src) && isDelimiter(r.src[r.pos+1]) {
			r.pos++
			r.skipSpace()
			tail, err := r.readValue()
			if err != nil {
				return nil, err
			}
			items = append(items, tail)
			dotted = true
			r.skipSpace()
			if r.pos >= len(r.src) || r.src[r.pos] != ')' {
				return nil, fmt.Errorf("lispwire: malformed dotted list at offset %d", r.pos)
			}
			r.pos++
			return List{Items: items, Dotted: dotted}, nil
		}
		v, err := r.readValue()
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
}

func (r *reader) readString() (Value, error) {
	r.pos++ // consume opening quote
	var b strings.Builder
	for r.pos < len(r.src) {
		c := r.src[r.pos]
		switch c {
		case '\\':
			if r.pos+1 >= len(r.src) {
				return nil, fmt.Errorf("lispwire: dangling escape in string")
			}
			b.WriteByte(r.src[r.pos+1])
			r.pos += 2
		case '"':
			r.pos++
			return Str(b.String()), nil
		default:
			b.WriteByte(c)
			r.pos++
		}
	}
	return nil, fmt.Errorf("lispwire: unterminated string")
}

func (r *reader) readHash() (Value, error) {
	// SBCL prints a base-string as #A((5) BASE-CHAR . "gr8s2") when
	// *print-readably* is on. Raft messages are printed with it off, but the
	// snapshot a witness is sent is printed to a file with it on
	// (raft-link-send-snapshot), so a member id there may arrive this way. It is
	// an ordinary string to us, and is written back as one.
	if r.pos+2 < len(r.src) && (r.src[r.pos+1] == 'A' || r.src[r.pos+1] == 'a') && r.src[r.pos+2] == '(' {
		start := r.pos
		r.pos += 2
		lst, err := r.readList()
		if err != nil {
			return nil, err
		}
		if l := lst.(List); l.Dotted && len(l.Items) == 3 {
			if kind, ok := l.Items[1].(Sym); ok && (kind == "BASE-CHAR" || kind == "CHARACTER") {
				if s, ok := l.Items[2].(Str); ok {
					return s, nil
				}
			}
		}
		return nil, fmt.Errorf("lispwire: unsupported array at offset %d", start)
	}
	// Otherwise only #( simple-vectors are expected on this wire; *read-eval* is
	// off, so reject #. and anything else rather than guess.
	if r.pos+1 < len(r.src) && r.src[r.pos+1] == '(' {
		r.pos++ // consume '#', leaving '(' for readList
		lst, err := r.readList()
		if err != nil {
			return nil, err
		}
		l := lst.(List)
		if l.Dotted {
			return nil, fmt.Errorf("lispwire: dotted vector is invalid")
		}
		return Vec{Items: l.Items}, nil
	}
	return nil, fmt.Errorf("lispwire: unsupported reader macro #%c at offset %d", peekByte(r.src, r.pos+1), r.pos)
}

func (r *reader) readAtom() (Value, error) {
	start := r.pos
	for r.pos < len(r.src) && !isDelimiter(r.src[r.pos]) {
		// A backslash escapes the next char inside a symbol token.
		if r.src[r.pos] == '\\' && r.pos+1 < len(r.src) {
			r.pos += 2
			continue
		}
		r.pos++
	}
	tok := r.src[start:r.pos]
	if tok == "" {
		return nil, fmt.Errorf("lispwire: empty token at offset %d", start)
	}
	if n, big, ok := parseInteger(tok); ok {
		if big != nil {
			return Big{V: big}, nil
		}
		return Int(n), nil
	}
	return Sym(tok), nil
}

func isDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '(', ')', '"':
		return true
	}
	return false
}

func peekByte(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return '?'
	}
	return s[i]
}

// parseInteger recognises a decimal integer token exactly as Lisp would print
// one: optional sign then digits, nothing else. Anything with a non-digit (a
// trailing '.', a ratio, a float) stays a symbol so it round-trips verbatim.
func parseInteger(tok string) (int64, *big.Int, bool) {
	s := tok
	if s == "" || s == "+" || s == "-" {
		return 0, nil, false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i = 1
	}
	if i == len(s) {
		return 0, nil, false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, nil, false
		}
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return 0, nil, false
	}
	if bi.IsInt64() {
		return bi.Int64(), nil, true
	}
	return 0, bi, true
}
