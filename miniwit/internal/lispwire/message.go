// SPDX-License-Identifier: Apache-2.0

package lispwire

import (
	"fmt"
)

// Entry is one Raft log entry as it travels on the wire: the transport flattens
// each entry to an (index term command) triple (member.lisp). A witness stores
// the command opaquely, so Command is kept as a parsed Value that prints back
// identically — the witness never interprets it.
type Entry struct {
	Index   int64
	Term    int64
	Command Value
}

// Msg is a decoded Raft message plist. Fields are keyed by their uppercase
// keyword name without the leading colon (e.g. "TERM", "PREV-LOG-INDEX").
// Entries, when present, are parsed out of the ":ENTRIES" field.
type Msg struct {
	Type    string // e.g. "REQUEST-VOTE", "APPEND-ENTRIES" (no leading colon)
	fields  map[string]Value
	Entries []Entry
	// Set only for a binary SNAPSHOT-CHUNK frame: the raw chunk bytes and, on the
	// first chunk, the artifact envelope. See frame.go.
	Data     []byte
	Envelope []byte
}

// Decode parses one RaftEnvelope.payload (ordinary, non-artifact) into a Msg.
func Decode(payload []byte) (*Msg, error) {
	v, err := Read(string(payload))
	if err != nil {
		return nil, err
	}
	lst, ok := v.(List)
	if !ok || lst.Dotted {
		return nil, fmt.Errorf("lispwire: message is not a proper list")
	}
	if len(lst.Items)%2 != 0 {
		return nil, fmt.Errorf("lispwire: message plist has odd length")
	}
	m := &Msg{fields: make(map[string]Value)}
	for i := 0; i < len(lst.Items); i += 2 {
		key, ok := lst.Items[i].(Sym)
		if !ok || len(key) < 2 || key[0] != ':' {
			return nil, fmt.Errorf("lispwire: plist key %d is not a keyword", i)
		}
		name := string(key[1:])
		val := lst.Items[i+1]
		m.fields[name] = val
	}
	if t, ok := m.fields["TYPE"].(Sym); ok && len(t) >= 2 && t[0] == ':' {
		m.Type = string(t[1:])
	} else {
		return nil, fmt.Errorf("lispwire: message has no :TYPE keyword")
	}
	if ev, ok := m.fields["ENTRIES"]; ok {
		entries, err := parseEntries(ev)
		if err != nil {
			return nil, err
		}
		m.Entries = entries
	}
	return m, nil
}

func parseEntries(v Value) ([]Entry, error) {
	lst, ok := v.(List)
	if !ok || lst.Dotted {
		// NIL (no entries) decodes as the symbol NIL, not a list.
		if sym, ok := v.(Sym); ok && sym == "NIL" {
			return nil, nil
		}
		return nil, fmt.Errorf("lispwire: :ENTRIES is not a proper list")
	}
	out := make([]Entry, 0, len(lst.Items))
	for _, it := range lst.Items {
		triple, ok := it.(List)
		if !ok || triple.Dotted || len(triple.Items) != 3 {
			return nil, fmt.Errorf("lispwire: entry is not an (index term command) triple")
		}
		idx, ok := triple.Items[0].(Int)
		if !ok {
			return nil, fmt.Errorf("lispwire: entry index is not an integer")
		}
		term, ok := triple.Items[1].(Int)
		if !ok {
			return nil, fmt.Errorf("lispwire: entry term is not an integer")
		}
		out = append(out, Entry{Index: int64(idx), Term: int64(term), Command: triple.Items[2]})
	}
	return out, nil
}

// Int returns the integer field named key (uppercase, no colon) and whether it
// was present as an integer. Absent or NIL fields return (0, false).
func (m *Msg) Int(key string) (int64, bool) {
	if v, ok := m.fields[key].(Int); ok {
		return int64(v), true
	}
	return 0, false
}

// Str returns the string field named key.
func (m *Msg) Str(key string) (string, bool) {
	if v, ok := m.fields[key].(Str); ok {
		return string(v), true
	}
	return "", false
}

// Sym returns the symbol field named key verbatim (e.g. ":VOTER", "T", "NIL").
func (m *Msg) Sym(key string) (string, bool) {
	if v, ok := m.fields[key].(Sym); ok {
		return string(v), true
	}
	return "", false
}

// Bool reads a Lisp generalized boolean: T (and any non-NIL value) is true, a
// missing field or NIL is false — matching getf + Lisp truthiness.
func (m *Msg) Bool(key string) bool {
	v, ok := m.fields[key]
	if !ok {
		return false
	}
	if sym, ok := v.(Sym); ok && sym == "NIL" {
		return false
	}
	return true
}

// Raw returns the parsed Value for key, if present.
func (m *Msg) Raw(key string) (Value, bool) {
	v, ok := m.fields[key]
	return v, ok
}

// Bytes returns an octet-vector field (#(...) of integers 0–255) as bytes. gr8s
// prints a snapshot chunk's :DATA this way when the chunk travels as a Lisp form
// rather than a binary frame — which is how a witness's config-only snapshot
// arrives (src/raft/transport/snapshot.lisp).
func (m *Msg) Bytes(key string) ([]byte, bool) {
	vec, ok := m.fields[key].(Vec)
	if !ok {
		return nil, false
	}
	b := make([]byte, len(vec.Items))
	for i, it := range vec.Items {
		n, ok := it.(Int)
		if !ok || n < 0 || n > 255 {
			return nil, false
		}
		b[i] = byte(n)
	}
	return b, true
}

// --- Reply builder --------------------------------------------------------

// Builder assembles an outgoing message plist in a fixed key order. cl-raft
// reads fields with getf, so order is irrelevant to it; a stable order just
// makes the wire output deterministic for tests.
type Builder struct {
	items []Value
}

// NewReply starts a message of the given type, e.g. NewReply("REQUEST-VOTE-REPLY").
func NewReply(msgType string) *Builder {
	return &Builder{items: []Value{Sym(":TYPE"), Sym(":" + msgType)}}
}

func (b *Builder) Int(key string, v int64) *Builder {
	b.items = append(b.items, Sym(":"+key), Int(v))
	return b
}

func (b *Builder) Str(key, v string) *Builder {
	b.items = append(b.items, Sym(":"+key), Str(v))
	return b
}

// Bool appends key with the Lisp boolean T or NIL (bare CL symbols, no colon).
func (b *Builder) Bool(key string, v bool) *Builder {
	val := Sym("NIL")
	if v {
		val = Sym("T")
	}
	b.items = append(b.items, Sym(":"+key), val)
	return b
}

// Raw appends key with an arbitrary pre-built Value (e.g. an :ENTRIES list or a
// snapshot :STATE form). Mainly for constructing test inputs and pass-through.
func (b *Builder) Raw(key string, v Value) *Builder {
	b.items = append(b.items, Sym(":"+key), v)
	return b
}

// Encode renders the message to UTF-8 wire octets.
func (b *Builder) Encode() []byte {
	return []byte(Write(List{Items: b.items}))
}
