// SPDX-License-Identifier: Apache-2.0

package lispwire

import "testing"

// Golden wire strings produced by stock SBCL using the exact bindings gr8s's
// raft-lisp-message->octets uses (with-standard-io-syntax + *print-readably*,
// *print-circle*, *print-pretty* bound off). See scratchpad/wire.lisp.
var golden = map[string]string{
	"request-vote":       `(:TYPE :REQUEST-VOTE :TERM 7 :FROM "gvision" :LAST-LOG-INDEX 42 :LAST-LOG-TERM 6 :LEADER-TRANSFER NIL)`,
	"pre-vote":           `(:TYPE :PRE-VOTE :TERM 8 :FROM "gr8s2" :LAST-LOG-INDEX 42 :LAST-LOG-TERM 6)`,
	"append-entries":     `(:TYPE :APPEND-ENTRIES :TERM 7 :FROM "gvision" :PREV-LOG-INDEX 42 :PREV-LOG-TERM 6 :ENTRIES ((43 7 (:RAFT-BARRIER)) (44 7 (:PUT "key" "value"))) :LEADER-COMMIT 42 :READ-SEQ 19)`,
	"append-heartbeat":   `(:TYPE :APPEND-ENTRIES :TERM 7 :FROM "gvision" :PREV-LOG-INDEX 42 :PREV-LOG-TERM 6 :ENTRIES NIL :LEADER-COMMIT 42 :READ-SEQ 20)`,
	"append-config":      `(:TYPE :APPEND-ENTRIES :TERM 7 :FROM "gvision" :PREV-LOG-INDEX 44 :PREV-LOG-TERM 7 :ENTRIES ((45 7 (:RAFT-CONFIG :MEMBERS (("gvision" . :VOTER) ("gr8s2" . :VOTER) ("wit" . :WITNESS)) :ADDRESSES (("gvision" "10.77.77.21" 7000)) :API-URLS NIL :PROMOTIONS NIL))) :LEADER-COMMIT 44 :READ-SEQ 21)`,
	"request-vote-reply": `(:TYPE :REQUEST-VOTE-REPLY :TERM 7 :FROM "wit" :GRANTED T)`,

	// What a witness originates when it stands in for a voter (the same strings
	// raftcore's standin_test.go expects of the real code path).
	"standin-pre-vote":     `(:TYPE :PRE-VOTE :TERM 5 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`,
	"standin-request-vote": `(:TYPE :REQUEST-VOTE :TERM 5 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4 :LEADER-TRANSFER NIL)`,
	"standin-heartbeat":    `(:TYPE :APPEND-ENTRIES :TERM 5 :FROM "wit" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES NIL :LEADER-COMMIT 4 :READ-SEQ 0)`,
	"standin-append":       `(:TYPE :APPEND-ENTRIES :TERM 5 :FROM "wit" :PREV-LOG-INDEX 4 :PREV-LOG-TERM 4 :ENTRIES ((5 4 (:PUT "key" "va\"lue" (1 . 2) #(3 4) NIL))) :LEADER-COMMIT 4 :READ-SEQ 0)`,
	"standin-timeout-now":  `(:TYPE :TIMEOUT-NOW :TERM 5 :FROM "wit")`,
	"pre-vote-reply":       `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "wit" :GRANTED NIL)`,
}

// Read then Write must reproduce each golden string byte-for-byte: this is the
// strongest evidence the codec speaks exactly gr8s's dialect, dotted pairs and all.
func TestRoundTripGolden(t *testing.T) {
	for name, s := range golden {
		v, err := Read(s)
		if err != nil {
			t.Fatalf("%s: Read: %v", name, err)
		}
		if got := Write(v); got != s {
			t.Errorf("%s: round-trip mismatch\n want %s\n  got %s", name, s, got)
		}
	}
}

func TestDecodeRequestVote(t *testing.T) {
	m, err := Decode([]byte(golden["request-vote"]))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "REQUEST-VOTE" {
		t.Errorf("type = %q", m.Type)
	}
	if term, _ := m.Int("TERM"); term != 7 {
		t.Errorf("term = %d", term)
	}
	if from, _ := m.Str("FROM"); from != "gvision" {
		t.Errorf("from = %q", from)
	}
	if lli, _ := m.Int("LAST-LOG-INDEX"); lli != 42 {
		t.Errorf("last-log-index = %d", lli)
	}
	if m.Bool("LEADER-TRANSFER") {
		t.Errorf("leader-transfer should be false (NIL)")
	}
}

func TestDecodeAppendEntries(t *testing.T) {
	m, err := Decode([]byte(golden["append-entries"]))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "APPEND-ENTRIES" {
		t.Errorf("type = %q", m.Type)
	}
	if pli, _ := m.Int("PREV-LOG-INDEX"); pli != 42 {
		t.Errorf("prev-log-index = %d", pli)
	}
	if rs, _ := m.Int("READ-SEQ"); rs != 19 {
		t.Errorf("read-seq = %d", rs)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(m.Entries))
	}
	if m.Entries[0].Index != 43 || m.Entries[0].Term != 7 {
		t.Errorf("entry0 = %+v", m.Entries[0])
	}
	if m.Entries[1].Index != 44 || m.Entries[1].Term != 7 {
		t.Errorf("entry1 = %+v", m.Entries[1])
	}
	// The command is opaque to a witness but must print back identically so a
	// recovered log entry is bit-for-bit what the leader sent.
	if got := Write(m.Entries[1].Command); got != `(:PUT "key" "value")` {
		t.Errorf("entry1 command = %s", got)
	}
}

func TestDecodeHeartbeatHasNoEntries(t *testing.T) {
	m, err := Decode([]byte(golden["append-heartbeat"]))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("heartbeat entries = %d, want 0", len(m.Entries))
	}
}

func TestDecodeConfigEntryWithDottedPairs(t *testing.T) {
	m, err := Decode([]byte(golden["append-config"]))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 {
		t.Fatalf("entries = %d", len(m.Entries))
	}
	// The config command carries dotted member pairs; it must survive verbatim.
	want := `(:RAFT-CONFIG :MEMBERS (("gvision" . :VOTER) ("gr8s2" . :VOTER) ("wit" . :WITNESS)) :ADDRESSES (("gvision" "10.77.77.21" 7000)) :API-URLS NIL :PROMOTIONS NIL)`
	if got := Write(m.Entries[0].Command); got != want {
		t.Errorf("config command round-trip\n want %s\n  got %s", want, got)
	}
}

// A reply built with the Builder must be byte-identical to what SBCL prints, so
// cl-raft's read-from-string + getf reads exactly the fields we intend.
func TestBuildRequestVoteReply(t *testing.T) {
	got := NewReply("REQUEST-VOTE-REPLY").Int("TERM", 7).Str("FROM", "wit").Bool("GRANTED", true).Encode()
	if string(got) != golden["request-vote-reply"] {
		t.Errorf("reply\n want %s\n  got %s", golden["request-vote-reply"], got)
	}
}

// The stand-in's messages, built the way raftcore builds them, must match what
// SBCL prints for the plists cl-raft makes.
func TestBuildStandInMessages(t *testing.T) {
	command, err := Read(`(:PUT "key" "va\"lue" (1 . 2) #(3 4) NIL)`)
	if err != nil {
		t.Fatal(err)
	}
	built := map[string][]byte{
		"standin-pre-vote": NewReply("PRE-VOTE").Int("TERM", 5).Str("FROM", "wit").
			Int("LAST-LOG-INDEX", 5).Int("LAST-LOG-TERM", 4).Encode(),
		"standin-request-vote": NewReply("REQUEST-VOTE").Int("TERM", 5).Str("FROM", "wit").
			Int("LAST-LOG-INDEX", 5).Int("LAST-LOG-TERM", 4).Bool("LEADER-TRANSFER", false).Encode(),
		"standin-heartbeat": NewReply("APPEND-ENTRIES").Int("TERM", 5).Str("FROM", "wit").
			Int("PREV-LOG-INDEX", 5).Int("PREV-LOG-TERM", 4).Raw("ENTRIES", Sym("NIL")).
			Int("LEADER-COMMIT", 4).Int("READ-SEQ", 0).Encode(),
		"standin-append": NewReply("APPEND-ENTRIES").Int("TERM", 5).Str("FROM", "wit").
			Int("PREV-LOG-INDEX", 4).Int("PREV-LOG-TERM", 4).
			Raw("ENTRIES", List{Items: []Value{List{Items: []Value{Int(5), Int(4), command}}}}).
			Int("LEADER-COMMIT", 4).Int("READ-SEQ", 0).Encode(),
		"standin-timeout-now": NewReply("TIMEOUT-NOW").Int("TERM", 5).Str("FROM", "wit").Encode(),
		"pre-vote-reply": NewReply("PRE-VOTE-REPLY").Int("TERM", 4).Int("PRE-TERM", 5).
			Str("FROM", "wit").Bool("GRANTED", false).Encode(),
	}
	for name, got := range built {
		if string(got) != golden[name] {
			t.Errorf("%s\n want %s\n  got %s", name, golden[name], got)
		}
	}
}

// With *print-readably* on -- as it is for the snapshot file a witness is sent --
// SBCL prints a base-string in #A notation. It reads as the string it is.
func TestReadsReadablyPrintedBaseString(t *testing.T) {
	v, err := Read(`(:MEMBERS ((#A((5) BASE-CHAR . "gr8s2") . :VOTER)))`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Write(v), `(:MEMBERS (("gr8s2" . :VOTER)))`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	for _, bad := range []string{`#A((2 2) FIXNUM (1 2) (3 4))`, `#A((1) BASE-CHAR . 7)`, `#.(+ 1 2)`} {
		if _, err := Read(bad); err == nil {
			t.Errorf("Read(%s) should fail", bad)
		}
	}
}

func TestStringEscaping(t *testing.T) {
	// A string containing a quote and backslash must escape and round-trip.
	in := List{Items: []Value{Sym(":FROM"), Str(`a"b\c`)}}
	s := Write(in)
	if s != `(:FROM "a\"b\\c")` {
		t.Fatalf("escaped write = %s", s)
	}
	back, err := Read(s)
	if err != nil {
		t.Fatal(err)
	}
	if Write(back) != s {
		t.Errorf("escape round-trip: %s", Write(back))
	}
}
