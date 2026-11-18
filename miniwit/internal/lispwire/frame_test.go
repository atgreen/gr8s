// SPDX-License-Identifier: Apache-2.0

package lispwire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// goldenFrame is a real GR8SCK01 snapshot-chunk frame produced by SBCL using
// member.lisp's exact framing (magic + u32 header/envelope/data lengths + the
// prin1 header + envelope + data). See scratchpad/frame.lisp.
const goldenFrame = "47523853434b3031000000db0000000300000006283a54595045203a534e415053484f542d4348554e4b203a5445524d2037203a46524f4d202267766973696f6e22203a4c4153542d494e44455820313230203a4c4153542d5445524d2036203a544f4b454e2022746f6b2d61626322203a44494745535420223031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323322203a544f54414c203130203a4f46465345542030203a444f4e45204e494c203a464f524d4154203a41525449464143542d563129090909010203040506"

func TestDecodeArtifactFrame(t *testing.T) {
	raw, err := hex.DecodeString(goldenFrame)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodePayload(raw)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if m.Type != "SNAPSHOT-CHUNK" {
		t.Fatalf("type = %q", m.Type)
	}
	checks := []struct {
		key  string
		want int64
	}{
		{"TERM", 7}, {"LAST-INDEX", 120}, {"LAST-TERM", 6}, {"TOTAL", 10}, {"OFFSET", 0},
	}
	for _, c := range checks {
		if got, _ := m.Int(c.key); got != c.want {
			t.Errorf("%s = %d, want %d", c.key, got, c.want)
		}
	}
	if from, _ := m.Str("FROM"); from != "gvision" {
		t.Errorf("from = %q", from)
	}
	if tok, _ := m.Str("TOKEN"); tok != "tok-abc" {
		t.Errorf("token = %q", tok)
	}
	if m.Bool("DONE") {
		t.Error("done should be false")
	}
	if !bytes.Equal(m.Data, []byte{1, 2, 3, 4, 5, 6}) {
		t.Errorf("data = %v", m.Data)
	}
	if !bytes.Equal(m.Envelope, []byte{9, 9, 9}) {
		t.Errorf("envelope = %v", m.Envelope)
	}
}

// A non-chunk (ordinary Lisp-form) payload still decodes normally through DecodePayload.
func TestDecodePayloadFallsBackToLisp(t *testing.T) {
	m, err := DecodePayload([]byte(`(:TYPE :REQUEST-VOTE :TERM 3 :FROM "x" :LAST-LOG-INDEX 0 :LAST-LOG-TERM 0)`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "REQUEST-VOTE" {
		t.Errorf("type = %q", m.Type)
	}
}
