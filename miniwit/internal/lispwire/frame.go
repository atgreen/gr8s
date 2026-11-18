// SPDX-License-Identifier: Apache-2.0

package lispwire

import (
	"encoding/binary"
	"fmt"
)

// artifactMagic marks a bounded binary snapshot-chunk frame on the wire:
// "GR8SCK01" (src/raft/transport/member.lisp +raft-artifact-wire-magic+). Ordinary
// Raft messages are Lisp forms; only artifact/snapshot chunks use this frame.
var artifactMagic = []byte{'G', 'R', '8', 'S', 'C', 'K', '0', '1'}

// DecodePayload decodes one RaftEnvelope payload, handling both ordinary Lisp-form
// messages and the binary artifact-chunk frame. For a chunk, Msg.Data and
// Msg.Envelope carry the binary parts that the Lisp header does not.
func DecodePayload(payload []byte) (*Msg, error) {
	if len(payload) >= len(artifactMagic) && string(payload[:len(artifactMagic)]) == string(artifactMagic) {
		return decodeArtifactFrame(payload)
	}
	return Decode(payload)
}

// decodeArtifactFrame parses the binary frame: magic(8) + u32 header-len +
// u32 envelope-len + u32 data-len (all big-endian) + header + envelope + data.
// The header is a Lisp plist (the chunk metadata, with :data and :artifact-envelope
// removed); the data and envelope are returned as raw bytes.
func decodeArtifactFrame(b []byte) (*Msg, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("lispwire: truncated artifact frame")
	}
	h := binary.BigEndian.Uint32(b[8:12])
	e := binary.BigEndian.Uint32(b[12:16])
	d := binary.BigEndian.Uint32(b[16:20])
	total := 20 + uint64(h) + uint64(e) + uint64(d)
	if uint64(len(b)) != total {
		return nil, fmt.Errorf("lispwire: artifact frame length mismatch (want %d, have %d)", total, len(b))
	}
	hdrEnd := 20 + h
	envEnd := hdrEnd + e
	msg, err := Decode(b[20:hdrEnd])
	if err != nil {
		return nil, fmt.Errorf("lispwire: artifact frame header: %w", err)
	}
	if msg.Type != "SNAPSHOT-CHUNK" {
		return nil, fmt.Errorf("lispwire: artifact frame is %q, not SNAPSHOT-CHUNK", msg.Type)
	}
	msg.Data = append([]byte(nil), b[envEnd:]...)
	if e > 0 {
		msg.Envelope = append([]byte(nil), b[hdrEnd:envEnd]...)
	}
	return msg, nil
}
