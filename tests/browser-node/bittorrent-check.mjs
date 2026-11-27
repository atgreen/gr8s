// The tab's BitTorrent codec on the cases the Lisp test gives it (podster-9mio): it
// prints what the tab would send and compute, for the test to compare byte for byte
// with what gr8s's agents (cl-torrent) send and compute.
//   node bittorrent-check.mjs CASES.json
import { readFileSync } from "node:fs";
import { bittorrent as bt } from "../../src/server/browser-node-runtime.mjs";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const file = readFileSync(cases.file);
const pieces = [];
for (let at = 0; at < file.length; at += cases.pieceLength) {
  pieces.push(await bt.pieceRoot(file.subarray(at, Math.min(at + cases.pieceLength, file.length)), cases.pieceLength));
}
const messages = cases.messages.map((m) => bt.hex(bt.message(m.kind, {
  piece: m.piece, begin: m.begin, length: m.length, payload: m.payload ? bt.unhex(m.payload) : undefined,
})));
// Decoding what the agents send gives back what was sent.
const decoded = cases.agentMessages.map((hex) => {
  const m = bt.parseMessage(bt.unhex(hex));
  return { kind: m.kind, piece: m.piece ?? null, begin: m.begin ?? null, length: m.length ?? null,
           payload: m.payload ? bt.hex(m.payload) : null };
});
console.log(JSON.stringify({
  handshake: bt.hex(bt.handshake(cases.infohash, bt.unhex(cases.peerId))),
  parsedHandshake: bt.parseHandshake(bt.unhex(cases.agentHandshake)).infohash,
  messages, decoded, pieces,
  bitfield: bt.hex(bt.bitfield(cases.have)),
}));
