// The tab's Service translation (podster-kw5u) on frames the script builds: it prints
// what the tab asks the server, and the frames it sends and delivers, for the Lisp test
// to check.
//   node services-check.mjs
import { serviceTranslation } from "../../src/server/browser-node-runtime.mjs";

const asked = [];
const services = serviceTranslation((message) => asked.push(message));
services.update({ serviceCidrs: ["10.96.0.0/12"] });

const sum = (bytes, start, end, initial = 0) => {
  let s = initial;
  for (let i = start; i < end; i += 2) s += (bytes[i] << 8) | (i + 1 < end ? bytes[i + 1] : 0);
  while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
  return s;
};
// An Ethernet frame holding a TCP segment from SOURCE:SPORT to DESTINATION:DPORT, with
// correct checksums.
function segment(source, sport, destination, dport, payload = [1, 2, 3]) {
  const frame = new Uint8Array(14 + 20 + 20 + payload.length);
  frame[12] = 0x08; frame[13] = 0x00;
  const ip = 14, l4 = 34, length = 20 + payload.length;
  frame[ip] = 0x45; frame[ip + 2] = (20 + length) >> 8; frame[ip + 3] = (20 + length) & 0xff;
  frame[ip + 8] = 64; frame[ip + 9] = 6;
  source.split(".").forEach((p, i) => { frame[ip + 12 + i] = Number(p); });
  destination.split(".").forEach((p, i) => { frame[ip + 16 + i] = Number(p); });
  frame[l4] = sport >> 8; frame[l4 + 1] = sport & 0xff; frame[l4 + 2] = dport >> 8; frame[l4 + 3] = dport & 0xff;
  frame[l4 + 12] = 0x50; frame[l4 + 13] = 0x02;
  frame.set(payload, l4 + 20);
  const ipSum = ~sum(frame, ip, ip + 20) & 0xffff;
  frame[ip + 10] = ipSum >> 8; frame[ip + 11] = ipSum & 0xff;
  const tcpSum = ~sum(frame, l4, l4 + length, sum(frame, ip + 12, ip + 20, 6 + length)) & 0xffff;
  frame[l4 + 16] = tcpSum >> 8; frame[l4 + 17] = tcpSum & 0xff;
  return frame;
}
const describe = (frame) => ({
  source: [...frame.subarray(26, 30)].join("."), sourcePort: (frame[34] << 8) | frame[35],
  destination: [...frame.subarray(30, 34)].join("."), destinationPort: (frame[36] << 8) | frame[37],
  ipChecksumOk: sum(frame, 14, 34) === 0xffff,
  tcpChecksumOk: sum(frame, 34, frame.length, sum(frame, 26, 34, 6 + frame.length - 34)) === 0xffff,
});

const sent = [];
const go = (frame) => sent.push(describe(frame));
// Not a Service: straight through, unasked.
services.out(segment("10.80.32.3", 40000, "10.80.16.2", 8080), go);
const straight = sent.length;
// A Service: held until the server answers, then sent to the backend.
services.out(segment("10.80.32.3", 40001, "10.96.0.11", 80), go);
services.out(segment("10.80.32.3", 40001, "10.96.0.11", 80), go);
const held = sent.length - straight;
services.answer({ op: "service", protocol: "TCP", address: "10.96.0.11", port: 80, backends: [["10.80.16.2", 8080]] });
// More of the connection, and a second one, which the answer serves without asking again.
services.out(segment("10.80.32.3", 40001, "10.96.0.11", 80), go);
services.out(segment("10.80.32.3", 40002, "10.96.0.11", 80), go);
// The backend's reply comes back as from the ClusterIP; others are as they were.
const reply = describe(services.in(segment("10.80.16.2", 8080, "10.80.32.3", 40001)));
const other = describe(services.in(segment("10.80.16.2", 8080, "10.80.32.3", 50000)));
// A Service port without ready backends: dropped.
services.out(segment("10.80.32.3", 40003, "10.96.0.12", 80), go);
services.answer({ op: "service", protocol: "TCP", address: "10.96.0.12", port: 80, backends: [] });
console.log(JSON.stringify({ asked, straight, held, sent, reply, other }));
