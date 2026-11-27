// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0
//
// The browser's half of a gr8s browser node (podster-57fv.2,
// docs/design-browser-nodes.md). The server runs the node's agent; this only
// runs containers. It answers the server's requests over one WebSocket and
// reports each Pod's status whenever its containers change. Each Pod gets its
// own unkernel instance (Linux as wasm), and each container is a process in it.
// Until the server serves images (podster-57fv.4), containers run in the
// instance's own root file system, so a busybox command works and the image is
// only recorded.
//
// The same module runs in a page and under Node: the caller passes
// createKernel and the distro (a URL in a browser, a path under Node).

const encoder = new TextEncoder();

function toBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}
const decoder = new TextDecoder();

// The node's identity (podster-57fv.5): an ECDSA P-256 key whose private half
// never leaves the browser (non-extractable, kept in IndexedDB), and a tab id kept
// for the tab's life. A reload of the tab is the same node; another tab or browser
// profile is another. The server proves possession with a challenge.
async function loadIdentityKey() {
  const fresh = () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  if (typeof indexedDB === "undefined") return fresh();
  const db = await new Promise((resolve, reject) => {
    const open = indexedDB.open("gr8s-browser-node", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  const request = (mode, run) => new Promise((resolve, reject) => {
    const r = run(db.transaction("keys", mode).objectStore("keys"));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  let pair = await request("readonly", (store) => store.get("identity"));
  if (!pair) {
    pair = await fresh();
    await request("readwrite", (store) => store.put(pair, "identity"));
  }
  return pair;
}

function tabId() {
  const make = () => [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (typeof sessionStorage === "undefined") return make();
  let id = sessionStorage.getItem("gr8s-tab");
  if (!id) sessionStorage.setItem("gr8s-tab", (id = make()));
  return id;
}

// Images (podster-57fv.4): the server resolves each container's image and serves its
// layers; here they are unpacked, base first, into an in-memory root the guest
// mounts over 9p, honouring the layers' whiteouts, and the container runs chrooted
// there. A tar stream is read as it arrives.
async function* tarEntries(readable) {
  const reader = readable.getReader();
  let buffer = new Uint8Array(0);
  let done = false;
  const need = async (count) => {
    while (buffer.length < count && !done) {
      const chunk = await reader.read();
      if (chunk.done) done = true;
      else {
        const joined = new Uint8Array(buffer.length + chunk.value.length);
        joined.set(buffer);
        joined.set(chunk.value, buffer.length);
        buffer = joined;
      }
    }
    return buffer.length >= count;
  };
  const take = (count) => {
    const out = buffer.subarray(0, count);
    buffer = buffer.subarray(count);
    return out;
  };
  const text = (bytes) => decoder.decode(bytes.subarray(0, bytes.indexOf(0) < 0 ? bytes.length : bytes.indexOf(0)));
  const octal = (bytes) => parseInt(text(bytes).trim() || "0", 8);
  let pax = {};
  let longName = null;
  let longLink = null;
  while (await need(512)) {
    const header = take(512).slice();
    if (header.every((b) => b === 0)) break;
    const size = octal(header.subarray(124, 136));
    const type = String.fromCharCode(header[156] || 48);
    const padding = (512 - (size % 512)) % 512;
    if (!(await need(size))) throw new Error("a layer ended inside a file");
    await need(size + padding);
    const data = take(size).slice();
    take(Math.min(padding, buffer.length));
    if (type === "x") {
      for (const line of decoder.decode(data).split("\n")) {
        const match = /^\d+ ([^=]+)=(.*)$/.exec(line);
        if (match) pax[match[1]] = match[2];
      }
      continue;
    }
    if (type === "g") continue;
    if (type === "L") { longName = text(data); continue; }
    if (type === "K") { longLink = text(data); continue; }
    const prefix = text(header.subarray(345, 500));
    const name = pax.path ?? longName ?? (prefix ? `${prefix}/${text(header.subarray(0, 100))}` : text(header.subarray(0, 100)));
    const link = pax.linkpath ?? longLink ?? text(header.subarray(157, 257));
    yield { name, type, mode: octal(header.subarray(100, 108)) & 0o7777, link, data };
    pax = {};
    longName = longLink = null;
  }
}

async function unpackLayer(fs, response, mediaType) {
  let body = response.body;
  if (/gzip/.test(mediaType)) body = body.pipeThrough(new DecompressionStream("gzip"));
  else if (/zstd/.test(mediaType)) throw new Error("zstd layers aren't supported in a browser node yet");
  for await (const entry of tarEntries(body)) {
    const path = "/" + entry.name.replace(/^(\.\/|\/)+/, "").replace(/\/+$/, "");
    if (path === "/") continue;
    const slash = path.lastIndexOf("/");
    const directory = path.slice(0, slash) || "/";
    const base = path.slice(slash + 1);
    if (base === ".wh..wh..opq") {
      if (fs.exists(directory)) for (const name of fs.list(directory)) fs.rm(`${directory === "/" ? "" : directory}/${name}`, { recursive: true, force: true });
      continue;
    }
    if (base.startsWith(".wh.")) {
      fs.rm(`${directory === "/" ? "" : directory}/${base.slice(4)}`, { recursive: true, force: true });
      continue;
    }
    if (entry.type === "5") {
      fs.mkdirp(path, { mode: entry.mode || 0o755 });
      continue;
    }
    if (directory !== "/") fs.mkdirp(directory);
    if (entry.type === "2") {
      fs.rm(path, { force: true });
      fs.writeLink(path, entry.link);
    } else if (entry.type === "1") {
      const target = "/" + entry.link.replace(/^(\.\/|\/)+/, "");
      if (fs.exists(target)) fs.writeFile(path, fs.readFile(target), { mode: fs.stat(target)?.mode & 0o7777 });
    } else if (entry.type === "0" || entry.type === "7") {
      if (fs.stat(path)?.type === "dir") fs.rm(path, { recursive: true, force: true });
      fs.writeFile(path, entry.data, { mode: entry.mode || 0o644 });
    }
  }
}

// The tab's layer cache (podster-57fv.11): layers it has downloaded, kept in the
// origin-private file system by digest, so a reload or another Pod of the same image
// needn't download them again. A layer is checked against its digest whenever it is
// read, from the server or the cache. Least recently used layers go past a budget.
const layerCache = {
  async directory() {
    if (!globalThis.navigator?.storage?.getDirectory) return null;
    try {
      return await navigator.storage.getDirectory().then((root) => root.getDirectoryHandle("gr8s-layers", { create: true }));
    } catch {
      return null;
    }
  },
  async index(dir) {
    try {
      return JSON.parse(await (await (await dir.getFileHandle("index.json")).getFile()).text());
    } catch {
      return {};
    }
  },
  async saveIndex(dir, index) {
    const writable = await (await dir.getFileHandle("index.json", { create: true })).createWritable();
    await writable.write(JSON.stringify(index));
    await writable.close();
  },
  async digests() {
    const dir = await this.directory();
    return dir ? Object.keys(await this.index(dir)) : [];
  },
  async get(digest) {
    const dir = await this.directory();
    if (!dir) return null;
    try {
      const bytes = new Uint8Array(await (await (await dir.getFileHandle(digest.replace(":", "-"))).getFile()).arrayBuffer());
      const index = await this.index(dir);
      index[digest] = { size: bytes.length, used: Date.now() };
      await this.saveIndex(dir, index);
      return bytes;
    } catch {
      return null;
    }
  },
  async put(digest, bytes) {
    const dir = await this.directory();
    if (!dir) return;
    try {
      const writable = await (await dir.getFileHandle(digest.replace(":", "-"), { create: true })).createWritable();
      await writable.write(bytes);
      await writable.close();
      const index = await this.index(dir);
      index[digest] = { size: bytes.length, used: Date.now() };
      const quota = (await navigator.storage.estimate?.())?.quota ?? 0;
      const budget = Math.min(2 ** 31, quota > 0 ? quota / 4 : 2 ** 30);
      let total = Object.values(index).reduce((sum, entry) => sum + entry.size, 0);
      for (const [old, entry] of Object.entries(index).sort((a, b) => a[1].used - b[1].used)) {
        if (total <= budget || old === digest) continue;
        await dir.removeEntry(old.replace(":", "-")).catch(() => {});
        delete index[old];
        total -= entry.size;
      }
      await this.saveIndex(dir, index);
    } catch {
      // A full or unavailable store only means downloading again next time.
    }
  },
};

async function sha256Matches(digest, bytes) {
  if (!digest.startsWith("sha256:")) return false;
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return digest.slice(7) === [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// BitTorrent between tabs (podster-9mio): the protocol gr8s's agents share image
// layers with (BEP 52 torrents, the standard peer wire), byte for byte, carried over
// WebRTC data channels, since a tab can't open TCP connections. Each layer is a
// torrent the server describes (piece length, each piece's Merkle root); a tab fetches
// pieces from tabs that hold them, rarest first, checks each piece as it arrives,
// shares the pieces it has while still downloading, and drops a peer at its first bad
// piece. The server seeds every piece too, so a layer always arrives.
export const bittorrent = (() => {
  const BLOCK = 16384;
  const NAME = new TextEncoder().encode("BitTorrent protocol");
  const KINDS = ["choke", "unchoke", "interested", "not-interested", "have", "bitfield", "request", "piece", "cancel"];
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (text) => Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
  const u32 = (bytes, at) => ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
  const putU32 = (bytes, at, value) => {
    bytes[at] = value >>> 24; bytes[at + 1] = (value >>> 16) & 255; bytes[at + 2] = (value >>> 8) & 255; bytes[at + 3] = value & 255;
  };
  // The handshake: the protocol name, eight reserved bytes (none set, as the agents
  // send them), the first 20 bytes of the v2 infohash, and the peer id.
  function handshake(infohash, peerId) {
    const bytes = new Uint8Array(68);
    bytes[0] = NAME.length;
    bytes.set(NAME, 1);
    bytes.set(unhex(infohash).subarray(0, 20), 28);
    bytes.set(peerId, 48);
    return bytes;
  }
  function parseHandshake(bytes) {
    if (bytes.length !== 68 || bytes[0] !== NAME.length || hex(bytes.subarray(1, 20)) !== hex(NAME)) {
      throw new Error("not a BitTorrent handshake");
    }
    return { infohash: hex(bytes.subarray(28, 48)), peerId: bytes.slice(48, 68) };
  }
  function message(kind, { piece = 0, begin = 0, length = 0, payload = new Uint8Array(0) } = {}) {
    const size = kind === "have" ? 4 : kind === "bitfield" ? payload.length
      : kind === "request" || kind === "cancel" ? 12 : kind === "piece" ? 8 + payload.length : 0;
    const bytes = new Uint8Array(5 + size);
    putU32(bytes, 0, 1 + size);
    bytes[4] = KINDS.indexOf(kind);
    if (kind === "have") putU32(bytes, 5, piece);
    else if (kind === "bitfield") bytes.set(payload, 5);
    else if (kind === "request" || kind === "cancel") { putU32(bytes, 5, piece); putU32(bytes, 9, begin); putU32(bytes, 13, length); }
    else if (kind === "piece") { putU32(bytes, 5, piece); putU32(bytes, 9, begin); bytes.set(payload, 13); }
    return bytes;
  }
  function parseMessage(bytes) {
    if (bytes.length < 4 || u32(bytes, 0) + 4 !== bytes.length) throw new Error("bad BitTorrent message length");
    if (bytes.length === 4) return { kind: "keepalive" };
    const kind = KINDS[bytes[4]];
    if (!kind) throw new Error(`unknown BitTorrent message ${bytes[4]}`);
    const m = { kind };
    if (kind === "have") m.piece = u32(bytes, 5);
    else if (kind === "bitfield") m.payload = bytes.slice(5);
    else if (kind === "request" || kind === "cancel") { m.piece = u32(bytes, 5); m.begin = u32(bytes, 9); m.length = u32(bytes, 13); }
    else if (kind === "piece") { m.piece = u32(bytes, 5); m.begin = u32(bytes, 9); m.payload = bytes.slice(13); }
    return m;
  }
  // What arrives on a channel, as a byte stream, back to frames: the handshake, then
  // length-prefixed messages, whatever the channel's message boundaries.
  function framer(onFrame) {
    let buffer = new Uint8Array(0);
    let handshaken = false;
    return (chunk) => {
      const joined = new Uint8Array(buffer.length + chunk.length);
      joined.set(buffer);
      joined.set(chunk, buffer.length);
      buffer = joined;
      for (;;) {
        const need = handshaken ? (buffer.length >= 4 ? 4 + u32(buffer, 0) : Infinity) : 68;
        if (need !== Infinity && need > 1 << 20) throw new Error("BitTorrent frame too long");
        if (buffer.length < need) return;
        const frame = buffer.slice(0, need);
        buffer = buffer.slice(need);
        if (handshaken) onFrame(parseMessage(frame), false);
        else { handshaken = true; onFrame(parseHandshake(frame), true); }
      }
    };
  }
  function bitfield(have) {
    const bytes = new Uint8Array(Math.ceil(have.length / 8));
    have.forEach((held, index) => { if (held) bytes[index >> 3] |= 0x80 >> (index & 7); });
    return bytes;
  }
  const fromBitfield = (bytes, count) => Uint8Array.from({ length: count }, (_, i) => (bytes[i >> 3] >> (7 - (i & 7))) & 1);
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  // A piece's BEP 52 Merkle root: SHA-256 of each 16 KiB block, a short last piece
  // padded with zero leaves, hashed pairwise up to one.
  async function pieceRoot(bytes, pieceLength) {
    let level = [];
    for (let at = 0; at < bytes.length; at += BLOCK) level.push(await sha256(bytes.subarray(at, Math.min(at + BLOCK, bytes.length))));
    while (level.length < pieceLength / BLOCK) level.push(new Uint8Array(32));
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const pair = new Uint8Array(64);
        pair.set(level[i]);
        pair.set(level[i + 1], 32);
        next.push(await sha256(pair));
      }
      level = next;
    }
    return hex(level[0]);
  }
  return { BLOCK, hex, unhex, handshake, parseHandshake, message, parseMessage, framer, bitfield, fromBitfield, pieceRoot };
})();

// A layer's bytes: from the cache when held and intact, else from SWARM, which gets
// its pieces from other tabs and the server and checks each; then kept.
async function layerBytes(layer, base, log, swarm) {
  const verify = !layer.decompressed;
  const cached = await layerCache.get(layer.digest);
  if (cached && (!verify || (await sha256Matches(layer.digest, cached)))) {
    log(`layer ${layer.digest.slice(7, 19)} from the tab's cache`);
    return cached;
  }
  const torrent = await swarm.torrent(layer.digest);
  const bytes = await swarm.download(layer.digest, torrent, layer.peers ?? []);
  if (!(await sha256Matches(torrent.content, bytes))) throw new Error(`layer ${layer.digest} did not match its digest`);
  await layerCache.put(layer.digest, bytes);
  return bytes;
}

// How much of each container's output is kept for `kubectl logs`.
const LOG_LIMIT = 1 << 20;

function now() {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

/**
 * Join a gr8s cluster as a browser node and run what it schedules here.
 * onInfo receives the server's periodic summary of this node, its Pods and the
 * cluster. Returns { close(), node: Promise<name>, closed: Promise }.
 */
/** What browser this is, as { name, os }: the server shows only names it knows. */
function describeBrowser() {
  const ua = globalThis.navigator?.userAgent ?? "";
  const name = /SamsungBrowser/.test(ua) ? "Samsung Internet"
    : /Edg\//.test(ua) ? "Edge"
    : /OPR\//.test(ua) ? "Opera"
    : /Vivaldi/.test(ua) ? "Vivaldi"
    : globalThis.navigator?.brave ? "Brave"
    : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari" : null;
  const os = /Android/.test(ua) ? "Android"
    : /iPhone|iPad|iPod/.test(ua) ? "iOS"
    : /CrOS/.test(ua) ? "ChromeOS"
    : /Windows/.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Linux/.test(ua) ? "Linux" : null;
  return { name, os };
}

export function joinCluster({ url, createKernel, MemoryFs, distro, memoryMiB = 256, capacity, log = () => {}, onInfo = () => {} }) {
  const pods = new Map(); // uid -> Pod
  const execs = new Map(); // exec id -> { process, pty }
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";

  // The Pods' network: a learning switch between each Pod's virtual NIC and the
  // server, which routes the node's Pod CIDR to this tab. Frames are Ethernet.
  const nics = new Map(); // MAC (hex) -> { kernel }
  const macOf = (frame, offset) => [...frame.subarray(offset, offset + 6)].map((b) => b.toString(16).padStart(2, "0")).join(":");
  const deliver = (frame, from) => {
    const destination = macOf(frame, 0);
    const local = nics.get(destination);
    if (local && local !== from) local.kernel?.receiveFrame(frame);
    else if (frame[0] & 1) for (const nic of nics.values()) if (nic !== from) nic.kernel?.receiveFrame(frame);
  };
  // The guest's NIC offloads TCP and UDP checksums, leaving only the pseudo-header
  // sum: as the "hardware" here, finish them before a frame leaves the Pod.
  function finishChecksum(frame) {
    if (frame.length < 34 || frame[12] !== 0x08 || frame[13] !== 0x00) return frame; // IPv4 only
    const ip = 14;
    const headerLength = (frame[ip] & 0x0f) * 4;
    const protocol = frame[ip + 9];
    if (protocol !== 6 && protocol !== 17) return frame;
    const totalLength = (frame[ip + 2] << 8) | frame[ip + 3];
    const l4 = ip + headerLength;
    const length = totalLength - headerLength;
    if (l4 + length > frame.length || (frame[ip + 6] & 0x3f) || frame[ip + 7]) return frame; // fragments as they are
    const field = l4 + (protocol === 6 ? 16 : 6);
    if (protocol === 17 && frame[field] === 0 && frame[field + 1] === 0) return frame; // UDP without one
    frame[field] = 0;
    frame[field + 1] = 0;
    let sum = protocol + length;
    for (let i = ip + 12; i < ip + 20; i += 2) sum += (frame[i] << 8) | frame[i + 1];
    for (let i = 0; i < length; i += 2) sum += (frame[l4 + i] << 8) | (i + 1 < length ? frame[l4 + i + 1] : 0);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    let checksum = ~sum & 0xffff;
    if (checksum === 0 && protocol === 17) checksum = 0xffff;
    frame[field] = checksum >> 8;
    frame[field + 1] = checksum & 0xff;
    return frame;
  }

  // East-west between tabs (podster-57fv.13). Each other browser node is reached over a
  // WebRTC data channel when one opens: a Pod's packet for an address in that node's
  // CIDR goes straight to it, and anything else, or anything before the channel opens,
  // through the server as before. The server introduces the peers and relays their
  // signals; what arrives is taken only from the peer's own CIDR, and only as this
  // tab's Pods' ingress policy admits it, or as a reply to what they sent.
  // Layers as torrents shared with other tabs (podster-9mio).
  const swarm = (() => {
    const peerId = new Uint8Array(20);
    peerId.set(new TextEncoder().encode("-GR0001-"));
    crypto.getRandomValues(peerId.subarray(8));
    const base = url.replace(/^ws/, "http");
    const torrents = new Map(); // digest -> Promise of its description
    const partial = new Map(); // digest -> { torrent, bytes, have, seeders }
    const bt = bittorrent;
    const pieceSize = (torrent, index) => Math.min(torrent.pieceLength, torrent.length - index * torrent.pieceLength);
    const timeout = (ms) => new Promise((_, reject) => setTimeout(() => reject(new Error("timed out")), ms));

    function torrent(digest) {
      if (!torrents.has(digest)) {
        torrents.set(digest, fetch(new URL(`torrents/${digest}`, base)).then((response) => {
          if (!response.ok) throw new Error(`layer ${digest}: no torrent (HTTP ${response.status})`);
          return response.json();
        }));
        torrents.get(digest).catch(() => torrents.delete(digest));
      }
      return torrents.get(digest);
    }

    // Give a peer that asks on CHANNEL the pieces of layer DIGEST this tab holds.
    async function serve(channel, digest) {
      channel.binaryType = "arraybuffer";
      // The peer speaks as soon as the channel opens: keep what it says until this tab
      // knows what it holds.
      const early = [];
      channel.onmessage = (event) => early.push(new Uint8Array(event.data));
      let source = partial.get(digest);
      if (!source) {
        const [bytes, description] = await Promise.all([layerCache.get(digest), torrent(digest).catch(() => null)]);
        if (!bytes || !description) { channel.close(); return; }
        source = { torrent: description, bytes, have: new Uint8Array(description.pieces.length).fill(1), seeders: new Set() };
      }
      const { torrent: description } = source;
      const sendFrame = async (frame) => {
        while (channel.bufferedAmount > 1 << 22) await new Promise((r) => setTimeout(r, 20));
        if (channel.readyState === "open") channel.send(frame);
      };
      const onHave = (index) => sendFrame(bt.message("have", { piece: index }));
      const receive = bt.framer((frame, first) => {
        if (first) {
          if (frame.infohash !== description.infohash.slice(0, 40)) { channel.close(); return; }
          sendFrame(bt.handshake(description.infohash, peerId));
          sendFrame(bt.message("bitfield", { payload: bt.bitfield(source.have) }));
          source.seeders.add(onHave);
        } else if (frame.kind === "interested") {
          sendFrame(bt.message("unchoke"));
        } else if (frame.kind === "request") {
          const { piece, begin, length } = frame;
          if (piece >= description.pieces.length || !source.have[piece] || length > bt.BLOCK
              || begin + length > pieceSize(description, piece)) return;
          const at = piece * description.pieceLength + begin;
          sendFrame(bt.message("piece", { piece, begin, payload: source.bytes.subarray(at, at + length) }));
        }
      });
      const take = (chunk) => { try { receive(chunk); } catch { channel.close(); } };
      channel.onmessage = (event) => take(new Uint8Array(event.data));
      early.splice(0).forEach(take);
      channel.onclose = () => source.seeders.delete(onHave);
    }

    // Layer DIGEST, whose torrent is DESCRIPTION, from the tabs PEERS and the server.
    async function download(digest, description, peers) {
      const count = description.pieces.length;
      const job = {
        bytes: new Uint8Array(description.length), have: new Uint8Array(count), inflight: new Set(),
        availability: new Uint16Array(count), seeders: new Set(), from: new Map(), left: count,
      };
      let finished;
      const done = new Promise((r) => { finished = r; });
      if (count === 0) return job.bytes;
      partial.set(digest, { torrent: description, bytes: job.bytes, have: job.have, seeders: job.seeders });
      peering.announce();
      // Keep a piece whose Merkle root is the torrent's; false when it isn't.
      const accept = async (index, bytes, source) => {
        if (job.have[index]) return true;
        if ((await bt.pieceRoot(bytes, description.pieceLength)) !== description.pieces[index]) return false;
        if (job.have[index]) return true;
        job.bytes.set(bytes, index * description.pieceLength);
        job.have[index] = 1;
        job.inflight.delete(index);
        job.from.set(source, (job.from.get(source) ?? 0) + 1);
        job.seeders.forEach((tell) => tell(index));
        if (--job.left === 0) finished();
        return true;
      };
      // The next piece for a source with HELD pieces: the rarest one nobody is
      // fetching; once all are being fetched, any still missing (the endgame).
      const pick = (held, fromEnd) => {
        let best = -1;
        for (let step = 0; step < count; step++) {
          const i = fromEnd ? count - 1 - step : step;
          if (job.have[i] || job.inflight.has(i) || (held && !held[i])) continue;
          if (best < 0 || job.availability[i] < job.availability[best]) best = i;
        }
        if (best < 0) {
          for (let step = 0; step < count; step++) {
            const i = fromEnd ? count - 1 - step : step;
            if (!job.have[i] && (!held || held[i])) return i;
          }
        }
        return best;
      };

      async function fromPeer(node) {
        const channel = await peering.channel(node, `bt:${digest}`);
        if (!channel) return;
        const held = new Uint8Array(count);
        const pending = new Map();
        let handshake, unchoke;
        const shook = new Promise((r) => { handshake = r; });
        const unchoked = new Promise((r) => { unchoke = r; });
        const receive = bt.framer((frame, first) => {
          if (first) { if (frame.infohash === description.infohash.slice(0, 40)) handshake(); else channel.close(); return; }
          if (frame.kind === "bitfield") {
            bt.fromBitfield(frame.payload, count).forEach((h, i) => { if (h && !held[i]) { held[i] = 1; job.availability[i]++; } });
          } else if (frame.kind === "have" && frame.piece < count && !held[frame.piece]) {
            held[frame.piece] = 1; job.availability[frame.piece]++;
          } else if (frame.kind === "unchoke") unchoke();
          else if (frame.kind === "piece") pending.get(`${frame.piece}:${frame.begin}`)?.(frame.payload);
        });
        channel.onmessage = (event) => { try { receive(new Uint8Array(event.data)); } catch { channel.close(); } };
        try {
          channel.send(bt.handshake(description.infohash, peerId));
          await Promise.race([shook, timeout(10000)]);
          channel.send(bt.message("interested"));
          await Promise.race([unchoked, timeout(10000)]);
          while (job.left > 0 && channel.readyState === "open") {
            const index = pick(held, false);
            if (index < 0) { await new Promise((r) => setTimeout(r, 250)); continue; }
            job.inflight.add(index);
            const size = pieceSize(description, index);
            const blocks = [];
            for (let begin = 0; begin < size; begin += bt.BLOCK) {
              const length = Math.min(bt.BLOCK, size - begin);
              blocks.push(new Promise((r) => pending.set(`${index}:${begin}`, r)));
              channel.send(bt.message("request", { piece: index, begin, length }));
            }
            let parts;
            try {
              parts = await Promise.race([Promise.all(blocks), timeout(20000)]);
            } catch {
              job.inflight.delete(index);
              break;
            }
            const piece = new Uint8Array(size);
            parts.forEach((part, i) => piece.set(part, i * bt.BLOCK));
            if (!(await accept(index, piece, node))) {
              // A bad piece: this peer is done with.
              log(`layer ${digest.slice(7, 19)}: ${node} sent a bad piece; dropped it`);
              job.inflight.delete(index);
              break;
            }
          }
        } catch {
          // A peer that doesn't answer is simply not used.
        } finally {
          held.forEach((h, i) => { if (h) job.availability[i]--; });
          channel.close();
        }
      }

      // The server seeds every piece; it takes pieces from the end, so tabs, which
      // start from the rarest, are used first where they can serve.
      async function fromServer() {
        if (peers.length) await new Promise((r) => setTimeout(r, 1500));
        while (job.left > 0) {
          const index = pick(null, true);
          if (index < 0) { await new Promise((r) => setTimeout(r, 100)); continue; }
          job.inflight.add(index);
          const start = index * description.pieceLength;
          const response = await fetch(new URL(`blobs/${digest}`, base), {
            headers: { Range: `bytes=${start}-${start + pieceSize(description, index) - 1}` },
          });
          if (!response.ok) throw new Error(`layer ${digest}: HTTP ${response.status}`);
          if (!(await accept(index, new Uint8Array(await response.arrayBuffer()), "the server"))) {
            throw new Error(`layer ${digest}: the server's piece ${index} did not match`);
          }
        }
      }

      try {
        const server = fromServer();
        peers.slice(0, 8).forEach((node) => fromPeer(node));
        await Promise.race([done, server.then(() => done)]);
      } finally {
        partial.delete(digest);
        peering.announce();
      }
      const fromTabs = [...job.from].filter(([source]) => source !== "the server");
      log(`layer ${digest.slice(7, 19)}: ${count} piece${count === 1 ? "" : "s"}, `
          + (fromTabs.length ? fromTabs.map(([node, n]) => `${n} from ${node}`).join(", ") + ", " : "")
          + `${job.from.get("the server") ?? 0} from the server`);
      return job.bytes;
    }

    return { torrent, serve, download, downloading: () => [...partial.keys()] };
  })();

  const peering = (() => {
    const available = typeof RTCPeerConnection !== "undefined";
    let self = null, peers = [], iceServers = [], policy = {};
    const links = new Map(); // node -> { pc, pods, layers, ready, waiters }
    const flows = new Map(); // "proto src sport dst dport" -> time
    const asked = new Map(); // node -> when this tab last asked it to connect
    const FLOW_IDLE = 300000;
    const toNumber = (address) => address.split(".").reduce((n, part) => n * 256 + Number(part), 0);
    const inCidr = (cidr, address) => {
      const [base, bits] = cidr.split("/");
      const mask = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
      return ((toNumber(base) & mask) >>> 0) === ((toNumber(address) & mask) >>> 0);
    };
    const ip = (bytes, at) => `${bytes[at]}.${bytes[at + 1]}.${bytes[at + 2]}.${bytes[at + 3]}`;
    const flowOf = (packet) => {
      const protocol = packet[9];
      const l4 = (packet[0] & 0x0f) * 4;
      const ports = (protocol === 6 || protocol === 17) && packet.length >= l4 + 4;
      return {
        protocol, source: ip(packet, 12), destination: ip(packet, 16),
        sourcePort: ports ? (packet[l4] << 8) | packet[l4 + 1] : null,
        destinationPort: ports ? (packet[l4 + 2] << 8) | packet[l4 + 3] : null,
      };
    };
    const key = (f, reverse) => reverse
      ? `${f.protocol} ${f.destination} ${f.destinationPort} ${f.source} ${f.sourcePort}`
      : `${f.protocol} ${f.source} ${f.sourcePort} ${f.destination} ${f.destinationPort}`;
    const admits = (f) => {
      const now = Date.now();
      const seen = flows.get(key(f, true)) ?? flows.get(key(f, false));
      if (seen && now - seen < FLOW_IDLE) return true;
      const pod = policy[f.destination];
      if (pod?.isolated) {
        const ok = (pod.entries ?? []).some((entry) =>
          inCidr(entry.cidr, f.source) &&
          !(entry.excepts ?? []).some((except) => inCidr(except, f.source)) &&
          (entry.ports === "all" || entry.ports.some(([protocol, first, last]) =>
            protocol === f.protocol && (first === null || (f.destinationPort !== null && first <= f.destinationPort && f.destinationPort <= (last ?? first))))));
        if (!ok) return false;
      }
      return true;
    };
    const peerFor = (address) => peers.find((peer) => inCidr(peer.cidr, address));
    const gatewayMac = Uint8Array.from([2, 0, 0, 0, 0, 1]);

    function receivePacket(node, data) {
      const packet = new Uint8Array(data);
      if (packet.length < 20 || packet[0] >> 4 !== 4) return;
      const peer = peers.find((p) => p.node === node);
      const f = flowOf(packet);
      if (!peer || !inCidr(peer.cidr, f.source) || !admits(f)) return;
      flows.set(key(f, false), Date.now());
      const nic = [...pods.values()].find((pod) => pod.request.network?.address === f.destination)?.nic;
      if (!nic?.kernel) return;
      const frame = new Uint8Array(14 + packet.length);
      frame.set(nic.mac, 0);
      frame.set(gatewayMac, 6);
      frame[12] = 0x08;
      frame[13] = 0x00;
      frame.set(packet, 14);
      nic.kernel.receiveFrame(frame);
    }

    // Layers a peer asks for: from the cache, in chunks, then an end marker.
    function link(node) {
      let l = links.get(node);
      if (l) return l;
      l = { pc: new RTCPeerConnection({ iceServers }), pods: null, layers: null, ready: false, waiters: [], queue: Promise.resolve() };
      links.set(node, l);
      l.pc.onicecandidate = (event) => {
        if (event.candidate) send({ op: "signal", to: node, data: { candidate: event.candidate.toJSON() } });
      };
      l.pc.onconnectionstatechange = () => {
        if (["failed", "closed"].includes(l.pc.connectionState)) { links.delete(node); l.ready = false; }
      };
      const adopt = (channel) => {
        channel.binaryType = "arraybuffer";
        if (channel.label === "pods") {
          l.pods = channel;
          channel.onopen = () => { l.ready = true; log(`direct link to ${node}`); l.waiters.splice(0).forEach((w) => w()); };
          channel.onmessage = (event) => receivePacket(node, event.data);
          if (channel.readyState === "open") channel.onopen();
        } else if (channel.label.startsWith("bt:")) {
          swarm.serve(channel, channel.label.slice(3));
        }
      };
      l.pc.ondatachannel = (event) => adopt(event.channel);
      l.adopt = adopt;
      return l;
    }

    async function offer(node) {
      const l = link(node);
      l.adopt(l.pc.createDataChannel("pods", { ordered: false, maxRetransmits: 0 }));
      await l.pc.setLocalDescription(await l.pc.createOffer());
      send({ op: "signal", to: node, data: { sdp: l.pc.localDescription.toJSON() } });
    }

    function connect(node) {
      if (!available || links.has(node) || !self) return;
      // The lower name offers, so two tabs never offer to each other at once.
      if (self < node) offer(node).catch(() => links.delete(node));
      else if (!(Date.now() - (asked.get(node) ?? 0) < 10000)) {
        asked.set(node, Date.now());
        send({ op: "signal", to: node, data: { want: true } });
      }
    }

    return {
      update(info) {
        self = info.node?.name ?? self;
        peers = info.peers ?? [];
        iceServers = [...(info.iceServers ?? [])];
        // The server's own STUN responder, at the address this page came from.
        const host = globalThis.location?.hostname;
        if (info.stunPort && host) iceServers.push({ urls: `stun:${host}:${info.stunPort}` });
        policy = info.ingressPolicy ?? {};
        // Link up with peers as soon as they are known, so a Pod's first packets
        // needn't detour through the server.
        for (const peer of peers.slice(0, 32)) connect(peer.node);
        this.announce();
      },
      // Which layers this tab can give its peers, held or still arriving, whenever
      // that changes.
      announce() {
        layerCache.digests().then((digests) => {
          const all = [...new Set([...digests, ...swarm.downloading()])].sort();
          const listed = all.join(",");
          if (listed !== this.reported) {
            this.reported = listed;
            send({ op: "have", digests: all });
          }
        });
      },
      async signal(from, data) {
        if (!available || !data) return;
        if (data.want) { if (self < from && !links.has(from)) offer(from).catch(() => links.delete(from)); return; }
        const l = link(from);
        if (data.sdp) {
          await l.pc.setRemoteDescription(data.sdp);
          if (data.sdp.type === "offer") {
            await l.pc.setLocalDescription(await l.pc.createAnswer());
            send({ op: "signal", to: from, data: { sdp: l.pc.localDescription.toJSON() } });
          }
        } else if (data.candidate) {
          await l.pc.addIceCandidate(data.candidate).catch(() => {});
        }
      },
      // Send a Pod's frame straight to the peer whose CIDR holds its destination, if
      // a channel to it is open; start one otherwise. True when it went.
      send(frame) {
        if (!available || frame.length < 34 || frame[12] !== 0x08 || frame[13] !== 0x00) return false;
        const packet = frame.subarray(14);
        const destination = ip(packet, 16);
        const peer = peerFor(destination);
        if (!peer) return false;
        const l = links.get(peer.node);
        if (!l?.ready || l.pods.readyState !== "open") { connect(peer.node); return false; }
        flows.set(key(flowOf(packet), false), Date.now());
        l.pods.send(packet.slice());
        return true;
      },
      // A new reliable channel LABEL to the peer NODE, open, or null when there is no
      // direct link to it.
      async channel(node, label) {
        if (!available) return null;
        connect(node);
        const l = links.get(node);
        if (!l) return null;
        if (!l.ready) await Promise.race([new Promise((r) => l.waiters.push(r)), new Promise((r) => setTimeout(r, 5000))]);
        if (!l.ready) return null;
        const channel = l.pc.createDataChannel(label);
        channel.binaryType = "arraybuffer";
        const opened = await Promise.race([
          new Promise((r) => { channel.onopen = () => r(true); }),
          new Promise((r) => setTimeout(() => r(false), 10000)),
        ]);
        if (!opened) { channel.close(); return null; }
        return channel;
      },
    };
  })();

  function makeNic() {
    const mac = new Uint8Array(6);
    crypto.getRandomValues(mac);
    mac[0] = (mac[0] & 0xfe) | 0x02; // unicast, locally administered
    const nic = { mac, kernel: null };
    nics.set(macOf(mac, 0), nic);
    nic.device = {
      mac,
      attach: (kernel) => { nic.kernel = kernel; },
      send: (frame) => {
        frame = finishChecksum(new Uint8Array(frame));
        if (peering.send(frame)) return;
        if (socket.readyState === 1) socket.send(frame);
        deliver(frame, nic);
      },
      close: () => nics.delete(macOf(mac, 0)),
    };
    return nic;
  }
  let resolveNode, rejectNode, resolveClosed;
  let refusal = null;
  const node = new Promise((resolve, reject) => { resolveNode = resolve; rejectNode = reject; });
  const closed = new Promise((resolve) => (resolveClosed = resolve));

  const send = (message) => {
    if (socket.readyState === 1) socket.send(JSON.stringify(message));
  };

  const identity = loadIdentityKey();
  let epoch = null;
  socket.onopen = async () => {
    const pair = await identity;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    send({
      op: "hello",
      identity: { publicKey: toBase64(publicKey), tab: tabId() },
      capacity: capacity ?? {
        cpu: String(Math.max(1, Math.min(8, (globalThis.navigator?.hardwareConcurrency ?? 2) - 1))),
        memory: `${memoryMiB * 4}Mi`,
        pods: "4",
      },
      arch: "arm64",
      browser: describeBrowser(),
    });
  };
  socket.onclose = async () => {
    for (const uid of [...pods.keys()]) await deletePod(uid);
    rejectNode(new Error(refusal ?? "the cluster closed the connection"));
    resolveClosed();
  };
  socket.onmessage = async (event) => {
    if (typeof event.data !== "string") {
      deliver(new Uint8Array(event.data), null);
      return;
    }
    const message = JSON.parse(event.data);
    if (message.op === "info") {
      peering.update(message);
      onInfo(message);
      return;
    }
    if (message.op === "signal") {
      peering.signal(message.from, message.data);
      return;
    }
    if (message.op === "exec-input" || message.op === "exec-resize" || message.op === "exec-kill") {
      execControl(message);
      return;
    }
    if (message.op === "challenge") {
      const pair = await identity;
      const signature = new Uint8Array(await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, fromBase64(message.nonce)));
      send({ op: "proof", signature: toBase64(signature) });
      return;
    }
    if (message.op === "refused") {
      refusal = message.reason;
      return;
    }
    if (message.op === "welcome") {
      epoch = message.epoch ?? null;
      log(`joined as ${message.node}`);
      resolveNode(message.node);
      return;
    }
    if (typeof message.id !== "number") return;
    // A request from an earlier session of this node is stale: never act on it.
    if (message.epoch !== undefined && message.epoch !== epoch) return;
    try {
      send({ id: message.id, result: await handle(message) });
    } catch (error) {
      send({ id: message.id, error: String(error?.message ?? error) });
    }
  };

  async function handle(message) {
    switch (message.op) {
      case "ensure":
        return { status: podStatus(await ensurePod(message.pod)) };
      case "delete":
        await deletePod(message.uid);
        return {};
      case "logs": {
        const container = pods.get(message.uid)?.containers.get(message.container);
        if (!container) throw new Error(`no container ${message.container} in Pod ${message.uid}`);
        let text = container.log;
        if (typeof message.tail === "number") text = text.split("\n").slice(-message.tail - 1).join("\n");
        return { text };
      }
      case "exec": {
        const pod = pods.get(message.uid);
        if (!pod) throw new Error(`no Pod ${message.uid} here`);
        const root = pod.roots?.get(message.container);
        const [file, ...args] = root ? ["sh", "-c", CHROOT, "chroot", root, "/", ...message.command] : message.command;
        const result = await pod.vm.exec(file, args, { user: "root" });
        return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode ?? 1 };
      }
      case "stats":
        return await nodeStats();
      case "http":
        return await proxyHttp(message);
      case "exec-start":
        await startExec(message);
        return {};
      default:
        throw new Error(`unknown request ${message.op}`);
    }
  }

  // Start the Pod's instance and containers once; later ensures report on it.
  async function ensurePod(request) {
    let pod = pods.get(request.uid);
    if (pod) return pod;
    pod = { request, vm: null, containers: new Map(), starting: null };
    pods.set(request.uid, pod);
    pod.starting = (async () => {
      log(`starting ${request.namespace}/${request.name}`);
      const network = request.network;
      if (network) pod.nic = makeNic();
      pod.vm = await createKernel({ distro, memoryMiB, ...(network ? { net: pod.nic.device } : {}) });
      if (network) {
        // The Pod's own address in the node's Pod CIDR, as the server assigned it.
        const setup = await pod.vm.exec("sh", ["-c",
          `pkill udhcpc; ip link set eth0 up && ip addr flush dev eth0 && ` +
          `ip addr add ${network.address}/${network.prefix} dev eth0 && ip route add default via ${network.gateway}`],
          { user: "root" });
        if (setup.exitCode !== 0) throw new Error(`network setup failed: ${setup.stderr}`);
        log(`${request.name} is ${network.address}`);
      }
      for (const spec of request.spec.containers ?? []) await startContainer(pod, spec);
    })();
    try {
      await pod.starting;
    } catch (error) {
      pods.delete(request.uid);
      await pod.vm?.stop?.();
      throw error;
    }
    return pod;
  }

  // A container's root: its image, unpacked once and mounted in the Pod's guest.
  async function containerRoot(pod, spec) {
    const info = spec.imageInfo;
    if (!info || !MemoryFs) return null;
    const root = `/run/gr8s/${spec.name}`;
    const fs = new MemoryFs();
    const base = url.replace(/^ws/, "http");
    for (const layer of info.layers) {
      const bytes = await layerBytes(layer, base, log, swarm);
      await unpackLayer(fs, new Response(bytes), layer.mediaType ?? "");
    }
    for (const dir of ["/proc", "/dev", "/tmp", "/etc"]) fs.mkdirp(dir);
    // Cluster DNS and the Pod's own name, as the kubelet writes them.
    const network = pod.request.network;
    if (network?.dns) {
      fs.rm("/etc/resolv.conf", { force: true });
      fs.writeFile("/etc/resolv.conf",
        network.dns.nameservers.map((server) => `nameserver ${server}\n`).join("") +
        `search ${network.dns.searches.join(" ")}\noptions ${network.dns.options.join(" ")}\n`);
      fs.rm("/etc/hosts", { force: true });
      fs.writeFile("/etc/hosts", `127.0.0.1\tlocalhost\n${network.address}\t${pod.request.name}\n`);
    }
    await pod.vm.exec("mkdir", ["-p", root], { user: "root" });
    await pod.vm.mount(root, fs);
    log(`${pod.request.name}/${spec.name}: ${spec.image} unpacked (${info.layers.length} layers)`);
    return root;
  }

  // The program and environment Kubernetes runs: command and args over the image's
  // Entrypoint and Cmd, the spec's environment over the image's.
  function containerProgram(spec) {
    const config = spec.imageInfo?.config ?? {};
    const entrypoint = spec.command ?? config.Entrypoint ?? [];
    const args = spec.args ?? (spec.command ? [] : config.Cmd ?? []);
    const env = {};
    for (const pair of config.Env ?? []) {
      const at = pair.indexOf("=");
      if (at > 0) env[pair.slice(0, at)] = pair.slice(at + 1);
    }
    for (const e of spec.env ?? []) if (typeof e.value === "string") env[e.name] = e.value;
    return { argv: [...entrypoint, ...args], env, workingDir: spec.workingDir || config.WorkingDir || "/" };
  }

  // Run argv in ROOT, chrooted, with /proc and /dev there.
  const CHROOT = 'R=$1; W=$2; shift 2; mount -t proc proc "$R/proc" 2>/dev/null; mount --bind /dev "$R/dev" 2>/dev/null; ' +
    'cd "$R$W" 2>/dev/null || cd "$R"; exec chroot "$R" "$@"';

  async function startContainer(pod, spec) {
    if (!pod.roots) pod.roots = new Map();
    if (!pod.roots.has(spec.name)) pod.roots.set(spec.name, await containerRoot(pod, spec));
    const root = pod.roots.get(spec.name);
    const program = containerProgram(spec);
    const argv = program.argv;
    const env = program.env;
    const container = pods.get(pod.request.uid)?.containers.get(spec.name) ?? {
      spec,
      log: "",
      restartCount: -1,
      state: null,
      process: null,
    };
    pod.containers.set(spec.name, container);
    container.restartCount += 1;
    const [file, ...args] = argv.length ? argv : ["sh"];
    const process = root
      ? await pod.vm.spawn("sh", ["-c", CHROOT, "chroot", root, program.workingDir, file, ...args], { pty: false, user: "root", env, cwd: "/" })
      : await pod.vm.spawn(file, args, { pty: false, user: "root", env, cwd: spec.workingDir || "/" });
    container.process = process;
    container.state = { running: { startedAt: now() } };
    log(`${pod.request.name}/${spec.name} running (pid ${process.pid})`);
    const append = (chunk) => {
      container.log += decoder.decode(chunk, { stream: true });
      if (container.log.length > LOG_LIMIT) container.log = container.log.slice(-LOG_LIMIT);
    };
    const drain = (stream) => stream.pipeTo(new WritableStream({ write: append })).catch(() => {});
    Promise.all([drain(process.stdout), drain(process.stderr)]);
    report(pod);
    process.ended.then(async (end) => {
      if (pods.get(pod.request.uid) !== pod || container.process !== process) return;
      const exitCode = end.type === "exit" ? end.code : 128 + (end.signal ?? 9);
      container.state = {
        terminated: {
          exitCode,
          reason: exitCode === 0 ? "Completed" : "Error",
          startedAt: container.state.running?.startedAt,
          finishedAt: now(),
        },
      };
      log(`${pod.request.name}/${spec.name} exited ${exitCode}`);
      report(pod);
      const policy = pod.request.spec.restartPolicy ?? "Always";
      if (policy === "Always" || (policy === "OnFailure" && exitCode !== 0)) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        if (pods.get(pod.request.uid) === pod) await startContainer(pod, spec).catch(() => {});
      }
    });
  }

  // One HTTP request to a server in a Pod, for the server's Pod proxy. A refused
  // connection is retried briefly: a simple server may be between connections.
  async function proxyHttp(message) {
    const pod = pods.get(message.uid);
    if (!pod) throw new Error(`no Pod ${message.uid} here`);
    await pod.starting;
    const init = { method: message.method, headers: message.headers ?? {} };
    if (message.body) init.body = fromBase64(message.body);
    for (let attempt = 0; ; attempt++) {
      try {
        const response = await pod.vm.fetch(`http://localhost:${message.port}${message.path}`, init);
        const body = new Uint8Array(await response.arrayBuffer());
        return { status: response.status, headers: [...response.headers], body: toBase64(body) };
      } catch (error) {
        if (attempt >= 20 || !/ECONNREFUSED|closed before/.test(String(error?.message))) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
  }

  // What the server reports as this node's metrics: each Pod's VM and the tab.
  // Memory in use is the guest's own MemTotal - MemAvailable, sampled every 15s.
  async function nodeStats() {
    const result = { tab: { cores: globalThis.navigator?.hardwareConcurrency ?? null }, pods: {} };
    const heap = globalThis.performance?.memory?.usedJSHeapSize;
    if (typeof heap === "number") result.tab.jsHeapBytes = heap;
    for (const [uid, pod] of pods) {
      if (!pod.vm) continue;
      const stats = pod.vm.stats();
      if (!pod.memorySampledAt || Date.now() - pod.memorySampledAt > 15000) {
        pod.memorySampledAt = Date.now();
        try {
          const meminfo = (await pod.vm.exec("cat", ["/proc/meminfo"], { user: "root" })).stdout;
          const field = (name) => Number(new RegExp(`^${name}:\\s+(\\d+) kB`, "m").exec(meminfo)?.[1] ?? NaN) * 1024;
          pod.memoryUsed = field("MemTotal") - field("MemAvailable");
        } catch {
          pod.memoryUsed = undefined;
        }
      }
      result.pods[uid] = {
        uptimeSeconds: stats.uptimeMs / 1000,
        memoryLimitBytes: memoryMiB * 1048576,
        ...(Number.isFinite(pod.memoryUsed) ? { memoryUsedBytes: pod.memoryUsed } : {}),
      };
    }
    return result;
  }

  // An interactive exec (kubectl exec): the server relays its streams.
  async function startExec(message) {
    const pod = pods.get(message.uid);
    if (!pod) throw new Error(`no Pod ${message.uid} here`);
    await pod.starting;
    const root = pod.roots?.get(message.container);
    const [file, ...args] = root ? ["sh", "-c", CHROOT, "chroot", root, "/", ...message.command] : message.command;
    const id = message.exec;
    const output = (channel) => new WritableStream({
      write: (chunk) => send({ op: "exec-output", exec: id, channel, data: toBase64(chunk) }),
    });
    let process;
    if (message.tty) {
      process = await pod.vm.spawn(file, args, { user: "root", cols: 80, rows: 24 });
      process.output.pipeTo(output(1)).catch(() => {});
    } else {
      process = await pod.vm.spawn(file, args, { pty: false, user: "root" });
      process.stdout.pipeTo(output(1)).catch(() => {});
      process.stderr.pipeTo(output(2)).catch(() => {});
      if (!message.stdin) process.stdin.close().catch(() => {});
    }
    const writer = message.tty ? null : process.stdin.getWriter();
    execs.set(id, { process, writer, tty: message.tty });
    process.ended.then((end) => {
      execs.delete(id);
      send({ op: "exec-exit", exec: id, exitCode: end.type === "exit" ? end.code : 128 + (end.signal ?? 9) });
    });
  }

  function execControl(message) {
    const exec = execs.get(message.exec);
    if (!exec) return;
    if (message.op === "exec-kill") {
      exec.process.kill("SIGKILL");
    } else if (message.op === "exec-resize") {
      if (exec.tty) exec.process.resize(message.cols, message.rows);
    } else if (message.data) {
      const bytes = fromBase64(message.data);
      if (exec.tty) exec.process.write(bytes);
      else exec.writer.write(bytes).catch(() => {});
    } else if (message.eof && exec.writer) {
      exec.writer.close().catch(() => {});
    }
  }

  async function deletePod(uid) {
    const pod = pods.get(uid);
    if (!pod) return;
    pods.delete(uid);
    await pod.starting?.catch(() => {});
    for (const container of pod.containers.values()) container.process?.kill("SIGKILL");
    await pod.vm?.stop?.();
    pod.nic?.device.close();
    log(`stopped ${pod.request.namespace}/${pod.request.name}`);
  }

  function podStatus(pod) {
    const statuses = [...pod.containers.entries()].map(([name, c]) => ({
      name,
      image: c.spec.image ?? "",
      imageID: "",
      containerID: `browser://${pod.request.uid}/${name}`,
      restartCount: Math.max(0, c.restartCount),
      ready: Boolean(c.state?.running),
      started: Boolean(c.state?.running),
      state: c.state ?? { waiting: { reason: "ContainerCreating" } },
    }));
    const terminated = statuses.filter((s) => s.state.terminated);
    const policy = pod.request.spec.restartPolicy ?? "Always";
    let phase = "Running";
    if (statuses.length === 0) phase = "Pending";
    else if (policy !== "Always" && terminated.length === statuses.length)
      phase = terminated.every((s) => s.state.terminated.exitCode === 0) ? "Succeeded" : "Failed";
    return { phase, containerStatuses: statuses };
  }

  function report(pod) {
    send({ op: "status", uid: pod.request.uid, status: podStatus(pod) });
  }

  return {
    node,
    closed,
    close: () => socket.close(),
  };
}
