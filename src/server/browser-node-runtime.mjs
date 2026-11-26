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
export function joinCluster({ url, createKernel, distro, memoryMiB = 256, capacity, log = () => {}, onInfo = () => {} }) {
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
        if (socket.readyState === 1) socket.send(frame);
        deliver(frame, nic);
      },
      close: () => nics.delete(macOf(mac, 0)),
    };
    return nic;
  }
  let resolveNode, resolveClosed;
  const node = new Promise((resolve) => (resolveNode = resolve));
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
    });
  };
  socket.onclose = async () => {
    for (const uid of [...pods.keys()]) await deletePod(uid);
    resolveClosed();
  };
  socket.onmessage = async (event) => {
    if (typeof event.data !== "string") {
      deliver(new Uint8Array(event.data), null);
      return;
    }
    const message = JSON.parse(event.data);
    if (message.op === "info") {
      onInfo(message);
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
        const [file, ...args] = message.command;
        const result = await pod.vm.exec(file, args, { user: "root" });
        return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode ?? 1 };
      }
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

  async function startContainer(pod, spec) {
    const argv = [...(spec.command ?? []), ...(spec.args ?? [])];
    const env = Object.fromEntries((spec.env ?? []).filter((e) => typeof e.value === "string").map((e) => [e.name, e.value]));
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
    const process = await pod.vm.spawn(file, args, { pty: false, user: "root", env, cwd: spec.workingDir || "/" });
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

  // An interactive exec (kubectl exec): the server relays its streams.
  async function startExec(message) {
    const pod = pods.get(message.uid);
    if (!pod) throw new Error(`no Pod ${message.uid} here`);
    await pod.starting;
    const [file, ...args] = message.command;
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
