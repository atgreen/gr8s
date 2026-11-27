// k9s in the visitor's tab: the unmodified linux/arm64 k9s release, in a Linux VM
// (unkernel) on this page. k9s talks plain HTTP to "kube" (192.0.2.10); each of the
// guest's TCP connections to it is a WebSocket to /k9s/tunnel, where the relay passes
// reads to the API server with its own read-only credential. Nothing else is reachable.

import { checkSupport, createKernel } from "./unkernel/web.mjs";

const KUBE = "192.0.2.10";

// The guest's TCP and DNS (unkernel's NetBackend): "kube" resolves, port 80 on it
// connects through a tunnel, and everything else is refused.
function tunnelBackend(url) {
  return {
    async lookup(name) {
      if (name === "kube") return [KUBE];
      throw Object.assign(new Error(`${name} not found`), { code: "ENOTFOUND" });
    },
    connect({ host, port }, ev) {
      if (host !== KUBE || port !== 80) {
        queueMicrotask(() => ev.onClose(new Error("refused")));
        return { write() {}, end() {}, destroy() {}, pause() {}, resume() {}, buffered: 0 };
      }
      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      let pending = [], held = [], paused = false, done = false, draining = null;
      const finish = (err) => {
        if (done) return;
        done = true;
        clearInterval(draining);
        if (!err) ev.onEnd();
        ev.onClose(err);
      };
      const drainLater = () => {
        if (draining || ws.bufferedAmount === 0) return;
        draining = setInterval(() => {
          if (ws.bufferedAmount > 0) return;
          clearInterval(draining);
          draining = null;
          ev.onDrain();
        }, 20);
      };
      ws.onopen = () => {
        for (const d of pending) ws.send(d);
        pending = [];
        ev.onConnect();
        drainLater();
      };
      ws.onmessage = (m) => {
        const d = new Uint8Array(m.data);
        if (paused) held.push(d);
        else ev.onData(d);
      };
      ws.onclose = (e) => finish(e.code === 1000 || e.code === 1005 ? null : new Error(`tunnel closed (${e.code})`));
      return {
        write(d) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(d);
            drainLater();
          } else if (ws.readyState === WebSocket.CONNECTING) pending.push(d.slice());
        },
        end() { ws.close(1000); },
        destroy() { done = true; clearInterval(draining); ws.close(1000); },
        pause() { paused = true; },
        resume() {
          paused = false;
          const h = held;
          held = [];
          for (const d of h) ev.onData(d);
        },
        get buffered() { return ws.bufferedAmount + pending.reduce((n, d) => n + d.length, 0); },
      };
    },
  };
}

// The kernel, downloaded whole and then compiled: compiling as it streams pauses the
// download, and a pause the server times out can end it early yet cleanly. A copy that
// does not compile is fetched once more past the browser's cache.
async function loadKernel(url) {
  for (const cache of ["default", "reload"]) {
    const response = await fetch(url, { cache });
    if (!response.ok) throw new Error(`Downloading the kernel failed: HTTP ${response.status}`);
    try {
      return await WebAssembly.compile(await response.arrayBuffer());
    } catch (e) {
      if (cache === "reload") throw new Error(`The kernel did not compile: ${e.message}`);
    }
  }
}

// Boots the VM and runs k9s in TERM (an xterm.js Terminal, already open and fitted).
// status(text) reports progress. Resolves with { restart, stop } once k9s runs.
export async function runK9s(term, status) {
  const support = await checkSupport();
  if (!support.ok) throw new Error(`This browser can't run the VM: ${support.problems.join("; ")}`);
  const base = new URL(".", import.meta.url);
  const tunnel = new URL("tunnel", base);
  tunnel.protocol = location.protocol === "https:" ? "wss:" : "ws:";
  status("Downloading Linux…");
  const kernel = await loadKernel(new URL("unkernel/unkernel.wasm", base).href);
  status("Starting Linux…");
  const vm = await createKernel({
    kernel,
    distro: new URL("k9s.erofs", base).href,
    memoryMiB: 384,
    net: tunnelBackend(tunnel.href),
  });
  vm.onOutput(() => {}); // the console is the kernel's; k9s gets its own pty
  let pty = null;
  const typing = term.onData((d) => pty?.write(d));
  const sizing = term.onResize(({ cols, rows }) => pty?.resize?.(cols, rows));
  async function start() {
    status("Starting k9s…");
    pty = await vm.spawn("/usr/local/bin/k9s", ["--readonly", "-c", "pods"], {
      user: "root",
      cols: term.cols,
      rows: term.rows,
      env: { KUBECONFIG: "/etc/k9s/kubeconfig", K9S_CONFIG_DIR: "/etc/k9s", XDG_STATE_HOME: "/tmp", XDG_CACHE_HOME: "/tmp" },
    });
    status("");
    const p = pty;
    p.output.pipeTo(new WritableStream({ write: (b) => term.write(b) })).catch(() => {});
    return p.ended.catch(() => null);
  }
  return {
    start,
    stop() {
      typing.dispose();
      sizing.dispose();
      try { vm.write("poweroff\n"); } catch {}
      setTimeout(() => vm.stop?.(), 2000);
    },
  };
}
