// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0
//
// A browser node without a browser (podster-57fv): the page's own module, run
// under Node with unkernel's Node entry. For trying browser nodes from a
// terminal and for tests/browser-node/e2e.sh.
//
//   cd tests/browser-node && npm install && node client.mjs ws://127.0.0.1:8099/socket

import { createKernel, fetchDistro } from "unkernel";
import { joinCluster } from "../../src/server/browser-node-runtime.mjs";

const url = process.argv[2] ?? "ws://127.0.0.1:8099/socket";
const distro = process.env.GR8S_BROWSER_DISTRO || (await fetchDistro("alpine"));
let last = null;
const node = joinCluster({
  url,
  createKernel,
  distro,
  log: (line) => console.log(`${new Date().toISOString()} ${line}`),
  onInfo: (info) => {
    const pods = info.pods.map((p) => `${p.name}:${p.phase}`).join(" ");
    if (pods !== last) console.log(`${new Date().toISOString()} server says: node ready=${info.node.ready} pods ${pods || "none"}`);
    last = pods;
  },
});
console.log(`node ${await node.node}`);
process.on("SIGINT", () => node.close());
process.on("SIGTERM", () => node.close());
await node.closed;
console.log("disconnected");
process.exit(0);
