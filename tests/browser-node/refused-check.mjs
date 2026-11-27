// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0
//
// What a tab learns when the server won't take it: the page tries again by itself only
// when the server says to (it is busy), not when it is full.
//   node refused-check.mjs ws://127.0.0.1:PORT/socket
import { joinCluster } from "../../src/server/browser-node-runtime.mjs";

const node = joinCluster({ url: process.argv[2], createKernel: async () => { throw new Error("no kernel"); }, MemoryFs: class {} });
try {
  console.log(JSON.stringify({ joined: await node.node }));
} catch (error) {
  console.log(JSON.stringify({ message: error.message, refused: error.refused, retry: error.retry }));
}
process.exit(0);
