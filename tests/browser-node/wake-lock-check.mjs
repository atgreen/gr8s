// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0
//
// The join page's screen wake lock (podster-2yfv), against a stand-in for the browser's
// API: taken once joined, let go by the browser when the page is hidden, taken again
// when it is shown, released on leaving, and nothing at all where the API is missing.
//   node wake-lock-check.mjs
import { screenWakeLock } from "../../src/server/browser-node-runtime.mjs";

const document = new EventTarget();
document.visibilityState = "visible";
let requests = 0;
let active = null;
const wakeLock = {
  async request(type) {
    if (type !== "screen") throw new Error(`asked for ${type}`);
    requests += 1;
    const sentinel = new EventTarget();
    sentinel.released = false;
    sentinel.release = async () => {
      if (sentinel.released) return;
      sentinel.released = true;
      if (active === sentinel) active = null;
      sentinel.dispatchEvent(new Event("release"));
    };
    active = sentinel;
    return sentinel;
  },
};
const steps = [];
const states = [];
const lock = screenWakeLock({ wakeLock, document, onChange: (state) => states.push(state) });
const step = (label) => steps.push([label, lock.state, requests, active !== null]);
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

step("made");
await lock.hold();
step("joined");
// The browser lets go of it when the page is hidden.
document.visibilityState = "hidden";
await active.release();
document.dispatchEvent(new Event("visibilitychange"));
await settle();
step("hidden");
document.visibilityState = "visible";
document.dispatchEvent(new Event("visibilitychange"));
await settle();
step("shown");
await lock.release();
step("left");
document.dispatchEvent(new Event("visibilitychange"));
await settle();
step("shown after leaving");

const unsupported = [];
const none = screenWakeLock({ wakeLock: undefined, document, onChange: (state) => unsupported.push(state) });
await none.hold();
await none.release();

const refusedStates = [];
const refused = screenWakeLock({ wakeLock: { request: async () => { throw new Error("NotAllowedError"); } }, document,
                                 onChange: (state) => refusedStates.push(state) });
await refused.hold();

console.log(JSON.stringify({ steps, states, unsupported, refused: refusedStates }));
