// The tab's backoff for direct links (podster-99q4) on a clock the script moves: it
// prints, at each step, whether the tab would try a direct link to peer "b".
//   node backoff-check.mjs
import { linkBackoff } from "../../src/server/browser-node-runtime.mjs";

let clock = 0;
const backoff = linkBackoff({ first: 10, most: 40, now: () => clock });
const steps = [];
const step = (label, act = () => {}) => { act(); steps.push([label, backoff.allows("b")]); };
step("fresh");
step("failed once", () => backoff.failed("b"));
step("9 later", () => { clock += 9; });
step("10 later", () => { clock += 1; });
step("failed twice", () => backoff.failed("b"));
step("19 later", () => { clock += 19; });
step("20 later", () => { clock += 1; });
step("failed thrice", () => backoff.failed("b"));
step("failed four times", () => { clock += 40; backoff.failed("b"); });
step("failed five times", () => { clock += 40; backoff.failed("b"); });
step("39 later", () => { clock += 39; });
step("40 later", () => { clock += 1; });
step("failed after a cap", () => backoff.failed("b"));
step("linked", () => backoff.succeeded("b"));
step("failed after linking", () => backoff.failed("b"));
step("10 later", () => { clock += 10; });
step("failed again", () => backoff.failed("b"));
step("left", () => backoff.retain(["c"]));
step("failed after rejoining", () => backoff.failed("b"));
step("10 later", () => { clock += 10; });
console.log(JSON.stringify({ steps, other: backoff.allows("c") }));
