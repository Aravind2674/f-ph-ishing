/** The extension's "Open in ThreatFusion" link pre-fills the scan form; nothing in it can start a scan. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { parsePrefill } from "./prefill.ts";

test("a target and type in the query pre-fill the form", () => {
  assert.deepEqual(parsePrefill("?target=login.example.com&type=domain"), { target: "login.example.com", type: "domain" });
  assert.deepEqual(parsePrefill("?target=https%3A%2F%2Fa.example%2Fx%3Fq%3D1&type=url"), { target: "https://a.example/x?q=1", type: "url" });
});

test("the type defaults to domain", () => {
  assert.deepEqual(parsePrefill("?target=example.com"), { target: "example.com", type: "domain" });
});

test("a missing, blank, oversized or unknown-type target is ignored", () => {
  assert.equal(parsePrefill(""), null);
  assert.equal(parsePrefill("?type=domain"), null);
  assert.equal(parsePrefill("?target=%20%20"), null);
  assert.equal(parsePrefill("?target=example.com&type=file"), null);
  assert.equal(parsePrefill(`?target=${"a".repeat(2049)}`), null);
});
