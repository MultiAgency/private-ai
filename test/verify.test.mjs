// The receipt checker's command line (core/verify.mjs): what it says and
// returns when it is misused or handed a receipt that cannot pass. Every case
// here is refused before any attestation evidence is fetched, so none needs
// the network.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { receiptText } from "./evidence.mjs";

const script = fileURLToPath(new URL("../core/verify.mjs", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "verify-"));
test.after(() => rmSync(dir, { recursive: true, force: true }));

const verify = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
function receiptFile(name, content) {
  const path = join(dir, name);
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
  return path;
}

test("no receipt path prints the usage and exits 2", () => {
  const { status, stderr, stdout } = verify();
  assert.equal(status, 2);
  assert.match(stderr, /^Usage: node core\/verify\.mjs receipt\.json/);
  assert.equal(stdout, "");
});

test("a missing file is not verified", () => {
  const { status, stderr, stdout } = verify(join(dir, "nothing.json"));
  assert.equal(status, 1);
  assert.match(stderr, /^not verified: /);
  assert.ok(!stdout.includes("verified\n"), "never claims success");
});

test("text that is not JSON is not verified", () => {
  const { status, stderr } = verify(receiptFile("garbage.json", "this is not a receipt"));
  assert.equal(status, 1);
  assert.match(stderr, /^not verified: /);
});

test("a receipt of an unknown version is not verified", () => {
  const { status, stderr } = verify(receiptFile("future.json", { ...JSON.parse(receiptText), version: 99 }));
  assert.equal(status, 1);
  assert.match(stderr, /not verified: unknown receipt version 99/);
});

test("a receipt without NVIDIA's verdict is not verified", () => {
  const { gpu_token, ...rest } = JSON.parse(receiptText);
  assert.ok(gpu_token);
  const { status, stderr, stdout } = verify(receiptFile("no-verdict.json", rest));
  assert.equal(status, 1);
  assert.match(stderr, /not verified: no NVIDIA verdict recorded/);
  assert.equal(stdout, "", "prints nothing about a receipt it refused");
});
