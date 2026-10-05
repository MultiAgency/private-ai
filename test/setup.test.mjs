import assert from "node:assert/strict";
import test from "node:test";

import { modelProblem } from "../review/setup.mjs";

test("a model that fails says how to fix it", () => {
  assert.match(modelProblem("m/x", new Error("NEAR AI GET /attestation/report: 401 Invalid or expired API key")), /Check the `NEARAI_API_KEY` secret/);
  assert.match(modelProblem("Qwen/Q", new Error("model: TCB status OutOfDate not accepted (INTEL-SA-1)")), /allow-unpatched-model: "true"/);
  assert.match(modelProblem("moonshotai/k", new Error("503 Provider error: No provider found that supports attestation reports")), /can't attest `moonshotai\/k`.*npm run models/);
  assert.match(modelProblem("m/x", new Error("model: report data does not bind the signer and nonce")), /didn't pass its attestation \(model: report data/);
});
