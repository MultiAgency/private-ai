// OutLayer step attestations, checked offline with what record-outlayer.mjs
// kept: a real public record (another project's call), the Intel collateral for
// its quote, and the worker builds approved on chain when it ran.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { verify } from "@phala/dcap-qvl";

import { canonical, taskHash, verifyStep } from "../core/outlayer.mjs";

const { now, record, collateral, approved } = JSON.parse(readFileSync(new URL("fixtures/outlayer-step.json", import.meta.url)));
const verifyQuote = async quote => verify(quote, collateral, now);
const expect = { project: record.project_id, caller: record.caller_account_id, wasmHashes: [record.wasm_hash], approved, verifyQuote };

test("a real step verifies: Intel quote, the record it binds, an approved worker build", async () => {
  const step = await verifyStep(record, expect);
  assert.equal(step.tcb, "UpToDate");
  assert.equal(step.wasmHash, record.wasm_hash);
});

test("any edit to the record breaks the binding", async () => {
  for (const field of ["output_hash", "input_hash", "wasm_hash", "project_id", "caller_account_id"]) {
    const edited = { ...record, [field]: field.endsWith("hash") ? "0".repeat(64) : "someone-else.near" };
    await assert.rejects(verifyStep(edited, { ...expect, project: undefined, caller: undefined, wasmHashes: undefined }), /does not bind this record/, field);
  }
  assert.equal(Buffer.from(taskHash(record)).length, 32);
});

test("the step must be a worker build approved at the time, for our project, caller and WASM", async () => {
  const rtmr3 = r => ({ ...r, rtmr3: "00".repeat(48) });
  await assert.rejects(verifyStep(record, { ...expect, approved: approved.map(rtmr3) }), /not a worker build OutLayer approved/);
  await assert.rejects(verifyStep(record, { ...expect, project: "hack.near/private-investigator" }), /ran for project/);
  await assert.rejects(verifyStep(record, { ...expect, caller: "relay.near" }), /called by/);
  await assert.rejects(verifyStep(record, { ...expect, wasmHashes: ["ab".repeat(32)] }), /not a published build/);
  await assert.rejects(verifyStep(record, { ...expect, output: { job: "x", more: false } }), /output does not match/);
});

test("the reader must be fully patched unless the policy allows a pending update", async () => {
  const stale = async quote => Object.assign(await verifyQuote(quote), { status: "OutOfDate" });
  await assert.rejects(verifyStep(record, { ...expect, verifyQuote: stale }), /TCB status OutOfDate/);
  assert.equal((await verifyStep(record, { ...expect, verifyQuote: stale, allowUnpatched: true })).tcb, "OutOfDate");
});

test("outputs are hashed as the worker hashes them: compact, keys sorted", () => {
  assert.equal(canonical({ more: true, job: "a1", turns: ["x"] }), '{"job":"a1","more":true,"turns":["x"]}');
  assert.equal(canonical({ b: { d: 1, c: null } }), '{"b":{"c":null,"d":1}}');
});

test("the task hash matches OutLayer's own verifier on its fixtures: V1, legacy and on-chain records", () => {
  for (const name of ["mainnet-205123-v1.json", "mainnet-500-legacy.json", "testnet-2008-chain.json"]) {
    const r = JSON.parse(readFileSync(new URL(`fixtures/outlayer-verify/${name}`, import.meta.url)));
    const signed = Buffer.from(r.tdx_quote, "base64").subarray(568, 600).toString("hex");
    assert.equal(Buffer.from(taskHash(r)).toString("hex"), signed, name);
  }
});

test("a record older than the V1 format cannot back a receipt", async () => {
  await assert.rejects(verifyStep({ ...record, timestamp: 1_700_000_000 }, expect), /older record/);
});
