// The page's sample receipt, checked offline with the evidence recorded for it
// (see evidence.mjs): the same verifyReceipt the CLI and the page run.
import assert from "node:assert/strict";
import test from "node:test";

import { verifyReceipt } from "../core/receipt.mjs";
import { nvidiaKeys, receiptText as text, verifyQuote } from "./evidence.mjs";

const options = { verifyQuote, getNvidiaKeys: async () => nvidiaKeys, getNvidiaToken: () => assert.fail("asked NVIDIA again") };

test("the sample receipt verifies", async () => {
  const { receipt, model, gateway } = await verifyReceipt(text, options);
  assert.equal(receipt.subject.pull_request, "MultiAgency/near-agencies#78");
  assert.equal(model.tcb, "UpToDate");
  assert.equal(gateway.tcb, "OutOfDate");
  assert.ok(receipt.turns.length > 0);
});

test("an edited turn, signer or verdict fails", async () => {
  const edit = change => {
    const receipt = JSON.parse(text);
    change(receipt);
    return verifyReceipt(JSON.stringify(receipt), options);
  };
  await assert.rejects(edit(r => { r.turns[3].request_sha256 = "0".repeat(64); }), /exact request and response/);
  await assert.rejects(edit(r => { r.turns[0] = { ...r.turns[0], signature: { ...r.turns[0].signature, signing_address: "11".repeat(32) } }; }), /other than the attested/);
  await assert.rejects(edit(r => { r.turns.push(r.turns[0]); }), /listed twice/);
  await assert.rejects(edit(r => { r.gpu_token = r.gpu_token.replace(/\.[^.]+$/, ".AAAA"); }), /NVIDIA/);
  await assert.rejects(edit(r => { r.nonce = "00".repeat(32); }), /report data does not bind/);
  await assert.rejects(edit(r => { r.turns = []; }), /no signed turns/);
});

test("a receipt is checked under the policy it states", async () => {
  const stale = async quote => Object.assign(await verifyQuote(quote), { status: "OutOfDate" });
  const withPolicy = allow => JSON.stringify({ ...JSON.parse(text), policy: { allow_unpatched_model: allow } });
  await assert.rejects(verifyReceipt(withPolicy(false), { ...options, verifyQuote: stale }), /model: TCB status OutOfDate not accepted/);
  const { model } = await verifyReceipt(withPolicy(true), { ...options, verifyQuote: stale });
  assert.equal(model.tcb, "OutOfDate");
});

// Version 2, as the hosted App writes it: the sample's real model evidence and
// turns, run by a job whose OutLayer attestations are stubbed to what the
// checker needs from them (outlayer.test.mjs checks real ones).
import { canonical } from "../core/outlayer.mjs";
import { sha256 } from "../core/sign.mjs";
import { subjectCommitment, turnHash } from "../core/receipt.mjs";

test("hashes match the App's (app/tests/core.rs pins the same values)", () => {
  assert.equal(turnHash(JSON.parse(text).turns[0]), "3ee9d41764acc01a67aee289edc62ecd43f16231ca972123f473b6c3eeaeebc9");
  const subject = { pull_request: "owner/secret-repo#7", base_sha: "a".repeat(40), head_sha: "b".repeat(40) };
  assert.equal(subjectCommitment("00112233445566778899aabbccddeeff", subject), "1713fd61b577b8dbe92fc4de33840d7f7d1c494908b33737395fc21ec322dc28");
});

// As app/builds.json records a release.
const published = [{ hash: "5e".repeat(32), commit: "c0ffee".padEnd(40, "0"), clean: true, project: "hack.near/private-investigator" }];

function v2(change = () => {}, wasm = "5e".repeat(32)) {
  const v1 = JSON.parse(text);
  const salt = "ab".repeat(16);
  const subject = { pull_request: v1.subject.pull_request, base_sha: v1.subject.base_sha, head_sha: v1.subject.head_sha };
  const hashes = v1.turns.map(turnHash);
  const half = Math.ceil(hashes.length / 2);
  const job = "f00d".repeat(8);
  const { subject: _, ...rest } = v1;
  const receipt = {
    ...rest,
    version: 2,
    subject_sha256: subjectCommitment(salt, subject),
    outlayer: {
      project: "hack.near/private-investigator",
      findings: 1,
      runs: [
        { call_id: "c1", output: { job, more: true } },
        { call_id: "c2", output: { job, more: true, nonce: v1.nonce } },
        { call_id: "c3", output: { job, more: true, turns: hashes.slice(0, half) } },
        { call_id: "c4" },
      ],
    },
  };
  change(receipt);
  const body = JSON.stringify(receipt, null, 2);
  const lastOutput = { findings: 1, job, more: false, receipt_sha256: sha256(body), subject_sha256: receipt.subject_sha256, turns: hashes.slice(half) };
  const outputs = [...receipt.outlayer.runs.slice(0, -1).map(r => r.output), lastOutput];
  // Stub attestations: each binds its run's output, as OutLayer's does.
  const records = Object.fromEntries(receipt.outlayer.runs.map((r, i) => [r.call_id, { project_id: receipt.outlayer.project, output_hash: sha256(canonical(outputs[i])), wasm_hash: wasm, timestamp: 1_791_000_000 }]));
  // As verifyStep checks the attested record (outlayer.test.mjs checks the real one).
  const checkStep = async (record, { project, wasmHashes, output }) => {
    if (record.project_id !== project) throw new Error("wrong project");
    if (!wasmHashes.includes(record.wasm_hash)) throw new Error(`ran WASM ${record.wasm_hash}, not a published build`);
    if (sha256(canonical(output)) !== record.output_hash) throw new Error("output does not match the attested hash");
    return { wasmHash: record.wasm_hash };
  };
  return { body, salt, subject, opts: { ...options, published, getRecord: async id => records[id], approvedFor: async () => [], checkStep } };
}

test("a version 2 receipt verifies: model evidence, every run, and the commitment the review's salt opens", async () => {
  const { body, salt, subject, opts } = v2();
  const { runs, subjectConfirmed, model } = await verifyReceipt(body, { ...opts, salt, subject });
  assert.equal(model.tcb, "UpToDate");
  assert.equal(runs.steps.length, 4);
  assert.deepEqual(runs.builds, published);
  assert.equal(subjectConfirmed, true);
  await assert.rejects(verifyReceipt(body, { ...opts, salt: "00".repeat(16), subject }), /not for this pull request/);
  await assert.rejects(verifyReceipt(body, { ...opts, expectSha256: "0".repeat(64) }), /not the one the review cites/);
});

test("a version 2 receipt fails when its runs do not prove its parts", async () => {
  const swapTurns = r => { r.outlayer.runs[2].output.turns = [...r.outlayer.runs[2].output.turns.slice(1), "0".repeat(64)]; };
  const loseNonce = r => { delete r.outlayer.runs[1].output.nonce; };
  const twoJobs = r => { r.outlayer.runs[1].output.job = "other"; };
  const noRuns = r => { r.outlayer.runs = []; };
  for (const [change, message] of [[swapTurns, /turns do not match/], [loseNonce, /nonce/], [twoJobs, /not one job/], [noRuns, /no OutLayer runs/]]) {
    const { body, opts } = v2(change);
    await assert.rejects(verifyReceipt(body, opts), message);
  }
  // An edit after the fact changes the receipt's hash, which the last run attested.
  const { body, opts } = v2();
  const edited = JSON.stringify({ ...JSON.parse(body), outlayer: { ...JSON.parse(body).outlayer, findings: 0 } }, null, 2);
  await assert.rejects(verifyReceipt(edited, opts), /output does not match/);
});

test("a version 2 receipt counts only as the published project's published builds", async () => {
  // Another project, running its own code, can attest whatever outputs it likes.
  const elsewhere = v2(r => { r.outlayer.project = "attacker.near/fake-investigator"; });
  await assert.rejects(verifyReceipt(elsewhere.body, elsewhere.opts), /not one whose builds are published/);
  // Our project, running a build no release recorded.
  const unpublished = v2(() => {}, "de".repeat(32));
  await assert.rejects(verifyReceipt(unpublished.body, unpublished.opts), /not a published build/);
  // A checker with nothing to check against refuses rather than trusting the receipt.
  const { body, opts } = v2();
  await assert.rejects(verifyReceipt(body, { ...opts, published: undefined }), /no published builds/);
});

test("the Reader claim names the build and the commit it rebuilds from", async () => {
  const { provenClaims } = await import("../core/receipt.mjs");
  const { body, opts } = v2();
  const { receipt, model, gateway, runs } = await verifyReceipt(body, opts);
  const reader = provenClaims({ model: receipt.model, attestation: { model, gateway }, turns: receipt.turns.length, runs }).find(([claim]) => claim === "Reader")[1];
  assert.match(reader, new RegExp(`build \`${"5e".repeat(32)}\`, built from commit \`c0ffee0{34}\``));
});
