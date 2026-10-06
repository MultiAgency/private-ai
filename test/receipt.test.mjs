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

// Version 2, as the hosted App writes it: the receipts app/tests/job.rs makes
// by running the job on the sample's real model evidence and signed turns
// (fixtures/receipt-v2-cases.json). The writer and this checker meet there;
// OutLayer's attestations are stubbed to what the checker reads from them
// (outlayer.test.mjs checks real ones).
import { readFileSync } from "node:fs";

import { canonical } from "../core/outlayer.mjs";
import { provenClaims, subjectCommitment, turnHash } from "../core/receipt.mjs";
import { sha256 } from "../core/sign.mjs";

const { cases } = JSON.parse(readFileSync(new URL("fixtures/receipt-v2-cases.json", import.meta.url), "utf8"));
const PROJECT = "hack.near/private-investigator";
const BUILD = "5e".repeat(32);
// As app/builds.json records a release.
const published = [{ hash: BUILD, commit: "c0ffee".padEnd(40, "0"), clean: true, project: PROJECT }];

test("hashes match the App's (app/tests/core.rs pins the same values)", () => {
  assert.equal(turnHash(JSON.parse(text).turns[0]), "3ee9d41764acc01a67aee289edc62ecd43f16231ca972123f473b6c3eeaeebc9");
  const subject = { pull_request: "owner/secret-repo#7", base_sha: "a".repeat(40), head_sha: "b".repeat(40) };
  assert.equal(subjectCommitment("00112233445566778899aabbccddeeff", subject), "1713fd61b577b8dbe92fc4de33840d7f7d1c494908b33737395fc21ec322dc28");
});

/** A case's receipt, optionally edited, with the checker's options: each call's attestation as OutLayer would record it, for the build given. */
function hosted(c, { edit, build = BUILD } = {}) {
  const receipt = JSON.parse(c.receipt);
  edit?.(receipt);
  const body = edit ? JSON.stringify(receipt, null, 2) : c.receipt;
  const records = Object.fromEntries(Object.entries(c.outputs).map(([call, output]) => [call, { project_id: PROJECT, wasm_hash: build, output_hash: sha256(canonical(output)), timestamp: 1_791_000_000 }]));
  // As verifyStep checks the attested record.
  const checkStep = async (record, { project, wasmHashes, output }) => {
    if (record.project_id !== project) throw new Error(`ran for project ${record.project_id}, not ${project}`);
    if (!wasmHashes.includes(record.wasm_hash)) throw new Error(`ran WASM ${record.wasm_hash}, not a published build`);
    if (sha256(canonical(output)) !== record.output_hash) throw new Error("output does not match the attested hash");
    return { wasmHash: record.wasm_hash };
  };
  return { body, opts: { ...options, published, getRecord: async id => records[id], approvedFor: async () => [], checkStep } };
}

for (const c of cases) {
  test(`the App's receipt verifies (${c.name}): model evidence, every run, and the commitment the review's salt opens`, async () => {
    const { body, opts } = hosted(c);
    const { runs, subjectConfirmed, model, receipt } = await verifyReceipt(body, { ...opts, salt: c.salt, subject: c.subject, expectSha256: c.sha256 });
    assert.equal(model.tcb, "UpToDate");
    assert.equal(runs.steps.length, Object.keys(c.outputs).length);
    assert.deepEqual(runs.builds, published);
    assert.equal(subjectConfirmed, true);
    assert.doesNotMatch(c.receipt, /secret-repo/, "the public receipt does not name the repository");
    await assert.rejects(verifyReceipt(body, { ...opts, salt: "00".repeat(16), subject: c.subject }), /not for this pull request/);
    await assert.rejects(verifyReceipt(body, { ...opts, expectSha256: "0".repeat(64) }), /not the one the review cites/);
    const reader = provenClaims({ model: receipt.model, attestation: { model, gateway: model }, turns: receipt.turns.length, runs }).find(([claim]) => claim === "Reader")[1];
    assert.match(reader, new RegExp(`build \`${BUILD}\`, built from commit \`c0ffee0{34}\``));
  });
}

test("the App's receipt fails when its runs do not prove its parts", async () => {
  const [c] = cases;
  const withTurns = r => r.outlayer.runs.find(run => run.output?.turns?.length);
  const edits = [
    [r => { withTurns(r).output.turns[0] = "0".repeat(64); }, /turns do not match/],
    [r => { delete r.outlayer.runs.find(run => run.output?.nonce).output.nonce; }, /nonce/],
    [r => { r.outlayer.runs[1].output.job = "other"; }, /not one job/],
    [r => { r.outlayer.runs = []; }, /no OutLayer runs/],
    // An edit after the fact changes the receipt's hash, which the last run attested.
    [r => { r.outlayer.findings = 0; }, /output does not match/],
  ];
  for (const [edit, message] of edits) {
    const { body, opts } = hosted(c, { edit });
    await assert.rejects(verifyReceipt(body, opts), message);
  }
});

test("the App's receipt counts only as the published project's published builds", async () => {
  const [c] = cases;
  // Another project, running its own code, can attest whatever outputs it likes.
  const elsewhere = hosted(c, { edit: r => { r.outlayer.project = "attacker.near/fake-investigator"; } });
  await assert.rejects(verifyReceipt(elsewhere.body, elsewhere.opts), /not one whose builds are published/);
  // Our project, running a build no release recorded.
  const unpublished = hosted(c, { build: "de".repeat(32) });
  await assert.rejects(verifyReceipt(unpublished.body, unpublished.opts), /not a published build/);
  // A checker with nothing to check against refuses rather than trusting the receipt.
  const { body, opts } = hosted(c);
  await assert.rejects(verifyReceipt(body, { ...opts, published: undefined }), /no published builds/);
});
