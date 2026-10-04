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
  await assert.rejects(edit(r => { r.turns.pop(); r.turns.push({ ...r.turns[0], signature: { ...r.turns[0].signature, signing_address: "11".repeat(32) } }); }), /other than the attested/);
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
