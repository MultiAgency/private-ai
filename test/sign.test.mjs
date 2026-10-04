// Signature checks on a real end-to-end encrypted turn recorded from NEAR AI Cloud.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { checkSignature, sha256, signedText } from "../core/sign.mjs";

const turn = JSON.parse(readFileSync(new URL("fixtures/turn.json", import.meta.url)));
const request = Buffer.from(turn.request, "base64");
const response = Buffer.from(turn.response, "base64");
const expected = (req = request, res = response) => signedText(turn.model, sha256(req), sha256(res));

test("the enclave's signature covers the exact request and response", () => {
  checkSignature(turn.signature, expected(), turn.signer);
});

test("a changed request or response byte fails", () => {
  const changed = bytes => Buffer.concat([bytes.subarray(0, -1), Buffer.from(" ")]);
  assert.throws(() => checkSignature(turn.signature, expected(changed(request)), turn.signer), /exact request and response/);
  assert.throws(() => checkSignature(turn.signature, expected(request, changed(response)), turn.signer), /exact request and response/);
});

test("a key other than the attested one fails", () => {
  assert.throws(() => checkSignature(turn.signature, expected(), "11".repeat(32)), /other than the attested/);
});

test("a forged signature fails", () => {
  const bytes = Buffer.from(turn.signature.signature, "hex");
  bytes[0] ^= 1;
  const forged = { ...turn.signature, signature: bytes.toString("hex") };
  assert.throws(() => checkSignature(forged, expected(), turn.signer), /invalid signature/);
});

test("a gateway signature is not the model enclave's", () => {
  assert.throws(() => checkSignature({ ...turn.signature, signature_kind: "gateway" }, expected(), turn.signer), /not the model enclave/);
});
