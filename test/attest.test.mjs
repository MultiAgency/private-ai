// Attestation checks on the evidence in the page's sample receipt: a real
// NEAR AI Cloud report for z-ai/glm-5.3-flash, NVIDIA's signed verdict on its
// GPUs, and the Intel collateral and NVIDIA key recorded with it (see evidence.mjs).
import assert from "node:assert/strict";
import test from "node:test";

import { p384 } from "@noble/curves/nist.js";

import { archivedNvidiaKeys, checkNvidiaToken, nvidiaSigningKey, verifyAttestation } from "../core/attest.mjs";
import { nvidiaKeys, receipt, verifyQuote } from "./evidence.mjs";

const { nonce, gpu_token: token } = receipt;
const options = { verifyQuote, getNvidiaToken: async () => token, getNvidiaKeys: async () => nvidiaKeys };
const body = () => structuredClone(receipt.attestation);
const model = b => b.model_attestations[0];

test("a real report verifies, and the review encrypts to the attested model key", async () => {
  const result = await verifyAttestation(body(), nonce, options);
  assert.equal(result.model.tcb, "UpToDate");
  assert.equal(result.model.gpuToken, token);
  assert.equal(result.model.publicKey, model(receipt.attestation).signing_public_key);
  assert.match(result.model.composeHash, /^[0-9a-f]{64}$/);
  assert.equal(result.gateway.tcb, "OutOfDate");
});

test("a different nonce fails: a replayed report does not bind it", async () => {
  const other = "00".repeat(32);
  await assert.rejects(verifyAttestation(body(), other, options), /report data does not bind/);
});

test("one changed byte in the model quote fails", async () => {
  const b = body();
  const quote = Buffer.from(model(b).intel_quote, "hex");
  quote[200] ^= 1;
  model(b).intel_quote = quote.toString("hex");
  await assert.rejects(verifyAttestation(b, nonce, options), /^Error: model: /);
});

test("a swapped signing key fails the report-data binding", async () => {
  const b = body();
  model(b).signing_address = model(b).signing_public_key = "11".repeat(32);
  await assert.rejects(verifyAttestation(b, nonce, options), /report data does not bind/);
});

test("an encryption key other than the signing key fails", async () => {
  const b = body();
  model(b).signing_public_key = "11".repeat(32);
  await assert.rejects(verifyAttestation(b, nonce, options), /encryption key is not the attested signing key/);
});

test("a changed compose file fails MRCONFIGID", async () => {
  const b = body();
  model(b).info.tcb_info.app_compose += " ";
  await assert.rejects(verifyAttestation(b, nonce, options), /MRCONFIGID/);
});

test("a changed event log fails RTMR3", async () => {
  const b = body();
  const events = model(b).event_log;
  const event = events.filter(e => e.imr === 3).at(-1);
  event.event_payload = "00" + event.event_payload;
  event.digest = "";
  await assert.rejects(verifyAttestation(b, nonce, options), /RTMR3/);
});

test("the model must be fully patched; the gateway may lag", async () => {
  const stale = async quote => Object.assign(await verifyQuote(quote), { status: "OutOfDate" });
  await assert.rejects(verifyAttestation(body(), nonce, { ...options, verifyQuote: stale }), /^Error: model: TCB status OutOfDate/);
});

test("a revoked gateway fails", async () => {
  const revoked = async quote => Object.assign(await verifyQuote(quote), { status: "Revoked" });
  await assert.rejects(verifyAttestation(body(), nonce, { ...options, verifyQuote: revoked }), /^Error: gateway: TCB status Revoked/);
});

test("GPU evidence must bind the nonce, and NVIDIA's signed verdict must approve it", async () => {
  const b = body();
  const payload = JSON.parse(model(b).nvidia_payload);
  payload.nonce = "00".repeat(32);
  model(b).nvidia_payload = JSON.stringify(payload);
  await assert.rejects(verifyAttestation(b, nonce, options), /GPU evidence does not bind the nonce/);

  const missing = body();
  delete model(missing).nvidia_payload;
  await assert.rejects(verifyAttestation(missing, nonce, options), /no GPU evidence/);
});

test("NVIDIA's verdict must carry NVIDIA's signature (either S form), our nonce and a pass", async () => {
  await checkNvidiaToken(token, nonce, nvidiaKeys);
  await assert.rejects(checkNvidiaToken(token, "00".repeat(32), nvidiaKeys), /another nonce/);
  await assert.rejects(checkNvidiaToken(token, nonce, []), /not signed by a known NVIDIA key/);

  const [header, claims, signature] = token.split(".");
  const raw = Buffer.from(signature, "base64url");
  const n = p384.Point.CURVE().n;
  const highS = (n - BigInt(`0x${raw.subarray(48).toString("hex")}`)).toString(16).padStart(96, "0");
  const flipped = Buffer.concat([raw.subarray(0, 48), Buffer.from(highS, "hex")]).toString("base64url");
  await checkNvidiaToken(`${header}.${claims}.${flipped}`, nonce, nvidiaKeys);
  const verdict = JSON.parse(Buffer.from(claims, "base64url"));
  const failed = Buffer.from(JSON.stringify({ ...verdict, "x-nvidia-overall-att-result": false })).toString("base64url");
  await assert.rejects(checkNvidiaToken(`${header}.${failed}.${signature}`, nonce, nvidiaKeys), /invalid signature/);
});

test("an NVIDIA key counts only with a certificate chain from NVIDIA's pinned intermediate, valid when the verdict was signed", async () => {
  const [key] = nvidiaKeys;
  const signedAt = JSON.parse(Buffer.from(token.split(".")[1], "base64url")).iat;
  assert.equal((await nvidiaSigningKey(key, signedAt)).length, 97, "an uncompressed P-384 point");
  // Years later, the same key still checks out for that verdict: what keeps receipts checkable.
  await checkNvidiaToken(token, nonce, [key]);
  await assert.rejects(nvidiaSigningKey(key, signedAt + 30 * 86400), /not valid when the verdict was signed/);
  await assert.rejects(nvidiaSigningKey({ ...key, x5c: undefined }, signedAt), /no certificate chain/);
  // Bare coordinates with someone else's chain: the leaf no longer matches the key.
  const [other] = archivedNvidiaKeys().filter(k => k.kid !== key.kid);
  await assert.rejects(nvidiaSigningKey({ ...key, x5c: other.x5c }, signedAt), /not valid when the verdict was signed|does not match its certificate/);
  // A chain issued by anything but the pinned intermediate.
  await assert.rejects(nvidiaSigningKey({ ...key, x5c: [key.x5c[0], key.x5c[0]] }, signedAt), /not issued by NVIDIA's attestation intermediate/);
  // A forged leaf: one byte of its signed part changed.
  const leaf = Buffer.from(key.x5c[0], "base64");
  leaf[40] ^= 1;
  await assert.rejects(nvidiaSigningKey({ ...key, x5c: [leaf.toString("base64"), key.x5c[1]] }, signedAt), /not signed by NVIDIA's attestation intermediate|not valid|does not match/);
});

test("the archive holds the sample receipt's key, long gone from NVIDIA's list", () => {
  assert.ok(archivedNvidiaKeys().some(k => k.kid === nvidiaKeys[0].kid));
});

test("a receipt's recorded verdict is checked instead of asking NVIDIA again", async () => {
  const asked = [];
  const result = await verifyAttestation(body(), nonce, {
    ...options,
    gpuToken: token,
    getNvidiaToken: async payload => { asked.push(payload); return token; },
  });
  assert.equal(result.model.gpuToken, token);
  assert.deepEqual(asked, []);
});

test("no model evidence fails", async () => {
  const b = body();
  b.model_attestations = [];
  await assert.rejects(verifyAttestation(b, nonce, options), /no model evidence/);
});

test("a repository can allow a model whose platform update is pending, never a revoked one", async () => {
  const stale = async quote => Object.assign(await verifyQuote(quote), { status: "OutOfDate" });
  const result = await verifyAttestation(body(), nonce, { ...options, verifyQuote: stale, allowUnpatchedModel: true });
  assert.equal(result.model.tcb, "OutOfDate");

  const revoked = async quote => Object.assign(await verifyQuote(quote), { status: "Revoked" });
  await assert.rejects(verifyAttestation(body(), nonce, { ...options, verifyQuote: revoked, allowUnpatchedModel: true }), /TCB status Revoked/);
});
