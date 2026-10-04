// Attestation checks on a real NEAR AI Cloud report for z-ai/glm-5.3-flash,
// recorded with its Intel collateral so the quotes verify offline at the
// recorded time. NVIDIA's verdict is stubbed; its nonce binding is not.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { verify } from "@phala/dcap-qvl";

import { verifyAttestation } from "../core/attest.mjs";

const fixture = JSON.parse(readFileSync(new URL("fixtures/attestation.json", import.meta.url)));
const collaterals = Object.values(fixture.collateral);

// The quote verifier, offline: whichever recorded collateral matches the quote's platform.
async function verifyQuote(quote) {
  let lastError;
  for (const collateral of collaterals) {
    try {
      return verify(quote, collateral, fixture.now);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}
const options = { verifyQuote, gpuVerdict: async () => true };
const body = () => structuredClone(fixture.body);
const model = b => b.model_attestations[0];

test("a real report verifies, and the review encrypts to the attested model key", async () => {
  const result = await verifyAttestation(body(), fixture.nonce, options);
  assert.equal(result.model.tcb, "UpToDate");
  assert.equal(result.model.gpu, true);
  assert.equal(result.model.publicKey, model(fixture.body).signing_public_key);
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
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /^Error: model: /);
});

test("a swapped signing key fails the report-data binding", async () => {
  const b = body();
  model(b).signing_address = model(b).signing_public_key = "11".repeat(32);
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /report data does not bind/);
});

test("an encryption key other than the signing key fails", async () => {
  const b = body();
  model(b).signing_public_key = "11".repeat(32);
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /encryption key is not the attested signing key/);
});

test("a changed compose file fails MRCONFIGID", async () => {
  const b = body();
  model(b).info.tcb_info.app_compose += " ";
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /MRCONFIGID/);
});

test("a changed event log fails RTMR3", async () => {
  const b = body();
  const events = model(b).event_log;
  const event = events.filter(e => e.imr === 3).at(-1);
  event.event_payload = "00" + event.event_payload;
  event.digest = "";
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /RTMR3/);
});

test("the model must be fully patched; the gateway may lag", async () => {
  const stale = async quote => Object.assign(await verifyQuote(quote), { status: "OutOfDate" });
  await assert.rejects(verifyAttestation(body(), fixture.nonce, { ...options, verifyQuote: stale }), /^Error: model: TCB status OutOfDate/);
});

test("a revoked gateway fails", async () => {
  const revoked = async quote => Object.assign(await verifyQuote(quote), { status: "Revoked" });
  await assert.rejects(verifyAttestation(body(), fixture.nonce, { ...options, verifyQuote: revoked }), /^Error: gateway: TCB status Revoked/);
});

test("GPU evidence must bind the nonce and pass NVIDIA", async () => {
  await assert.rejects(verifyAttestation(body(), fixture.nonce, { ...options, gpuVerdict: async () => false }), /NVIDIA did not attest/);

  const b = body();
  const payload = JSON.parse(model(b).nvidia_payload);
  payload.nonce = "00".repeat(32);
  model(b).nvidia_payload = JSON.stringify(payload);
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /GPU evidence does not bind the nonce/);

  const missing = body();
  delete model(missing).nvidia_payload;
  await assert.rejects(verifyAttestation(missing, fixture.nonce, options), /no GPU evidence/);
});

test("no model evidence fails", async () => {
  const b = body();
  b.model_attestations = [];
  await assert.rejects(verifyAttestation(b, fixture.nonce, options), /no model evidence/);
});
