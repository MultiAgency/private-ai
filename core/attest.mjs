// Verifies a NEAR AI Cloud attestation report before any code is sent, per
// docs.near.ai/cloud/verification: for the gateway and every model candidate,
// an Intel TDX quote whose report data binds the signing key and our nonce,
// whose MRCONFIGID is the hash of the attested compose file, and whose RTMR3
// matches the replayed event log; for the model, NVIDIA's verdict on its GPUs.
import { createHash, randomBytes } from "node:crypto";

import { getCollateralAndVerify } from "@phala/dcap-qvl";

// The model reads the code, so its platform must be fully patched.
export const MODEL_TCB = ["UpToDate"];
// Under E2EE the gateway relays ciphertext only. Its quote must still verify and
// bind our nonce, but a pending platform patch there does not expose code.
export const GATEWAY_TCB = [
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
];

const NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";

const bytes = hex => Buffer.from(hex.replace(/^0x/i, ""), "hex");
const parse = value => (typeof value === "string" ? JSON.parse(value) : value);
const hash = (algorithm, ...parts) => {
  const h = createHash(algorithm);
  for (const part of parts) h.update(part);
  return h.digest();
};

export function replayRtmr3(eventLog) {
  let rtmr3 = Buffer.alloc(48);
  for (const event of parse(eventLog)) {
    if (event.imr !== 3) continue;
    const eventType = Buffer.alloc(4);
    eventType.writeUInt32LE(event.event_type);
    const digest = hash("sha384", eventType, ":", Buffer.from(event.event, "utf8"), ":", bytes(event.event_payload ?? ""));
    if (event.digest && !bytes(event.digest).equals(digest)) throw new Error(`event log digest mismatch for ${event.event}`);
    rtmr3 = hash("sha384", rtmr3, digest);
  }
  return rtmr3;
}

/** The TDX checks on one report; returns what the receipt records. */
export async function checkReport(report, nonce, accepted, verifyQuote = getCollateralAndVerify) {
  const verified = await verifyQuote(bytes(report.intel_quote));
  if (!accepted.includes(verified.status)) {
    throw new Error(`TCB status ${verified.status} not accepted (${verified.advisory_ids.join(", ") || "no advisories"})`);
  }
  if (verified.report.type !== "td10") throw new Error("expected a TDX quote");
  const quote = verified.report.data;
  if (quote.tdAttributes[0] & 1) throw new Error("TDX debug mode is enabled");

  if (report.signing_algo !== "ed25519") throw new Error(`unexpected signing algorithm ${report.signing_algo}`);
  const identity = bytes(report.signing_address);
  if (identity.length !== 32) throw new Error("malformed signing address");
  const bound = report.tls_cert_fingerprint ? hash("sha256", identity, bytes(report.tls_cert_fingerprint)) : identity;
  if (!Buffer.from(quote.reportData).equals(Buffer.concat([bound, bytes(nonce)]))) {
    throw new Error("report data does not bind the signer and nonce");
  }
  if (report.request_nonce?.toLowerCase() !== nonce) throw new Error("echoed nonce does not match");

  const composeHash = hash("sha256", Buffer.from(parse(report.info.tcb_info).app_compose, "utf8"));
  if (!Buffer.from(quote.mrConfigId).equals(Buffer.concat([Buffer.from([1]), composeHash, Buffer.alloc(15)]))) {
    throw new Error("MRCONFIGID does not match the attested compose file");
  }
  if (!replayRtmr3(report.event_log).equals(Buffer.from(quote.rtMr3))) throw new Error("event log does not match RTMR3");

  return {
    tcb: verified.status,
    advisories: verified.advisory_ids,
    signer: report.signing_address,
    composeHash: composeHash.toString("hex"),
  };
}

export async function nvidiaVerdict(payload) {
  const response = await fetch(NRAS_URL, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error(`NVIDIA attestation service: ${response.status}`);
  const token = (await response.json())?.[0]?.[1];
  if (typeof token !== "string") throw new Error("NVIDIA attestation service returned no token");
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url"))["x-nvidia-overall-att-result"] === true;
}

export async function checkGpu(report, nonce, verdict = nvidiaVerdict) {
  if (!report.nvidia_payload) throw new Error("no GPU evidence");
  const payload = parse(report.nvidia_payload);
  if (String(payload.nonce).toLowerCase() !== nonce) throw new Error("GPU evidence does not bind the nonce");
  if (!(await verdict(payload))) throw new Error("NVIDIA did not attest the GPUs");
}

/**
 * Fetches a fresh report for the model and verifies it. `evidence` is what a
 * receipt keeps; `attestation` is what was verified, with the key to encrypt to.
 */
export async function attest(client, model) {
  const nonce = randomBytes(32).toString("hex");
  const { ohttp_key_config, ohttp_attestation, ...report } = await client.attestationReport(model, nonce);
  return { evidence: { nonce, report }, attestation: await verifyAttestation(report, nonce) };
}

/**
 * Checks the gateway and every model candidate, and returns the gateway summary
 * plus the first verified model, whose key the review encrypts to.
 */
export async function verifyAttestation(body, nonce, { verifyQuote, gpuVerdict } = {}) {
  const gateway = await checkReport(body.gateway_attestation, nonce, GATEWAY_TCB, verifyQuote)
    .catch(error => { throw new Error(`gateway: ${error.message}`); });

  const candidates = body.model_attestations ?? [];
  if (candidates.length === 0) throw new Error("no model evidence returned");
  const failures = [];
  for (const candidate of candidates) {
    try {
      const model = await checkReport(candidate, nonce, MODEL_TCB, verifyQuote);
      await checkGpu(candidate, nonce, gpuVerdict);
      if (candidate.signing_public_key?.toLowerCase() !== candidate.signing_address.toLowerCase()) {
        throw new Error("encryption key is not the attested signing key");
      }
      return { gateway, model: { ...model, gpu: true, publicKey: candidate.signing_public_key } };
    } catch (error) {
      failures.push(error.message);
    }
  }
  throw new Error(`model: ${failures.join("; ")}`);
}
