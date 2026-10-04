// Verifies a NEAR AI Cloud attestation report before any data is sent, per
// docs.near.ai/cloud/verification: for the gateway and every model candidate,
// an Intel TDX quote whose report data binds the signing key and our nonce,
// whose MRCONFIGID is the hash of the attested compose file, and whose RTMR3
// matches the replayed event log; for the model, NVIDIA's signed verdict on its
// GPUs for the same nonce. Runs in Node and in the browser alike.
import { getCollateralAndVerify } from "@phala/dcap-qvl";
import { p384 } from "@noble/curves/nist.js";
import { equalBytes } from "@noble/curves/utils.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

// The model reads the data, so its platform must be fully patched.
export const MODEL_TCB = ["UpToDate"];
// Under E2EE the gateway relays ciphertext only. Its quote must still verify and
// bind our nonce, but a pending platform patch there does not expose data.
export const GATEWAY_TCB = [
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
];

const NRAS = "https://nras.attestation.nvidia.com";

const bytes = hex => hexToBytes(hex.replace(/^0x/i, ""));
const parse = value => (typeof value === "string" ? JSON.parse(value) : value);
const base64url = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

export function replayRtmr3(eventLog) {
  let rtmr3 = new Uint8Array(48);
  for (const event of parse(eventLog)) {
    if (event.imr !== 3) continue;
    const eventType = new Uint8Array(4);
    new DataView(eventType.buffer).setUint32(0, event.event_type, true);
    const digest = sha384(concatBytes(eventType, utf8ToBytes(":"), utf8ToBytes(event.event), utf8ToBytes(":"), bytes(event.event_payload ?? "")));
    if (event.digest && !equalBytes(bytes(event.digest), digest)) throw new Error(`event log digest mismatch for ${event.event}`);
    rtmr3 = sha384(concatBytes(rtmr3, digest));
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
  const bound = report.tls_cert_fingerprint ? sha256(concatBytes(identity, bytes(report.tls_cert_fingerprint))) : identity;
  if (!equalBytes(Uint8Array.from(quote.reportData), concatBytes(bound, bytes(nonce)))) {
    throw new Error("report data does not bind the signer and nonce");
  }
  if (report.request_nonce?.toLowerCase() !== nonce) throw new Error("echoed nonce does not match");

  const composeHash = sha256(utf8ToBytes(parse(report.info.tcb_info).app_compose));
  if (!equalBytes(Uint8Array.from(quote.mrConfigId), concatBytes(new Uint8Array([1]), composeHash, new Uint8Array(15)))) {
    throw new Error("MRCONFIGID does not match the attested compose file");
  }
  if (!equalBytes(replayRtmr3(report.event_log), Uint8Array.from(quote.rtMr3))) throw new Error("event log does not match RTMR3");

  return {
    tcb: verified.status,
    advisories: verified.advisory_ids,
    signer: report.signing_address,
    composeHash: bytesToHex(composeHash),
  };
}

/** NVIDIA's signed verdict on a model's GPU evidence: a JWT from its attestation service. */
export async function nvidiaToken(payload) {
  const response = await fetch(`${NRAS}/v3/attest/gpu`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error(`NVIDIA attestation service: ${response.status}`);
  const token = (await response.json())?.[0]?.[1];
  if (typeof token !== "string") throw new Error("NVIDIA attestation service returned no token");
  return token;
}

export async function nvidiaKeys() {
  const response = await fetch(`${NRAS}/.well-known/jwks.json`, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`NVIDIA signing keys: ${response.status}`);
  return (await response.json()).keys;
}

/** Checks NVIDIA's signature on the verdict, its issuer, its result and our nonce. */
export function checkNvidiaToken(token, nonce, keys) {
  const [header, claims, signature] = token.split(".");
  const { alg, kid } = JSON.parse(new TextDecoder().decode(base64url(header)));
  const key = keys.find(k => k.kid === kid);
  if (alg !== "ES384" || !key) throw new Error("NVIDIA verdict is not signed by a published NVIDIA key");
  const publicKey = concatBytes(new Uint8Array([4]), base64url(key.x), base64url(key.y));
  let valid = false;
  try {
    // JOSE allows either of an ECDSA signature's two valid S values; NVIDIA uses both.
    valid = p384.verify(base64url(signature), utf8ToBytes(`${header}.${claims}`), publicKey, { lowS: false });
  } catch {}
  if (!valid) throw new Error("NVIDIA verdict has an invalid signature");
  const verdict = JSON.parse(new TextDecoder().decode(base64url(claims)));
  if (verdict.iss !== NRAS) throw new Error("NVIDIA verdict has the wrong issuer");
  if (String(verdict.eat_nonce).toLowerCase() !== nonce) throw new Error("NVIDIA verdict is for another nonce");
  if (verdict["x-nvidia-overall-att-result"] !== true) throw new Error("NVIDIA did not attest the GPUs");
}

/**
 * Checks the gateway and every model candidate, and returns the gateway summary
 * plus the first verified model, whose key the run encrypts to. A receipt passes
 * the NVIDIA verdict it recorded as `gpuToken`; a live run asks NVIDIA for one.
 */
export async function verifyAttestation(body, nonce, { verifyQuote, gpuToken, getNvidiaToken = nvidiaToken, getNvidiaKeys = nvidiaKeys } = {}) {
  const gateway = await checkReport(body.gateway_attestation, nonce, GATEWAY_TCB, verifyQuote)
    .catch(error => { throw new Error(`gateway: ${error.message}`); });

  const candidates = body.model_attestations ?? [];
  if (candidates.length === 0) throw new Error("no model evidence returned");
  const failures = [];
  for (const candidate of candidates) {
    try {
      const model = await checkReport(candidate, nonce, MODEL_TCB, verifyQuote);
      if (!candidate.nvidia_payload) throw new Error("no GPU evidence");
      const payload = parse(candidate.nvidia_payload);
      if (String(payload.nonce).toLowerCase() !== nonce) throw new Error("GPU evidence does not bind the nonce");
      const token = gpuToken ?? await getNvidiaToken(payload);
      checkNvidiaToken(token, nonce, await getNvidiaKeys());
      if (candidate.signing_public_key?.toLowerCase() !== candidate.signing_address.toLowerCase()) {
        throw new Error("encryption key is not the attested signing key");
      }
      return { gateway, model: { ...model, gpuToken: token, publicKey: candidate.signing_public_key } };
    } catch (error) {
      failures.push(error.message);
    }
  }
  throw new Error(`model: ${failures.join("; ")}`);
}

/**
 * Fetches a fresh report for the model and verifies it. `evidence` is what a
 * receipt keeps; `attestation` is what was verified, with the key to encrypt to.
 */
export async function attest(client, model) {
  const nonce = bytesToHex(randomBytes(32));
  const { ohttp_key_config, ohttp_attestation, ...report } = await client.attestationReport(model, nonce);
  const attestation = await verifyAttestation(report, nonce);
  return { evidence: { nonce, report, gpuToken: attestation.model.gpuToken }, attestation };
}
