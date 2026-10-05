// Checks one OutLayer step attestation: the proof of which code read a
// repository in the hosted App. A step's public record (api.outlayer.ai
// /attestations/{task_id}) holds a TDX quote whose report data binds the task:
// the WASM that ran, its input and output hashes, the caller and the project.
// The quote's five measurements must be a worker build OutLayer approved on
// chain (worker.outlayer.near) when the step ran. Runs in Node and in the browser.
import { getCollateralAndVerify } from "@phala/dcap-qvl";
import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { MODEL_TCB, GATEWAY_TCB } from "./attest.mjs";

export const REGISTRY = "worker.outlayer.near";
const ARCHIVAL = "https://archival-rpc.mainnet.fastnear.com";
const MEASUREMENTS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"];

const le64 = n => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt(n), true);
  return b;
};
const base64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

// Records from before this instant commit to fewer fields (OutLayer's
// outlayer-verify: V1_CUTOFF): not the caller, project, secrets, time or payment.
export const V1_CUTOFF = 1_769_784_939;

/**
 * The task hash the worker puts in the first 32 bytes of report data, as
 * OutLayer's own verifier rebuilds it (outlayer-verify verify-core/src/preimage.rs).
 */
export function taskHash(r) {
  const parts = [utf8ToBytes(r.task_type), le64(r.task_id)];
  for (const k of ["repo_url", "commit_hash", "build_target", "wasm_hash", "input_hash"]) if (r[k] != null) parts.push(utf8ToBytes(r[k]));
  parts.push(utf8ToBytes(r.output_hash));
  if (r.block_height != null) parts.push(le64(r.block_height));
  if (r.timestamp >= V1_CUTOFF) {
    for (const k of ["caller_account_id", "project_id", "secrets_ref"]) if (r[k] != null) parts.push(utf8ToBytes(r[k]));
    parts.push(le64(r.timestamp));
    if (r.attached_usd != null) parts.push(utf8ToBytes(r.attached_usd));
  }
  return sha256(concatBytes(...parts));
}

// Archival RPC: FastNEAR first, NEAR's own when it is rate limited.
const ARCHIVALS = [ARCHIVAL, "https://archival-rpc.mainnet.near.org"];

async function rpc(method, params) {
  let last;
  for (const url of ARCHIVALS) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    const body = await response.json().catch(() => ({ error: { message: `HTTP ${response.status}` } }));
    if (body.error?.code === -429 || response.status === 429) {
      last = new Error(`NEAR RPC ${method}: rate limited`);
      continue;
    }
    if (body.error || body.result?.error) throw new Error(`NEAR RPC ${method}: ${JSON.stringify(body.error ?? body.result.error).slice(0, 120)}`);
    return body.result;
  }
  throw last;
}

/** A JSON value as the worker hashes it: compact, keys sorted (the App prints them sorted too). */
export const canonical = value =>
  Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object" ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`
  : JSON.stringify(value);

/** A step's public record, by the call id an HTTPS call returned (the documented lookup). */
export async function stepRecord(callId) {
  const response = await fetch(`https://api.outlayer.ai/attestations/by-call/${encodeURIComponent(callId)}`, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`OutLayer attestation for call ${callId}: ${response.status}`);
  return response.json();
}

const header = async blockId => (await rpc("block", blockId === "final" ? { finality: "final" } : { block_id: blockId })).header;

/**
 * The last block at or before `seconds`. Blocks come about every 0.6 s, so
 * the height is estimated from the chain head, then corrected from the blocks
 * it lands on: a handful of calls rather than a bisection's two dozen.
 */
export async function blockAt(seconds) {
  const target = BigInt(seconds) * 1_000_000_000n;
  let { height, timestamp_nanosec: ts } = await header("final");
  let rate = 600_000_000n; // ns per block, refined as blocks are read
  for (let i = 0; i < 6; i++) {
    const guess = height - Number((BigInt(ts) - target) / rate);
    if (guess === height) break;
    const block = await header(guess).catch(() => null);
    if (!block) break;
    if (block.height !== height) rate = BigInt(Math.max(1, Math.abs(Number(BigInt(ts) - BigInt(block.timestamp_nanosec)) / Math.abs(height - block.height))) | 0);
    ({ height, timestamp_nanosec: ts } = block);
    if (BigInt(ts) <= target && target - BigInt(ts) < 2_000_000_000n) break;
  }
  // Step back to the last block at or before the target.
  while (BigInt(ts) > target) ({ height, timestamp_nanosec: ts } = await header(height - 1));
  return height;
}

const approvedCache = new Map();

/** OutLayer's approved worker builds at a block (cached: a receipt's runs are minutes apart). */
export async function approvedAt(height) {
  if (!approvedCache.has(height)) {
    approvedCache.set(height, rpc("query", { request_type: "call_function", block_id: height, account_id: REGISTRY, method_name: "get_approved_measurements", args_base64: "e30=" })
      .then(result => JSON.parse(new TextDecoder().decode(Uint8Array.from(result.result)))));
  }
  return approvedCache.get(height);
}

/**
 * Checks one step record. `expect` names what it must show: the project, the
 * caller, the WASM builds published for it, and the output the step returned
 * (a JSON value).
 * `approved` lists the measurements OutLayer approved when the step ran.
 */
export async function verifyStep(record, { project, caller, wasmHashes, output, approved, allowUnpatched = false, verifyQuote = getCollateralAndVerify }) {
  if (record.timestamp < V1_CUTOFF) throw new Error(`step ${record.task_id}: an older record that does not commit to the caller or project`);
  const verified = await verifyQuote(base64(record.tdx_quote));
  if (!(allowUnpatched ? GATEWAY_TCB : MODEL_TCB).includes(verified.status)) throw new Error(`step ${record.task_id}: TCB status ${verified.status} not accepted`);
  const td = verified.report.data;
  if (verified.report.type !== "td10") throw new Error(`step ${record.task_id}: expected a TDX quote`);
  if (td.tdAttributes[0] & 1) throw new Error(`step ${record.task_id}: TDX debug mode is enabled`);
  if (!equalBytes(Uint8Array.from(td.reportData).subarray(0, 32), taskHash(record))) throw new Error(`step ${record.task_id}: the quote does not bind this record`);

  const measured = { mrtd: td.mrTd, rtmr0: td.rtMr0, rtmr1: td.rtMr1, rtmr2: td.rtMr2, rtmr3: td.rtMr3 };
  const hex = Object.fromEntries(MEASUREMENTS.map(k => [k, bytesToHex(Uint8Array.from(measured[k]))]));
  if (!approved.some(set => MEASUREMENTS.every(k => set[k]?.toLowerCase() === hex[k]))) throw new Error(`step ${record.task_id}: not a worker build OutLayer approved`);

  if (project && record.project_id !== project) throw new Error(`step ${record.task_id}: ran for project ${record.project_id}, not ${project}`);
  if (caller && record.caller_account_id !== caller) throw new Error(`step ${record.task_id}: called by ${record.caller_account_id}, not ${caller}`);
  if (wasmHashes && !wasmHashes.includes(record.wasm_hash)) throw new Error(`step ${record.task_id}: ran WASM ${record.wasm_hash}, not a published build`);
  if (output !== undefined && bytesToHex(sha256(utf8ToBytes(canonical(output)))) !== record.output_hash) throw new Error(`step ${record.task_id}: output does not match the attested hash`);
  return { task: record.task_id, wasmHash: record.wasm_hash, tcb: verified.status, timestamp: record.timestamp };
}
