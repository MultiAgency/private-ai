// A receipt: what a private run proves, in a form anyone can re-check, from
// the command line (verify.mjs) or in a browser. It holds the attestation
// evidence, the nonce it binds, NVIDIA's signed verdict on the model's GPUs,
// and each turn's request and response hashes with the model enclave's
// signature. It holds no request or response bytes, so none of the client's data.
import { verifyAttestation } from "./attest.mjs";
import { approvedAt, blockAt, canonical, stepRecord, verifyStep } from "./outlayer.mjs";
import { checkSignature, sha256, signedText } from "./sign.mjs";

// Version 1: written by the Action. Version 2: written by the hosted App, with
// the subject committed rather than named, and every OutLayer run listed.
export const RECEIPT_VERSION = 1;
const VERSIONS = [1, 2];

/** A turn record as a run's attested output lists it. */
export const turnHash = record => sha256(canonical(record));

/** The commitment a version 2 receipt makes to its pull request (salt from the review's link). */
export const subjectCommitment = (salt, subject) => sha256(`${salt}:${canonical(subject)}`);

/** `subject` names what the run was about, e.g. a pull request and its commits. */
export function receipt({ subject, model, evidence, turns }) {
  const text = JSON.stringify({
    version: RECEIPT_VERSION,
    subject,
    model,
    created_at: new Date().toISOString(),
    nonce: evidence.nonce,
    attestation: evidence.report,
    gpu_token: evidence.gpuToken,
    // The key that signed NVIDIA's verdict, with its certificate chain: NVIDIA
    // lists only current keys, so the receipt keeps the one it needs.
    gpu_key: evidence.gpuKey,
    policy: { allow_unpatched_model: evidence.allowUnpatchedModel === true },
    turns,
  }, null, 2);
  return { text, sha256: sha256(text) };
}

/**
 * What a verified run proves, as [label, text] pairs with code in backticks. The
 * review's proof block, the page and the CLI all state exactly these claims.
 */
export function provenClaims({ model: modelName, attestation: { model, gateway }, turns, runs }) {
  return [
    ...(runs ? [["Reader", `Fetched from GitHub and read only by Private Investigator's published build ${runs.builds.map(b => `\`${b.hash}\`${b.clean ? `, built from commit \`${b.commit}\`` : ""}`).join("; ")}, in attested OutLayer enclaves: ${runs.steps.length} runs, each an approved worker build whose attestation binds what it returned.`]] : []),
    ["Model", `\`${modelName}\` in an Intel TDX enclave with NVIDIA confidential GPUs. Quote verified, TCB ${model.tcb}${model.tcb === "UpToDate" ? "" : " (an Intel platform update is pending, which this repository's policy allows for the model)"}, debug off; it binds signing key \`${model.signer}\` and this run's nonce. Compose hash \`${model.composeHash}\`.`],
    ["GPUs", "NVIDIA's signed verdict approves them for the same nonce."],
    ["Gateway", `Quote verified, TCB ${gateway.tcb}${gateway.tcb === "UpToDate" ? "" : " (an Intel platform update is pending, which the check allows for the gateway only)"}. It relayed only end-to-end encrypted content.`],
    ["Signed", `${turns} of ${turns} responses signed by the model enclave's key, over the exact request and response bytes.`],
  ];
}

/**
 * Re-runs the attestation checks on the recorded evidence, against current
 * Intel collateral and NVIDIA's published keys, and checks every response
 * signature against the attested model key. Throws on the first failure.
 *
 * The receipt keeps hashes of the encrypted requests and responses, not the
 * bytes, so this proves the enclave signed those hashes; the run itself
 * matched them to the bytes on the wire before using each reply.
 */
export async function verifyReceipt(text, options = {}) {
  const receipt = JSON.parse(text);
  if (!VERSIONS.includes(receipt.version)) throw new Error(`unknown receipt version ${receipt.version}`);
  if (options.expectSha256 && sha256(text) !== options.expectSha256) throw new Error("the published receipt is not the one the review cites (its hash differs)");
  if (!receipt.gpu_token) throw new Error("no NVIDIA verdict recorded");
  // A receipt states the policy it ran under; the only relaxation there is
  // allows a pending platform update, which provenClaims then states too.
  const { gateway, model } = await verifyAttestation(receipt.attestation, receipt.nonce, {
    ...options,
    gpuToken: receipt.gpu_token,
    gpuKey: receipt.gpu_key,
    allowUnpatchedModel: receipt.policy?.allow_unpatched_model === true,
  });
  if (!receipt.turns?.length) throw new Error("no signed turns");
  // Each request is encrypted afresh, so no two turns share their hashes: a
  // repeat would only inflate the count of signed responses.
  if (new Set(receipt.turns.map(t => `${t.request_sha256}:${t.response_sha256}`)).size !== receipt.turns.length) throw new Error("a turn is listed twice");
  for (const turn of receipt.turns) {
    checkSignature(turn.signature, signedText(receipt.model, turn.request_sha256, turn.response_sha256), model.publicKey);
  }
  const runs = receipt.version === 2 ? await verifyRuns(receipt, sha256(text), options) : undefined;
  const subjectConfirmed = receipt.version === 2 && options.salt && options.subject
    ? subjectCommitment(options.salt, options.subject) === receipt.subject_sha256
    : undefined;
  if (subjectConfirmed === false) throw new Error("the receipt is not for this pull request (its subject commitment does not match)");
  return { receipt, sha256: sha256(text), gateway, model, runs, subjectConfirmed };
}

/**
 * The OutLayer side of a version 2 receipt: every run's attestation is fetched
 * by its call id and checked (an approved worker build, running one of the
 * published builds of a published project, bound to the run's output), and
 * the outputs must prove the receipt's parts: one run generated the nonce,
 * the runs took exactly the receipt's turns, and the last run attests this
 * receipt's hash and subject commitment (its output is rebuilt here, since it
 * could not be listed in the receipt it hashes).
 */
async function verifyRuns(receipt, receiptSha256, {
  published,
  getRecord = stepRecord,
  approvedFor = async timestamp => approvedAt(await blockAt(timestamp)),
  checkStep = verifyStep,
  verifyStepQuote,
} = {}) {
  const { project, runs, findings } = receipt.outlayer ?? {};
  if (!project || !runs?.length) throw new Error("no OutLayer runs recorded");
  // Whose runs these must be: a project and builds the checker already trusts
  // (app/builds.json), never ones the receipt names for itself.
  if (!published) throw new Error("no published builds to check the runs against");
  const builds = published.filter(b => b.project === project);
  if (!builds.length) throw new Error(`project ${project} is not one whose builds are published`);
  const listed = runs.slice(0, -1).map(r => r.output);
  const job = listed[0]?.job;
  if (!job || listed.some(o => o?.job !== job)) throw new Error("the runs are not one job");
  if (!listed.some(o => o.nonce === receipt.nonce)) throw new Error("no run attests the evidence's nonce");

  // Every turn is attested exactly once: by the run that took it, or by the
  // last run (its own, and any taken by a run cut off before it could answer).
  const turns = receipt.turns.map(turnHash);
  const unclaimed = new Map();
  for (const hash of turns) unclaimed.set(hash, (unclaimed.get(hash) ?? 0) + 1);
  for (const hash of listed.flatMap(o => o.turns ?? [])) {
    if (!unclaimed.get(hash)) throw new Error("the runs' turns do not match the receipt's turns");
    unclaimed.set(hash, unclaimed.get(hash) - 1);
  }
  const rest = turns.filter(hash => unclaimed.get(hash) > 0 && unclaimed.set(hash, unclaimed.get(hash) - 1));
  const last = {
    findings, job, more: false, receipt_sha256: receiptSha256, subject_sha256: receipt.subject_sha256, turns: rest,
  };
  const outputs = [...listed, last];

  const steps = [];
  for (const [i, run] of runs.entries()) {
    if (!run.call_id) throw new Error(`run ${i + 1} has no call id`);
    const record = await getRecord(run.call_id);
    steps.push(await checkStep(record, {
      project,
      wasmHashes: builds.map(b => b.hash),
      output: outputs[i],
      approved: await approvedFor(record.timestamp),
      allowUnpatched: receipt.policy?.allow_unpatched_model === true,
      ...(verifyStepQuote && { verifyQuote: verifyStepQuote }),
    }));
  }
  return { project, steps, builds: [...new Set(steps.map(s => s.wasmHash))].map(hash => builds.find(b => b.hash === hash)) };
}

