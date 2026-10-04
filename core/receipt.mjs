// A receipt: what a private run proves, in a form anyone can re-check, from
// the command line (verify.mjs) or in a browser. It holds the attestation
// evidence, the nonce it binds, NVIDIA's signed verdict on the model's GPUs,
// and each turn's request and response hashes with the model enclave's
// signature. It holds no request or response bytes, so none of the client's data.
import { verifyAttestation } from "./attest.mjs";
import { checkSignature, sha256, signedText } from "./sign.mjs";

export const RECEIPT_VERSION = 1;

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
    turns,
  }, null, 2);
  return { text, sha256: sha256(text) };
}

/**
 * What a verified run proves, as [label, text] pairs with code in backticks. The
 * review's proof block, the page and the CLI all state exactly these claims.
 */
export function provenClaims({ model: modelName, attestation: { model, gateway }, turns }) {
  return [
    ["Model", `\`${modelName}\` in an Intel TDX enclave with NVIDIA confidential GPUs. Quote verified, TCB ${model.tcb}, debug off; it binds signing key \`${model.signer}\` and this run's nonce. Compose hash \`${model.composeHash}\`.`],
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
  if (receipt.version !== RECEIPT_VERSION) throw new Error(`unknown receipt version ${receipt.version}`);
  if (!receipt.gpu_token) throw new Error("no NVIDIA verdict recorded");
  const { gateway, model } = await verifyAttestation(receipt.attestation, receipt.nonce, { ...options, gpuToken: receipt.gpu_token });
  if (!receipt.turns?.length) throw new Error("no signed turns");
  for (const turn of receipt.turns) {
    checkSignature(turn.signature, signedText(receipt.model, turn.request_sha256, turn.response_sha256), model.publicKey);
  }
  return { receipt, sha256: sha256(text), gateway, model };
}
