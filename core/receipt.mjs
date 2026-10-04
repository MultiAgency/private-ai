// A receipt: what a private run proves, in a form anyone can re-check with
// verify.mjs. It holds the attestation evidence, the nonce it binds, and each
// turn's request and response hashes with the model enclave's signature. It
// holds no request or response bytes, so nothing of the client's data.
import { sha256 } from "./sign.mjs";

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
    turns,
  }, null, 2);
  return { text, sha256: sha256(text) };
}
