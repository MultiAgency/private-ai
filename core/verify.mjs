// Re-checks a receipt: the attestation report against fresh Intel collateral
// and NVIDIA's service, with the same checks the run made, and every response
// signature against the attested model key.
//
// Usage: node core/verify.mjs receipt.json
//
// The receipt keeps hashes of the encrypted requests and responses, not the
// bytes, so this proves the enclave signed those hashes; the run itself
// matched them to the bytes on the wire before using each reply.
import { readFileSync } from "node:fs";

import { verifyAttestation } from "./attest.mjs";
import { RECEIPT_VERSION } from "./receipt.mjs";
import { checkSignature, sha256, signedText } from "./sign.mjs";

const path = process.argv[2];
if (!path) {
  console.error("Usage: node core/verify.mjs receipt.json");
  process.exit(2);
}

try {
  const text = readFileSync(path, "utf8");
  const receipt = JSON.parse(text);
  if (receipt.version !== RECEIPT_VERSION) throw new Error(`unknown receipt version ${receipt.version}`);
  console.log(`receipt sha256 ${sha256(text)}, created ${receipt.created_at}`);
  for (const [key, value] of Object.entries(receipt.subject ?? {})) console.log(`  ${key}: ${value}`);

  const { gateway, model } = await verifyAttestation(receipt.attestation, receipt.nonce);
  console.log(`gateway: quote verified, TCB ${gateway.tcb}, compose ${gateway.composeHash}`);
  console.log(`model ${receipt.model}: quote verified, TCB ${model.tcb}, GPUs attested, compose ${model.composeHash}, signer ${model.signer}`);

  if (!receipt.turns?.length) throw new Error("no signed turns");
  for (const turn of receipt.turns) {
    checkSignature(turn.signature, signedText(receipt.model, turn.request_sha256, turn.response_sha256), model.publicKey);
  }
  console.log(`signatures: ${receipt.turns.length} of ${receipt.turns.length} signed by the attested model key`);
  console.log("verified");
} catch (error) {
  console.error(`not verified: ${error.message}`);
  process.exit(1);
}
