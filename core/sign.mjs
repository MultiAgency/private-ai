// Checks a response signature from NEAR AI Cloud: the model's enclave signs
// "<model>:<sha256 of the exact request bytes>:<sha256 of the exact response
// bytes>" with the key its attestation report bound.
import { createHash } from "node:crypto";

import { ed25519 } from "@noble/curves/ed25519.js";

export const sha256 = data => createHash("sha256").update(data).digest("hex");

export const signedText = (model, requestSha256, responseSha256) => `${model}:${requestSha256}:${responseSha256}`;

export function checkSignature(signature, expectedText, signer) {
  if (signature?.signature_kind !== "provider_tee") {
    throw new Error(`signed by ${signature?.signature_kind ?? "nobody"}, not the model enclave`);
  }
  if (signature.signing_algo !== "ed25519") throw new Error(`unexpected signing algorithm ${signature.signing_algo}`);
  if (signature.text !== expectedText) throw new Error("signature does not cover the exact request and response");
  if (signature.signing_address?.toLowerCase() !== signer.toLowerCase()) throw new Error("signed by a key other than the attested one");
  let valid = false;
  try {
    valid = ed25519.verify(Buffer.from(signature.signature, "hex"), Buffer.from(signature.text, "utf8"), Buffer.from(signer, "hex"));
  } catch {}
  if (!valid) throw new Error("invalid signature");
}
