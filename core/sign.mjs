// Checks a response signature from NEAR AI Cloud: the model's enclave signs
// "<model>:<sha256 of the exact request bytes>:<sha256 of the exact response
// bytes>" with the key its attestation report bound. Runs in Node and in the
// browser alike.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 as sha256Bytes } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/** Hex SHA-256 of bytes, or of a string's UTF-8. */
export const sha256 = data => bytesToHex(sha256Bytes(typeof data === "string" ? utf8ToBytes(data) : data));

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
    valid = ed25519.verify(hexToBytes(signature.signature), utf8ToBytes(signature.text), hexToBytes(signer));
  } catch {}
  if (!valid) throw new Error("invalid signature");
}
