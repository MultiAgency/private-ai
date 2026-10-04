// Re-checks a receipt from the command line; the page in site/ runs the same
// checks in a browser.
//
// Usage: node core/verify.mjs receipt.json
import { readFileSync } from "node:fs";

import { provenClaims, verifyReceipt } from "./receipt.mjs";

const path = process.argv[2];
if (!path) {
  console.error("Usage: node core/verify.mjs receipt.json");
  process.exit(2);
}

try {
  const { receipt, sha256, gateway, model } = await verifyReceipt(readFileSync(path, "utf8"));
  console.log(`receipt sha256 ${sha256}, created ${receipt.created_at}`);
  for (const [key, value] of Object.entries(receipt.subject ?? {})) console.log(`  ${key}: ${value}`);
  for (const [claim, text] of provenClaims({ model: receipt.model, attestation: { model, gateway }, turns: receipt.turns.length })) {
    console.log(`${claim}: ${text.replace(/`/g, "")}`);
  }
  console.log("verified");
} catch (error) {
  console.error(`not verified: ${error.message}`);
  process.exit(1);
}
