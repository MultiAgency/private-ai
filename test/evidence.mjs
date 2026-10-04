// The page's sample receipt, from a real review of a public pull request, with
// what checking it offline needs: the Intel collateral and NVIDIA key recorded
// when it was made, and a quote verifier that uses them at the receipt's time.
import { readFileSync } from "node:fs";

import { verify } from "@phala/dcap-qvl";

export const receiptText = readFileSync(new URL("../site/sample-receipt.json", import.meta.url), "utf8");
export const receipt = JSON.parse(receiptText);
const recorded = JSON.parse(readFileSync(new URL("fixtures/sample-receipt-evidence.json", import.meta.url)));
export const nvidiaKeys = recorded.keys;

/** Whichever recorded collateral matches the quote's platform. */
export async function verifyQuote(quote) {
  let lastError;
  for (const collateral of Object.values(recorded.collateral)) {
    try {
      return verify(quote, collateral, recorded.now);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}
