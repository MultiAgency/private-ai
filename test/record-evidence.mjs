// Records what checking the sample receipt offline needs: the Intel collateral
// for its quotes and the NVIDIA key that signed its GPU verdict. Run by
// `npm run sample` right after a new sample receipt is made.
import { readFileSync, writeFileSync } from "node:fs";

import { getCollateral, PHALA_PCCS_URL } from "@phala/dcap-qvl";

import { nvidiaKeys } from "../core/attest.mjs";

const receipt = JSON.parse(readFileSync(new URL("../site/sample-receipt.json", import.meta.url)));
const reports = [receipt.attestation.gateway_attestation, ...receipt.attestation.model_attestations];

const collateral = {};
for (const report of reports) {
  collateral[report.signing_address] = await getCollateral(PHALA_PCCS_URL, Buffer.from(report.intel_quote, "hex"));
}
const { kid } = JSON.parse(Buffer.from(receipt.gpu_token.split(".")[0], "base64url"));
const keys = (await nvidiaKeys()).filter(key => key.kid === kid);
if (keys.length !== 1) throw new Error(`NVIDIA no longer publishes key ${kid}`);

const now = Math.floor(Date.parse(receipt.created_at) / 1000);
writeFileSync(new URL("fixtures/sample-receipt-evidence.json", import.meta.url), `${JSON.stringify({ now, collateral, keys }, null, 1)}\n`);
console.log(`recorded collateral for ${reports.length} quotes and NVIDIA key ${kid}`);
