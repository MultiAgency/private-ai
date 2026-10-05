// Records what checking an OutLayer step attestation offline needs: the public
// record, the Intel collateral for its quote, and the worker builds OutLayer
// had approved on chain when it ran.
//
// Usage: node test/record-outlayer.mjs <task id>
import { writeFileSync } from "node:fs";

import { getCollateral, PHALA_PCCS_URL } from "@phala/dcap-qvl";

import { approvedAt, blockAt } from "../core/outlayer.mjs";

const task = process.argv[2];
if (!task) throw new Error("Usage: node test/record-outlayer.mjs <task id>");
const record = await fetch(`https://api.outlayer.ai/attestations/${task}`).then(r => r.json());
const collateral = await getCollateral(PHALA_PCCS_URL, Buffer.from(record.tdx_quote, "base64"));
const block = await blockAt(record.timestamp);
const approved = await approvedAt(block);
writeFileSync(new URL("fixtures/outlayer-step.json", import.meta.url), `${JSON.stringify({ now: record.timestamp, block, record, collateral, approved }, null, 1)}\n`);
console.log(`recorded task ${task} at block ${block}: ${approved.length} approved builds`);
