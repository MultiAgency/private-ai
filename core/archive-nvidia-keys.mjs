// Adds NVIDIA's current signing keys to core/nvidia-keys.json: the archive that
// lets a receipt written before receipts kept their own key be checked after
// NVIDIA rotates that key out of its list, within days. Every key's
// certificate chain is checked against the pinned intermediate first.
//
// Usage: npm run nvidia-keys [-- keys.json ...]   (JWKS-shaped files to add as well)
import { readFileSync, writeFileSync } from "node:fs";

import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";

import { archivedNvidiaKeys, nvidiaKeys, nvidiaSigningKey } from "./attest.mjs";

const path = new URL("nvidia-keys.json", import.meta.url);
const found = [...await nvidiaKeys(), ...process.argv.slice(2).flatMap(file => JSON.parse(readFileSync(file, "utf8")).keys)];
const keys = new Map(archivedNvidiaKeys().map(k => [k.kid, k]));
let added = 0;
for (const key of found) {
  if (keys.has(key.kid)) continue;
  try {
    // Checked as of its certificate's first moment: every verdict it signed comes after.
    const leaf = AsnConvert.parse(Buffer.from(key.x5c?.[0] ?? "", "base64"), Certificate);
    await nvidiaSigningKey(key, leaf.tbsCertificate.validity.notBefore.getTime() / 1000);
  } catch (error) {
    console.error(`skipped ${key.kid}: ${error.message}`);
    continue;
  }
  keys.set(key.kid, key);
  added += 1;
}
const intermediates = new Set([...keys.values()].map(k => k.x5c[1]));
if (intermediates.size > 1) throw new Error("keys from more than one intermediate: the archive keeps one");
writeFileSync(path, `${JSON.stringify({
  $comment: "NVIDIA's GPU-verdict signing keys, kept after NVIDIA rotates them out of its list, for receipts that predate keeping their own. Each is trusted only after its certificate chain checks out (core/attest.mjs nvidiaSigningKey). Kept by npm run nvidia-keys.",
  intermediate: [...intermediates][0] ?? "",
  keys: [...keys.values()].sort((a, b) => a.kid.localeCompare(b.kid)).map(({ kid, x, y, x5c }) => ({ kid, x, y, leaf: x5c[0] })),
}, null, 1)}\n`);
console.log(`${added} added, ${keys.size} kept`);
