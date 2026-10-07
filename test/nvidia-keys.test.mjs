// The archive of NVIDIA's signing keys (core/nvidia-keys.json): what lets old
// receipts be checked after NVIDIA rotates a key out of its list. Nothing in
// it is trusted on sight, so every key must still check out against the pinned
// intermediate, and the file must stay the shape `npm run nvidia-keys` writes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";

import { archivedNvidiaKeys, nvidiaSigningKey } from "../core/attest.mjs";

const archive = JSON.parse(readFileSync(new URL("../core/nvidia-keys.json", import.meta.url), "utf8"));
const notBefore = key => AsnConvert.parse(Buffer.from(key.x5c[0], "base64"), Certificate).tbsCertificate.validity.notBefore.getTime() / 1000;

test("the archive is not empty and every key is complete", () => {
  assert.ok(archive.keys.length > 0);
  assert.ok(archive.intermediate);
  for (const key of archive.keys) {
    for (const field of ["kid", "x", "y", "leaf"]) assert.equal(typeof key[field], "string", `${key.kid ?? "a key"} has no ${field}`);
  }
});

test("no key is archived twice, and they are kept in the order the script writes them", () => {
  const kids = archive.keys.map(k => k.kid);
  assert.equal(new Set(kids).size, kids.length, "a duplicate kid");
  assert.deepEqual(kids, [...kids].sort((a, b) => a.localeCompare(b)));
});

test("archivedNvidiaKeys gives each key the archive's one intermediate", () => {
  const keys = archivedNvidiaKeys();
  assert.equal(keys.length, archive.keys.length);
  for (const key of keys) {
    assert.equal(key.crv, "P-384");
    assert.deepEqual(key.x5c, [archive.keys.find(k => k.kid === key.kid).leaf, archive.intermediate]);
  }
});

test("every archived key's certificate chain checks out against the pinned intermediate", async () => {
  for (const key of archivedNvidiaKeys()) {
    // As of its certificate's first moment, the way the script admits a key.
    const point = await nvidiaSigningKey(key, notBefore(key));
    assert.equal(point.length, 97, `${key.kid} is not an uncompressed P-384 point`);
  }
});

test("a key's certificate is not valid before it was issued", async () => {
  const [key] = archivedNvidiaKeys();
  await assert.rejects(nvidiaSigningKey(key, notBefore(key) - 86400), /not valid when the verdict was signed/);
});
