import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readWebhookBody } from "../relay/http.mjs";
import { signedByGitHub, reviewRequest } from "../relay/relay.mjs";

test("webhook verification authenticates bytes without UTF-8 normalization", async () => {
  const bytes = new Uint8Array([123, 255, 125]);
  const signature = `sha256=${createHmac("sha256", "secret").update(bytes).digest("hex")}`;
  assert.equal(await signedByGitHub("secret", bytes, signature), true);
  assert.equal(await signedByGitHub("secret", new TextDecoder().decode(bytes), signature), false);
  assert.throws(() => new TextDecoder("utf-8", { fatal: true }).decode(bytes));
});

test("webhook size limit covers missing or misleading Content-Length and cancels streams", async () => {
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(8)); },
    cancel() { cancelled = true; },
  });
  await assert.rejects(readWebhookBody(new Request("https://example.test", { method: "POST", body: stream, duplex: "half", headers: { "content-length": "1" } }), 4), { status: 413 });
  assert.equal(cancelled, true);
  await assert.rejects(readWebhookBody(new Request("https://example.test", { method: "POST", body: "12345" }), 4), { status: 413 });
  assert.deepEqual(await readWebhookBody(new Request("https://example.test", { method: "POST", body: "1234" }), 4), new TextEncoder().encode("1234"));
});

test("review events require positive safe IDs and a concrete trigger ID", () => {
  const payload = { installation: { id: 1 }, repository: { id: 2 }, action: "created", issue: { number: 3, pull_request: {} }, comment: { id: 4, body: "/review", author_association: "COLLABORATOR" } };
  for (const id of [0, -1, Number.MAX_SAFE_INTEGER + 1, undefined]) {
    assert.equal(reviewRequest("issue_comment", { ...payload, comment: { ...payload.comment, id } }), null);
    assert.equal(reviewRequest("issue_comment", { ...payload, installation: { id } }), null);
  }
});
