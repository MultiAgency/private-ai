// One private turn (core/turn.mjs) against a stand-in for NEAR AI Cloud: the
// request leaves encrypted, and the reply is used only when the model
// enclave's signature covers the exact bytes exchanged.
import assert from "node:assert/strict";
import test from "node:test";

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { seal, session } from "../core/e2ee.mjs";
import { ask, MAX_REPLY_TOKENS, signedTurn } from "../core/turn.mjs";
import { sha256, signedText } from "../core/sign.mjs";

const MODEL = "test/model";
const secret = ed25519.utils.randomSecretKey();
const publicKey = bytesToHex(ed25519.getPublicKey(secret));

/**
 * A client whose chat reply is encrypted to whoever asked, and whose signature
 * is the model's, over the bytes it "exchanged". `tamper` changes what it signs.
 */
function fakeClient({ reply = "hello", tamper = {}, calls = [] } = {}) {
  return {
    calls,
    async chat(headers, body) {
      calls.push({ headers, body });
      const request = JSON.stringify(body);
      const response = "response bytes";
      // The reply is encrypted to the requester's key, as the model enclave does.
      const toClient = seal(reply, ed25519.utils.toMontgomery(Buffer.from(headers["x-client-pub-key"], "hex")));
      const events = [
        { id: "chat-1", choices: [{ delta: { content: toClient } }] },
        { id: "chat-1", choices: [{ delta: {}, finish_reason: "stop" }], usage: { total_tokens: 7 } },
      ];
      this.last = { request, response };
      return { request, response, events };
    },
    async signature(id, model) {
      const text = tamper.text ?? signedText(model, sha256(this.last.request), sha256(this.last.response));
      return {
        signature_kind: "provider_tee",
        signing_algo: "ed25519",
        text,
        signing_address: publicKey,
        signature: bytesToHex(ed25519.sign(utf8ToBytes(text), secret)),
      };
    },
  };
}

test("a signed turn returns the decrypted reply with the hashes the enclave signed", async () => {
  const client = fakeClient({ reply: "four" });
  const { reply, finishReason, usage, record } = await signedTurn({
    client, model: MODEL, publicKey, e2ee: session(publicKey), messages: [{ role: "user", content: "2+2?" }],
  });
  assert.equal(reply.content, "four");
  assert.equal(finishReason, "stop");
  assert.equal(usage.total_tokens, 7);
  assert.equal(record.id, "chat-1");
  assert.equal(record.request_sha256, sha256(client.last.request));
  assert.equal(record.response_sha256, sha256(client.last.response));
  assert.equal(record.signature.signing_address, publicKey);
});

test("the request is encrypted, capped, and carries the reasoning effort", async () => {
  const client = fakeClient();
  await signedTurn({
    client, model: MODEL, publicKey, e2ee: session(publicKey), messages: [{ role: "user", content: "a secret question" }], effort: "high",
  });
  const [{ headers, body }] = client.calls;
  assert.equal(headers["x-encryption-version"], "2");
  assert.equal(body.model, MODEL);
  assert.equal(body.max_tokens, MAX_REPLY_TOKENS);
  assert.equal(body.reasoning_effort, "high");
  assert.ok(!JSON.stringify(body).includes("a secret question"), "the question travels as ciphertext");
});

test("a signature over other bytes is refused, and its reply is not returned", async () => {
  const client = fakeClient({ tamper: { text: signedText(MODEL, "0".repeat(64), "1".repeat(64)) } });
  await assert.rejects(
    signedTurn({ client, model: MODEL, publicKey, e2ee: session(publicKey), messages: [{ role: "user", content: "hi" }] }),
    /exact request and response/,
  );
});

test("a signature by a key other than the attested one is refused", async () => {
  const other = bytesToHex(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
  await assert.rejects(
    signedTurn({ client: fakeClient(), model: MODEL, publicKey: other, e2ee: session(publicKey), messages: [{ role: "user", content: "hi" }] }),
    /other than the attested/,
  );
});

test("ask sends a system and a user message and returns the text with its record", async () => {
  const client = fakeClient({ reply: "an answer" });
  const { text, record } = await ask({ client, model: MODEL, publicKey, system: "be brief", prompt: "why?" });
  assert.equal(text, "an answer");
  assert.equal(record.id, "chat-1");
  const { messages } = client.calls[0].body;
  assert.deepEqual(messages.map(m => m.role), ["system", "user"]);
  assert.ok(messages.every(m => !["be brief", "why?"].includes(m.content)), "both travel encrypted");
});

test("ask gives an empty string for a reply with no text", async () => {
  const client = fakeClient({ reply: "" });
  assert.equal((await ask({ client, model: MODEL, publicKey, system: "s", prompt: "p" })).text, "");
});
