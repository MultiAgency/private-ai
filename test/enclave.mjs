// A stand-in enclave: it holds the model key, decrypts each request, answers
// from a script as an encrypted stream to the client's key, and signs the exact
// streamed bytes, as NEAR AI Cloud's model enclave does.
import assert from "node:assert/strict";

import { ed25519 } from "@noble/curves/ed25519.js";

import { open, seal } from "../core/e2ee.mjs";
import { parseEvents } from "../core/nearai.mjs";
import { sha256, signedText } from "../core/sign.mjs";

export const MODEL = "test/model";
export const SECRET = "the-private-code";

export function enclave(script, { tamper } = {}) {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = Buffer.from(ed25519.getPublicKey(secretKey)).toString("hex");
  const modelX = ed25519.utils.toMontgomerySecret(secretKey);
  const seen = [];
  const signatures = new Map();

  return {
    publicKey,
    seen,
    async chat(headers, body) {
      const request = Buffer.from(JSON.stringify(body));
      assert.ok(!request.includes(SECRET), "plaintext reached the wire");
      assert.equal(headers["x-encrypt-all-fields"], "true");
      const messages = body.messages.map(m => ({ ...m, content: m.content == null ? null : open(m.content, modelX) }));
      const toolNames = body.tools.map(t => open(t.function.name, modelX));
      seen.push({ messages, toolNames });

      // Stream the reply as NEAR AI does: every fragment encrypted on its own,
      // content in two pieces, a tool call's name first and its arguments after.
      const clientX = ed25519.utils.toMontgomery(Buffer.from(headers["x-client-pub-key"], "hex"));
      const step = script[seen.length - 1];
      const id = `chat-${seen.length}`;
      const halves = text => [text.slice(0, Math.ceil(text.length / 2)), text.slice(Math.ceil(text.length / 2))].filter(Boolean);
      const events = [{ id, choices: [{ delta: { role: "assistant", content: "", reasoning_content: "" } }] }];
      for (const piece of halves(step.content ?? "")) events.push({ id, choices: [{ delta: { content: seal(piece, clientX) } }] });
      if (step.call) {
        events.push({ id, choices: [{ delta: { tool_calls: [{ index: 0, id: `call_${seen.length}`, type: "function", function: { name: seal(step.call[0], clientX) } }] } }] });
        for (const piece of halves(JSON.stringify(step.call[1]))) {
          events.push({ id, choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: seal(piece, clientX) } }] } }] });
        }
      }
      events.push({ id, choices: [{ delta: {}, finish_reason: step.length ? "length" : step.call ? "tool_calls" : "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } });
      const response = Buffer.from(`${events.map(e => `data: ${JSON.stringify(e)}\n\n`).join("")}data: [DONE]\n\n`);
      const text = signedText(MODEL, sha256(tamper ? Buffer.concat([request, Buffer.from(" ")]) : request), sha256(response));
      signatures.set(id, {
        text,
        signature: Buffer.from(ed25519.sign(Buffer.from(text), secretKey)).toString("hex"),
        signing_address: publicKey,
        signing_algo: "ed25519",
        signature_kind: "provider_tee",
      });
      return { request, response, events: parseEvents(response) };
    },
    signature: async id => signatures.get(id),
  };
}

