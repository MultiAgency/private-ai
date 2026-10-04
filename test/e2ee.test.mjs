import assert from "node:assert/strict";
import test from "node:test";

import { ed25519 } from "@noble/curves/ed25519.js";

import { open, seal, session } from "../core/e2ee.mjs";

test("a streamed reply opens fragment by fragment, with tool calls joined by index", () => {
  const modelSecret = ed25519.utils.randomSecretKey();
  const s = session(Buffer.from(ed25519.getPublicKey(modelSecret)).toString("hex"));
  const toClient = ed25519.utils.toMontgomery(Buffer.from(s.headers["x-client-pub-key"], "hex"));
  const e = text => seal(text, toClient);
  const delta = d => ({ id: "chat-1", choices: [{ delta: d }] });

  const reply = s.decryptStream([
    delta({ role: "assistant", content: "", reasoning_content: "" }),
    delta({ reasoning_content: e("Two files") }),
    delta({ reasoning_content: e(" to read.") }),
    delta({ tool_calls: [{ index: 0, id: "call_a", type: "function", function: { name: e("read_file") } }] }),
    delta({ tool_calls: [{ index: 0, function: { arguments: e('{"path": ') } }] }),
    delta({ tool_calls: [{ index: 0, function: { arguments: e('"a.js"}') } }] }),
    delta({ tool_calls: [{ index: 1, id: "call_b", type: "function", function: { name: e("grep") } }] }),
    delta({ tool_calls: [{ index: 1, function: { arguments: e('{"pattern": "x"}') } }] }),
    { id: "chat-1", choices: [{ delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 9, completion_tokens: 4 } },
  ]);

  assert.equal(reply.id, "chat-1");
  assert.equal(reply.finishReason, "tool_calls");
  assert.deepEqual(reply.usage, { prompt_tokens: 9, completion_tokens: 4 });
  assert.equal(reply.message.reasoning_content, "Two files to read.");
  assert.equal(reply.message.content, "");
  assert.deepEqual(reply.message.tool_calls, [
    { id: "call_a", type: "function", function: { name: "read_file", arguments: '{"path": "a.js"}' } },
    { id: "call_b", type: "function", function: { name: "grep", arguments: '{"pattern": "x"}' } },
  ]);
});

test("a request opens only with the model's key", () => {
  const modelSecret = ed25519.utils.randomSecretKey();
  const s = session(Buffer.from(ed25519.getPublicKey(modelSecret)).toString("hex"));
  const { messages } = s.encryptRequest({ messages: [{ role: "user", content: "secret code" }], tools: [] });
  assert.equal(open(messages[0].content, ed25519.utils.toMontgomerySecret(modelSecret)), "secret code");
  assert.throws(() => open(messages[0].content, ed25519.utils.toMontgomerySecret(ed25519.utils.randomSecretKey())));
});
