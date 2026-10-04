// The private tool loop against a stand-in enclave: it holds the model key, decrypts
// each request, answers from a script, encrypts the reply to the client's key
// and signs the exact bytes, as NEAR AI Cloud's model enclave does.
import assert from "node:assert/strict";
import test from "node:test";

import { ed25519 } from "@noble/curves/ed25519.js";

import { runAgent } from "../core/agent.mjs";
import { open, seal } from "../core/e2ee.mjs";
import { sha256, signedText } from "../core/sign.mjs";

const MODEL = "test/model";
const SECRET = "the-private-code";

function enclave(script, { tamper } = {}) {
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

      const clientX = ed25519.utils.toMontgomery(Buffer.from(headers["x-client-pub-key"], "hex"));
      const step = script[seen.length - 1];
      const message = { role: "assistant", content: step.content ? seal(step.content, clientX) : null };
      if (step.call) {
        message.tool_calls = [{
          id: `call_${seen.length}`,
          type: "function",
          function: { name: seal(step.call[0], clientX), arguments: seal(JSON.stringify(step.call[1]), clientX) },
        }];
      }
      const id = `chat-${seen.length}`;
      const response = Buffer.from(JSON.stringify({ id, choices: [{ message, finish_reason: step.length ? "length" : "stop" }] }));
      const text = signedText(MODEL, sha256(tamper ? Buffer.concat([request, Buffer.from(" ")]) : request), sha256(response));
      signatures.set(id, {
        text,
        signature: Buffer.from(ed25519.sign(Buffer.from(text), secretKey)).toString("hex"),
        signing_address: publicKey,
        signing_algo: "ed25519",
        signature_kind: "provider_tee",
      });
      return { request, response, json: JSON.parse(response) };
    },
    signature: async id => signatures.get(id),
  };
}

const tool = (name, properties = {}) => ({
  type: "function",
  function: { name, description: name, parameters: { type: "object", properties } },
});
const lookup = tool("lookup", { key: { type: "string" } });
const finish = {
  tool: tool("submit", { answer: { type: "string" } }),
  check: args => (typeof args.answer === "string" ? undefined : "submit needs an answer"),
};
const run = (client, options) => runAgent({
  client, model: MODEL, publicKey: client.publicKey, system: "rules", prompt: "p",
  tools: [lookup], call: () => "", finish, maxTurns: 10, ...options,
});

test("an encrypted, signed loop: tool calls, a nudge, then the submitted result", async () => {
  const calls = [];
  const client = enclave([
    { call: ["lookup", { key: "a" }] },
    { content: "Thinking it over." },
    { call: ["submit", { answer: "done" }] },
  ]);
  const { result, turns } = await run(client, {
    prompt: `data with ${SECRET}`,
    call: (name, args) => { calls.push([name, args]); return `value ${SECRET}`; },
  });

  assert.deepEqual(result, { answer: "done" });
  assert.deepEqual(calls, [["lookup", { key: "a" }]]);
  assert.equal(turns.length, 3);
  assert.deepEqual(client.seen[0].toolNames, ["lookup", "submit"]);
  assert.equal(client.seen[0].messages[1].content, `data with ${SECRET}`);
  assert.equal(client.seen[1].messages.at(-1).content, `value ${SECRET}`);
  assert.equal(client.seen[2].messages.at(-1).content, "Call submit to finish.");
});

test("a reply whose signature does not cover the exact request is never used", async () => {
  const client = enclave([{ call: ["submit", { answer: "x" }] }], { tamper: true });
  await assert.rejects(run(client), /exact request and response/);
});

test("an incomplete submission is sent back, the model is told to wrap up, and the turn cap ends a loop", async () => {
  const client = enclave([{ call: ["submit", {}] }, { content: "done" }]);
  await assert.rejects(run(client, { maxTurns: 2 }), /nothing submitted after 2 turns/);
  assert.deepEqual(client.seen[1].messages.slice(-2).map(m => m.content), [
    "error: submit needs an answer",
    "1 turn left: call submit now with what you have.",
  ]);
});

test("a reply cut off at the cap is dropped, and the model is asked to be briefer", async () => {
  const client = enclave([
    { call: ["lookup", { key: "a" }], length: true },
    { call: ["submit", { answer: "x" }] },
  ]);
  const calls = [];
  const { turns } = await run(client, { call: (...args) => { calls.push(args); return ""; } });
  assert.equal(turns.length, 2);
  assert.deepEqual(calls, []);
  assert.match(client.seen[1].messages.at(-1).content, /was cut off/);
});
