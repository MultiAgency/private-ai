// The private tool loop against a stand-in enclave: it holds the model key, decrypts
// each request, answers from a script as an encrypted stream to the client's key,
// and signs the exact streamed bytes, as NEAR AI Cloud's model enclave does.
import assert from "node:assert/strict";
import test from "node:test";

import { runAgent } from "../core/agent.mjs";
import { enclave, MODEL, SECRET } from "./enclave.mjs";

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

test("anonymous mode: a plaintext loop with no key, whose turns are unsigned", async () => {
  const seen = [];
  const client = {
    async chat(headers, body) {
      assert.deepEqual(headers, {});
      seen.push(body);
      const id = `chat-${seen.length}`;
      const events = seen.length === 1
        ? [{ id, choices: [{ delta: { tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "lookup", arguments: "{\"key\":\"a\"}" } }] }, finish_reason: "tool_calls" }] }]
        : [{ id, choices: [{ delta: { tool_calls: [{ index: 0, id: "c2", type: "function", function: { name: "submit", arguments: "{\"answer\":\"done\"}" } }] }, finish_reason: "tool_calls" }] }];
      return { request: Buffer.from(JSON.stringify(body)), response: Buffer.from(JSON.stringify(events)), events };
    },
    signature: async () => assert.fail("an anonymous turn has no signature to fetch"),
  };
  const { result, turns } = await run(client, { publicKey: undefined, prompt: `data with ${SECRET}` });
  assert.deepEqual(result, { answer: "done" });
  assert.equal(seen[0].messages[1].content, `data with ${SECRET}`);
  assert.equal(seen[0].tools[0].function.name, "lookup");
  assert.equal(turns.length, 2);
  assert.equal(turns[0].signature, undefined);
  assert.match(turns[0].request_sha256, /^[0-9a-f]{64}$/);
});
