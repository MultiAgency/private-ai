// The client against a local stand-in for NEAR AI Cloud's chat endpoint.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { nearai } from "../core/nearai.mjs";

const SSE = 'data: {"id":"chat-1","choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n';

async function serve(handler) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

test("a dropped connection is retried once, and the second answer is used", async () => {
  let calls = 0;
  const { url, close } = await serve((req, res) => {
    calls++;
    if (calls === 1) return req.socket.destroy();
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(SSE);
  });
  try {
    const { events, request } = await nearai("key", url).chat({}, { model: "m" });
    assert.equal(calls, 2);
    assert.equal(events[0].id, "chat-1");
    assert.equal(JSON.parse(request).stream, true);
  } finally {
    close();
  }
});

test("a refused request is not retried, and a second drop gives up", async () => {
  let calls = 0;
  const refusing = await serve((req, res) => {
    calls++;
    res.writeHead(400, { "content-type": "application/json" });
    res.end('{"error":{"message":"bad request"}}');
  });
  try {
    await assert.rejects(nearai("key", refusing.url).chat({}, { model: "m" }), /400 bad request/);
    assert.equal(calls, 1);
  } finally {
    refusing.close();
  }

  calls = 0;
  const dropping = await serve(req => { calls++; req.socket.destroy(); });
  try {
    await assert.rejects(nearai("key", dropping.url).chat({}, { model: "m" }), /NEAR AI POST \/chat\/completions/);
    assert.equal(calls, 2);
  } finally {
    dropping.close();
  }
});
