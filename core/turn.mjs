// One private turn on NEAR AI Cloud: the request end-to-end encrypted to the
// attested model key, the reply streamed, and nothing of it used until the
// model enclave's signature over the exact request and response bytes checks
// out. The agent loop, the review's deep pass and the eval's judge all take
// their turns here.
import { session } from "./e2ee.mjs";
import { checkSignature, sha256, signedText } from "./sign.mjs";

// The most one reply may produce, reasoning included: at about 35 tokens a
// second, 16k tokens is some eight minutes of streaming.
export const MAX_REPLY_TOKENS = 16_384;

/** A signed turn in an ongoing exchange; `e2ee` is the exchange's session. */
export async function signedTurn({ client, model, publicKey, e2ee, messages, tools = [], effort }) {
  const { request, response, events } = await client.chat(e2ee.headers, {
    model,
    ...e2ee.encryptRequest({ messages, tools }),
    max_tokens: MAX_REPLY_TOKENS,
    reasoning_effort: effort,
  });
  const { id, message, finishReason, usage } = e2ee.decryptStream(events);
  const record = { id, request_sha256: sha256(request), response_sha256: sha256(response) };
  record.signature = await client.signature(id, model);
  checkSignature(record.signature, signedText(model, record.request_sha256, record.response_sha256), publicKey);
  return { reply: message, finishReason, usage, record };
}

/** One question and its answer, as a signed turn of its own, without tools. */
export async function ask({ client, model, publicKey, system, prompt, effort }) {
  const { reply, record } = await signedTurn({
    client,
    model,
    publicKey,
    e2ee: session(publicKey),
    messages: [{ role: "system", content: system }, { role: "user", content: prompt }],
    effort,
  });
  return { text: reply.content ?? "", record };
}
