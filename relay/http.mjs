// Bound memory before signature verification; authenticate the original bytes.
export const MAX_WEBHOOK_BYTES = 1024 * 1024;
export async function readWebhookBody(request, maximum = MAX_WEBHOOK_BYTES) {
  const reject = status => Object.assign(new Error("Invalid webhook body"), { status });
  if (request.headers.get("content-encoding") && request.headers.get("content-encoding") !== "identity") throw reject(415);
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maximum)) throw reject(413);
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        throw reject(413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}
