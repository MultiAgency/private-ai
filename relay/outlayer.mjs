// OutLayer's asynchronous execution API. Never log response bodies: errors can
// contain guest output or credentials. Only fixed categories and call ids leave here.
const API = "https://api.outlayer.ai";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const validCallId = value => typeof value === "string" && UUID.test(value);

export class CallError extends Error {
  constructor(message, { retryable = false, refused = false, delay = 0 } = {}) {
    super(message);
    Object.assign(this, { retryable, refused, delay });
  }
}

export function outlayer({ project, paymentKey, computeLimit, fetch: request = fetch }) {
  async function send(path, body) {
    let response;
    try {
      response = await request(`${API}${path}`, {
        method: body ? "POST" : "GET",
        headers: {
          "x-payment-key": paymentKey,
          ...(body && { "x-compute-limit": computeLimit, "content-type": "application/json" }),
        },
        ...(body && { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new CallError("OutLayer connection failed");
    }
    if (!response.ok) {
      // /call has no idempotency key. Only documented pre-queue refusals are
      // safe to submit again. 5xx, 408 and proxy timeouts may already be running.
      let reason;
      try { reason = (await response.json()).reason; } catch { /* proxy HTML */ }
      const retryable = (response.status === 503 && ["upstream_unavailable", "keystore_error"].includes(reason))
        || response.status === 429;
      const refused = retryable || [400, 401, 402, 403, 404, 409, 415, 422].includes(response.status);
      const seconds = Number(response.headers.get("retry-after"));
      const delay = Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, 300_000) : 0;
      throw new CallError(`OutLayer HTTP ${response.status}`, { retryable, refused, delay });
    }
    let result;
    try { result = await response.json(); } catch { throw new CallError("OutLayer returned invalid JSON"); }
    if (!validCallId(result?.call_id) || !["pending", "completed", "failed"].includes(result?.status)) {
      throw new CallError("OutLayer returned an invalid call result");
    }
    return result;
  }

  return {
    start: input => send(`/call/${project}`, {
      input, async: true, resource_limits: { max_execution_seconds: 180 },
    }),
    poll: async callId => {
      if (!validCallId(callId)) throw new CallError("OutLayer call id is invalid");
      const result = await send(`/calls/${callId}`);
      if (result.call_id !== callId) throw new CallError("OutLayer returned a different call id");
      return result;
    },
  };
}
