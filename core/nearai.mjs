// NEAR AI Cloud client. It keeps the exact bytes sent and received, which the
// response signatures cover, so nothing between here and the wire may
// re-serialize or decompress them.
import { Agent, fetch } from "undici";

const BASE = "https://cloud-api.near.ai/v1";
// Replies come back only once complete, after the model has reasoned, which can
// pass the five minutes Node's built-in fetch waits for response headers.
const TIMEOUT_MS = 900_000;
const dispatcher = new Agent({ headersTimeout: TIMEOUT_MS, bodyTimeout: TIMEOUT_MS });

export function nearai(apiKey) {
  const headers = { authorization: `Bearer ${apiKey}`, "x-no-aliasing": "true" };

  async function send(method, path, extraHeaders, body) {
    const started = Date.now();
    let response, raw;
    try {
      response = await fetch(`${BASE}${path}`, {
        method,
        headers: { ...headers, ...extraHeaders },
        body,
        dispatcher,
        // Longer than the slowest capped reply (see MAX_REPLY_TOKENS in agent.mjs).
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      raw = Buffer.from(await response.arrayBuffer());
    } catch (error) {
      const cause = error.cause?.code ?? error.cause?.message ?? error.name;
      throw new Error(`NEAR AI ${method} ${path.split("?")[0]}: ${error.message} (${cause}) after ${Math.round((Date.now() - started) / 1000)}s`);
    }
    if (!response.ok) {
      // Error text names the status and the API's own message; request bodies
      // are ciphertext, so an echo of them reveals nothing.
      const message = (() => { try { return JSON.parse(raw).error?.message; } catch {} })();
      throw new Error(`NEAR AI ${method} ${path.split("?")[0]}: ${response.status}${message ? ` ${String(message).slice(0, 200)}` : ""}`);
    }
    return raw;
  }

  return {
    async attestationReport(model, nonce) {
      const query = new URLSearchParams({ model, provider: "near", signing_algo: "ed25519", include_tls_fingerprint: "false", nonce });
      return JSON.parse(await send("GET", `/attestation/report?${query}`));
    },

    async chat(e2eeHeaders, body) {
      const request = Buffer.from(JSON.stringify(body));
      const response = await send(
        "POST",
        "/chat/completions",
        { ...e2eeHeaders, "content-type": "application/json", "accept-encoding": "identity" },
        request,
      );
      return { request, response, json: JSON.parse(response) };
    },

    // A signature can lag its response by a moment; retry briefly, then give up.
    async signature(id, model) {
      let lastError;
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          const signature = JSON.parse(await send("GET", `/signature/${encodeURIComponent(id)}?signing_algo=ed25519&model=${encodeURIComponent(model)}`));
          if (!signature.error_code) return signature;
          lastError = new Error(`signature unavailable: ${signature.error_code}`);
        } catch (error) {
          lastError = error;
        }
        await new Promise(resolve => setTimeout(resolve, attempt * 1000));
      }
      throw lastError;
    },
  };
}
