// Lists the NEAR AI Cloud models that can carry a private run today: each model
// NEAR runs in its own enclaves is attested here with the same checks a review
// makes. A model can pass, pass only with a pending platform update allowed, or
// fail, with the reason.
//
// Usage: node core/models.mjs        Env: NEARAI_API_KEY.
import { pathToFileURL } from "node:url";

import { attest } from "./attest.mjs";
import { nearai } from "./nearai.mjs";

/** The catalog's models that could carry a private run: verifiable, NEAR's own, and with room for a pull request. */
export function chatModels(list) {
  return (list.models ?? list.data ?? list)
    // Chat models with room for a pull request: the catalog's speech, filter and
    // reranker models are text in and out too, but with tiny contexts.
    .filter(m => m.metadata?.verifiable && m.metadata?.ownedBy === "nearai" && (m.metadata?.contextLength ?? 0) >= 32_768
      && m.metadata?.architecture?.outputModalities?.includes("text") && !/rerank|embed|whisper|filter/i.test(m.modelId ?? m.id))
    .map(m => m.modelId ?? m.id);
}

async function main() {
  const client = nearai(process.env.NEARAI_API_KEY);
  const list = await fetch("https://cloud-api.near.ai/v1/model/list").then(r => r.json());
  for (const model of chatModels(list)) {
    try {
      await attest(client, model);
      console.log(`passes                      ${model}`);
    } catch (strict) {
      try {
        await attest(client, model, { allowUnpatchedModel: true });
        console.log(`passes if unpatched allowed ${model}  (${strict.message.split(": ").slice(1).join(": ").slice(0, 60)})`);
      } catch (error) {
        console.log(`fails                       ${model}  (${error.message.slice(0, 80)})`);
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
