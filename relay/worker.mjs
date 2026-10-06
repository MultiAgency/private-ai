// The GitHub App's webhook relay, a Cloudflare Worker. It answers GitHub
// within its 10 s, and hands each review to a Durable Object that drives it:
// one HTTPS call to the Private Investigator project on OutLayer per alarm
// (each run stops within 180 s), again while the output says there is more.
// What crosses it: GitHub's event (read here, never stored or forwarded), and
// OutLayer's outputs (a job id, a flag, hashes). It logs job ids only.
//
// Secrets (wrangler secret put): WEBHOOK_SECRET, PAYMENT_KEY (an OutLayer
// payment key restricted to the project). Vars: OUTLAYER_PROJECT, COMPUTE_LIMIT
// (micro-USD per call).
import { DurableObject } from "cloudflare:workers";

import { enqueued, eventInput, reviewRequest, settled, signedByGitHub } from "./relay.mjs";

const OUTLAYER = "https://api.outlayer.ai/call";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/github") return new Response("not found", { status: 404 });
    const body = await request.text();
    if (!(await signedByGitHub(env.WEBHOOK_SECRET, body, request.headers.get("x-hub-signature-256")))) {
      return new Response("bad signature", { status: 401 });
    }
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      return new Response("bad body", { status: 400 });
    }
    const wanted = reviewRequest(request.headers.get("x-github-event"), payload);
    if (!wanted) return new Response("ignored", { status: 202 });
    // One Durable Object per pull request, so pushes to it queue up in order.
    const driver = env.REVIEWS.get(env.REVIEWS.idFromName(`${wanted.installation}/${wanted.repo_id}/${wanted.pr}`));
    await driver.enqueue(eventInput(wanted));
    return new Response("queued", { status: 202 });
  },
};

export class Reviews extends DurableObject {
  /** Queues an OutLayer input and wakes the driver. */
  async enqueue(input) {
    const queue = enqueued((await this.ctx.storage.get("queue")) ?? [], input);
    if (!queue) return console.log("a pull request's queue is full; a request was dropped");
    await this.ctx.storage.put("queue", queue);
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now());
  }

  /** One OutLayer call per alarm: the queue's head. */
  async alarm() {
    const head = ((await this.ctx.storage.get("queue")) ?? [])[0];
    if (!head) return;
    let result;
    try {
      const response = await fetch(`${OUTLAYER}/${this.env.OUTLAYER_PROJECT}`, {
        method: "POST",
        // A step can run 150 s and more; OutLayer's default ceiling is $0.01.
        headers: { "x-payment-key": this.env.PAYMENT_KEY, "x-compute-limit": this.env.COMPUTE_LIMIT, "content-type": "application/json" },
        // OutLayer's default for an HTTPS call is 60 s; a step is planned for 180.
        body: JSON.stringify({ input: head.input, resource_limits: { max_execution_seconds: 180 } }),
      });
      if (!response.ok) throw new Error(`OutLayer ${response.status}`);
      result = { output: (await response.json()).output };
    } catch (error) {
      result = { error: error.message };
    }
    // Read again: requests that arrived during the call joined the queue.
    const { queue, next, log } = settled((await this.ctx.storage.get("queue")) ?? [head], result);
    if (log) console.log(log);
    await this.ctx.storage.put("queue", queue);
    if (next !== null) await this.ctx.storage.setAlarm(Date.now() + next);
  }
}
