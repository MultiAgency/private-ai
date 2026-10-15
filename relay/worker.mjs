// The GitHub App's webhook relay, a Cloudflare Worker. It answers GitHub
// within its 10 s, and hands each review to a Durable Object that drives it:
// one HTTPS call to the Private Investigator project on OutLayer per alarm
// (each run stops within 180 s), again while the output says there is more.
// What crosses it: GitHub's event (read here, never stored or forwarded except
// install ids/account login for internal stats), and OutLayer's outputs (a job
// id, a flag, hashes).
//
// Secrets (wrangler secret put): WEBHOOK_SECRET, PAYMENT_KEY, STATS_SECRET.
// Vars: OUTLAYER_PROJECT, COMPUTE_LIMIT (micro-USD per call).
//
// GET /stats?key=$STATS_SECRET — HTML dashboard. GET /stats.json?key=… — JSON.
import { DurableObject } from "cloudflare:workers";

import { driver, eventInput, installationEvent, reviewRequest, signedByGitHub } from "./relay.mjs";
import { applyStat, emptyStats, renderStatsHtml, summarize } from "./stats.mjs";

const OUTLAYER = "https://api.outlayer.ai/call";

function statsStub(env) {
  return env.STATS.get(env.STATS.idFromName("stats"));
}

function authorizedStats(request, env) {
  if (!env.STATS_SECRET) return false;
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || request.headers.get("x-stats-key");
  return key === env.STATS_SECRET;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/stats" || url.pathname === "/stats.json")) {
      if (!authorizedStats(request, env)) return new Response("unauthorized", { status: 401 });
      const summary = await statsStub(env).snapshot();
      if (url.pathname === "/stats.json") {
        return Response.json(summary, { headers: { "cache-control": "no-store" } });
      }
      return new Response(renderStatsHtml(summary), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }

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

    const event = request.headers.get("x-github-event");
    const install = installationEvent(event, payload);
    if (install) {
      await statsStub(env).record(install);
      return new Response("noted", { status: 202 });
    }

    const wanted = reviewRequest(event, payload);
    if (!wanted) return new Response("ignored", { status: 202 });

    await statsStub(env).record({
      type: "review_request",
      installation: wanted.installation,
      repo_id: wanted.repo_id,
      pr: wanted.pr,
      trigger: wanted.comment != null ? "review" : "rerun",
    });

    // One Durable Object per pull request, so requests to it queue up in order.
    const reviews = env.REVIEWS.get(env.REVIEWS.idFromName(`${wanted.installation}/${wanted.repo_id}/${wanted.pr}`));
    await reviews.enqueue(eventInput(wanted));
    return new Response("queued", { status: 202 });
  },
};

/** Singleton observation store: counters, installations, recent events. */
export class Stats extends DurableObject {
  async record(event) {
    const state = applyStat((await this.ctx.storage.get("stats")) ?? emptyStats(), event);
    await this.ctx.storage.put("stats", state);
  }

  async snapshot() {
    return summarize((await this.ctx.storage.get("stats")) ?? emptyStats());
  }
}

/** One pull request's driver (relay.mjs), on this Durable Object's storage and OutLayer. */
export class Reviews extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const stats = () => statsStub(env);
    this.driver = driver({
      storage: ctx.storage,
      call: async input => {
        const response = await fetch(`${OUTLAYER}/${env.OUTLAYER_PROJECT}`, {
          method: "POST",
          // A step can run 150 s and more; OutLayer's default ceiling is $0.01.
          headers: { "x-payment-key": env.PAYMENT_KEY, "x-compute-limit": env.COMPUTE_LIMIT, "content-type": "application/json" },
          // OutLayer's default for an HTTPS call is 60 s; a step is planned for 180.
          body: JSON.stringify({ input, resource_limits: { max_execution_seconds: 180 } }),
        });
        if (!response.ok) throw new Error(`OutLayer ${response.status}`);
        return (await response.json()).output;
      },
      log: line => console.log(line),
      note: event => stats().record(event),
    });
  }

  enqueue(input) {
    return this.driver.enqueue(input);
  }

  alarm() {
    return this.driver.alarm();
  }
}
