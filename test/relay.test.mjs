// The relay's decisions: GitHub's signature, which events ask for a review,
// and that only ids (and a nonce) go on to OutLayer.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { readFileSync } from "node:fs";

import { MAX_QUEUED, RETRIES, driver, eventInput, installationEvent, reviewRequest, signedByGitHub } from "../relay/relay.mjs";
import { applyStat, emptyStats, renderStatsHtml, summarize } from "../relay/stats.mjs";

const secret = "webhook-secret";
const sign = body => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
const base = { installation: { id: 11 }, repository: { id: 22, full_name: "owner/secret-repo" } };

test("only a body GitHub signed with our secret is accepted", async () => {
  const body = JSON.stringify(base);
  assert.equal(await signedByGitHub(secret, body, sign(body)), true);
  assert.equal(await signedByGitHub(secret, `${body} `, sign(body)), false);
  assert.equal(await signedByGitHub("other", body, sign(body)), false);
  assert.equal(await signedByGitHub(secret, body, null), false);
});

test("only /review comments and check re-runs ask for a review; pull_request actions do not", () => {
  const pr = action => ({ ...base, action, pull_request: { number: 7, title: "Secret plan", body: "private text" } });
  assert.equal(reviewRequest("pull_request", pr("opened")), null, "opt-in: opening does not review");
  assert.equal(reviewRequest("pull_request", pr("reopened")), null);
  assert.equal(reviewRequest("pull_request", pr("ready_for_review")), null);
  assert.equal(reviewRequest("pull_request", pr("synchronize")), null, "pushes are silent until /review");
  assert.equal(reviewRequest("pull_request", pr("closed")), null);
  assert.equal(reviewRequest("pull_request", pr("labeled")), null);
  const comment = (text, association = "COLLABORATOR") => ({ ...base, action: "created", issue: { number: 7, pull_request: {} }, comment: { id: 99, body: text, user: { login: "someone" }, author_association: association } });
  assert.deepEqual(reviewRequest("issue_comment", comment("/review please")), { installation: 11, repo_id: 22, pr: 7, comment: 99 });
  assert.equal(reviewRequest("issue_comment", comment("looks good")), null);
  assert.equal(reviewRequest("issue_comment", comment("/review", "NONE")), null, "a stranger's /review costs nothing");
  assert.equal(reviewRequest("issue_comment", comment("/review", "FIRST_TIME_CONTRIBUTOR")), null);
  assert.deepEqual(reviewRequest("issue_comment", comment("/review", "CONTRIBUTOR")), { installation: 11, repo_id: 22, pr: 7, comment: 99 }, "the enclave decides");
  assert.equal(reviewRequest("issue_comment", { ...comment("/review"), issue: { number: 7 } }), null, "a comment on an issue, not a pull request");
  assert.deepEqual(reviewRequest("check_run", { ...base, action: "rerequested", check_run: { id: 33, pull_requests: [{ number: 7 }] } }), { installation: 11, repo_id: 22, pr: 7, rerun: 33 });
  assert.equal(reviewRequest("push", base), null);
});

test("OutLayer's input carries ids and a fresh nonce, never names or text", () => {
  const request = reviewRequest("issue_comment", { ...base, action: "created", issue: { number: 7, pull_request: {} }, comment: { id: 99, body: "/review", user: { login: "someone" }, author_association: "COLLABORATOR" } });
  const [a, b] = [eventInput(request), eventInput(request)];
  assert.match(a.event.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.event.nonce, b.event.nonce);
  assert.doesNotMatch(JSON.stringify(a), /secret|Secret|private|someone/);
});

/** A Durable Object's storage, in memory, with its one alarm. */
function storage() {
  const data = new Map();
  let alarm = null;
  return {
    get: async key => structuredClone(data.get(key)),
    put: async (key, value) => { data.set(key, structuredClone(value)); },
    getAlarm: async () => alarm,
    setAlarm: async at => { alarm = at; },
    fired: () => { const at = alarm; alarm = null; return at; },
    queue: () => data.get("queue") ?? [],
  };
}

test("a driver steps a job until it is done, one call per alarm", async () => {
  const store = storage();
  const calls = [];
  const outputs = [{ job: "j", more: true }, { job: "j", more: true }, { job: "j", more: false }];
  const d = driver({ storage: store, call: async input => (calls.push(input), outputs.shift()), now: () => 0 });
  await d.enqueue({ event: 1 });
  while (store.fired() !== null) await d.alarm();
  assert.deepEqual(calls, [{ event: 1 }, { step: "j" }, { step: "j" }]);
  assert.deepEqual(store.queue(), []);
});

test("a request that arrives during a call is kept, behind the job's next step", async () => {
  const store = storage();
  let d;
  d = driver({ storage: store, call: async input => {
    if (input.event === 1) await d.enqueue({ event: 2 });
    return input.event === 1 ? { job: "j", more: true } : { job: input.event ? "k" : "j", more: false };
  }, now: () => 0 });
  await d.enqueue({ event: 1 });
  store.fired();
  await d.alarm();
  assert.deepEqual(store.queue().map(i => i.input), [{ step: "j" }, { event: 2 }]);
});

test("a failed or empty call is retried with backoff, then given up", async () => {
  const store = storage();
  const logs = [];
  const d = driver({ storage: store, call: async () => undefined, log: line => logs.push(line), now: () => 1_000 });
  await d.enqueue({ event: 1 });
  await d.enqueue({ event: 2 });
  store.fired();
  for (let tries = 1; tries < RETRIES; tries++) {
    await d.alarm();
    assert.equal(store.queue()[0].tries, tries, "a run that returned no output is retried");
    assert.equal(store.fired(), 1_000 + 30_000 * tries);
  }
  await d.alarm();
  assert.deepEqual(store.queue().map(i => i.input), [{ event: 2 }], `given up after ${RETRIES} tries, and the next request goes on`);
  assert.match(logs[0], /gave up/);
  assert.equal(store.fired(), 1_000);
});

test("the relay calls a failing step often enough for the App to report it stopped", () => {
  const job = readFileSync(new URL("../app/src/job.rs", import.meta.url), "utf8");
  const retries = Number(job.match(/pub const STEP_RETRIES: u64 = (\d+);/)[1]);
  // The App fails a step on the call after `retries` killed runs, counting the first.
  assert.ok(RETRIES >= retries + 2, `relay RETRIES ${RETRIES} must be at least STEP_RETRIES + 2 (${retries + 2})`);
});

test("a pull request's queue is bounded", async () => {
  const store = storage();
  const logs = [];
  const notes = [];
  const d = driver({ storage: store, call: async () => ({}), log: line => logs.push(line), note: async e => notes.push(e) });
  for (let i = 0; i <= MAX_QUEUED; i++) await d.enqueue({ event: i });
  assert.equal(store.queue().length, MAX_QUEUED);
  assert.match(logs[0], /full/);
  assert.deepEqual(notes, [{ type: "queue_drop" }]);
});

test("installation and repo-scope events carry ids and account login, never repo names", () => {
  assert.deepEqual(installationEvent("installation", {
    action: "created",
    installation: { id: 11, account: { login: "Acme", type: "Organization" } },
    repositories: [{ id: 1, full_name: "Acme/secret" }, { id: 2, full_name: "Acme/other" }],
  }), { type: "install", installation: 11, account: "Acme", account_type: "Organization", repos: 2 });
  assert.deepEqual(installationEvent("installation", {
    action: "deleted",
    installation: { id: 11, account: { login: "Acme", type: "Organization" } },
  }), { type: "uninstall", installation: 11, account: "Acme", account_type: "Organization" });
  assert.deepEqual(installationEvent("installation_repositories", {
    action: "added",
    installation: { id: 11, account: { login: "bob", type: "User" } },
    repositories_added: [{ id: 3, name: "secret-repo" }],
    repositories_removed: [],
  }), { type: "repos", installation: 11, account: "bob", account_type: "User", added: 1, removed: 0 });
  assert.equal(installationEvent("installation", { action: "new_permissions_accepted", installation: { id: 11 } }), null);
  assert.doesNotMatch(JSON.stringify(installationEvent("installation", {
    action: "created",
    installation: { id: 11, account: { login: "Acme", type: "Organization" } },
    repositories: [{ id: 1, full_name: "Acme/secret" }],
  })), /secret|full_name|name/);
});

test("stats accumulate installs, reviews, and outcomes for the dashboard", () => {
  let s = emptyStats();
  s = applyStat(s, { type: "install", installation: 11, account: "Acme", account_type: "Organization", repos: 2 }, 1000);
  s = applyStat(s, { type: "repos", installation: 11, account: "Acme", account_type: "Organization", added: 1, removed: 0 }, 2000);
  s = applyStat(s, { type: "review_request", installation: 11, repo_id: 22, pr: 7, trigger: "review" }, 3000);
  s = applyStat(s, { type: "job_done", job: "j1" }, 4000);
  s = applyStat(s, { type: "job_failed", job: "j2", failed: "trial_exhausted" }, 5000);
  s = applyStat(s, { type: "outlayer_error", error: "OutLayer 503" }, 6000);
  const summary = summarize(s);
  assert.equal(summary.active_installations, 1);
  assert.equal(summary.active_orgs, 1);
  assert.equal(summary.repos_on_active, 3);
  assert.equal(summary.review_requests, 1);
  assert.equal(summary.jobs_done, 1);
  assert.equal(summary.jobs_failed, 1);
  assert.equal(summary.outlayer_errors, 1);
  assert.equal(summary.failed_by_reason.trial_exhausted, 1);
  assert.equal(summary.installations[0].account, "Acme");
  const html = renderStatsHtml(summary);
  assert.match(html, /Active installs/);
  assert.match(html, /Acme/);
  assert.doesNotMatch(html, /secret-repo|private text/);
});

test("the driver notes job outcomes and OutLayer give-ups", async () => {
  const store = storage();
  const notes = [];
  const d = driver({
    storage: store,
    call: async () => ({ job: "j", more: false, failed: "run_cutoff" }),
    note: async e => notes.push(e),
    now: () => 0,
  });
  await d.enqueue({ event: 1 });
  store.fired();
  await d.alarm();
  assert.deepEqual(notes, [{ type: "job_failed", job: "j", failed: "run_cutoff" }]);
});
