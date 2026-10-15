// The relay's decisions: GitHub's signature, which events ask for a review,
// and that only ids (and a nonce) go on to OutLayer.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { readFileSync } from "node:fs";

import { MAX_QUEUED, RETRIES, POLL_INTERVAL, PENDING_LIMIT, driver as createDriver, eventInput, installationEvent, reviewRequest, signedByGitHub } from "../relay/relay.mjs";
import { applyStat, emptyStats, renderStatsHtml, summarize } from "../relay/stats.mjs";
import { CallError, outlayer } from "../relay/outlayer.mjs";

const CALL_ID = "11111111-2222-3333-4444-555555555555";
// Existing job fixtures finish immediately; asynchronous fixtures below span alarms.
const driver = ({ call, ...options }) => createDriver({ ...options, execution: {
  start: async input => ({ call_id: CALL_ID, status: "completed", output: await call(input) }),
  poll: async () => { throw new Error("unexpected poll"); },
} });

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

test("a pending call is submitted once and polled across driver restarts", async () => {
  const store = storage();
  let submissions = 0;
  let polls = 0;
  const execution = {
    start: async () => { submissions++; return { call_id: CALL_ID, status: "pending" }; },
    poll: async id => {
      assert.equal(id, CALL_ID);
      return ++polls < 2 ? { status: "pending" } : { status: "completed", output: { job: "j", more: false } };
    },
  };
  const d = () => createDriver({ storage: store, execution, now: () => 1000 });
  await d().enqueue({ event: 1 });
  store.fired();
  await d().alarm();
  assert.equal(store.queue()[0].callId, CALL_ID);
  assert.equal(store.fired(), 1000 + POLL_INTERVAL);
  await d().alarm();
  store.fired();
  await d().alarm();
  assert.equal(submissions, 1);
  assert.equal(polls, 2);
  assert.deepEqual(store.queue(), []);
});

test("polling errors keep the same call and pause instead of submitting twice", async () => {
  const store = storage();
  let submissions = 0;
  const notes = [];
  const d = createDriver({ storage: store, note: async e => notes.push(e), execution: {
    start: async () => { submissions++; return { call_id: CALL_ID, status: "pending" }; },
    poll: async () => { throw new CallError("OutLayer HTTP 524"); },
  } });
  await d.enqueue({ event: 1 });
  store.fired();
  await d.alarm();
  for (let i = 0; i < RETRIES; i++) { store.fired(); await d.alarm(); }
  assert.equal(submissions, 1);
  assert.equal(store.queue()[0].callId, CALL_ID);
  assert.equal(store.queue()[0].paused, true);
  assert.equal(notes[0].call_id, CALL_ID);
  await d.enqueue({ event: 2 });
  assert.equal(store.queue()[0].paused, false, "a fresh command resumes status polling");
  store.fired();
  await d.alarm();
  assert.equal(submissions, 1);
});

test("an ambiguous POST or interrupted submission is never retried", async () => {
  for (const interrupted of [false, true]) {
    const store = storage();
    let submissions = 0;
    const d = createDriver({ storage: store, execution: {
      start: async () => { submissions++; throw new CallError("OutLayer HTTP 524"); },
    } });
    await d.enqueue({ event: 1 });
    if (interrupted) await store.put("queue", [{ input: { event: 1 }, tries: 0, protocol: 1, submitting: true }]);
    store.fired();
    await d.alarm();
    assert.equal(store.queue()[0].paused, true);
    await d.enqueue({ event: 2 });
    await d.alarm();
    assert.equal(submissions, interrupted ? 0 : 1);
  }
});

test("a stalled pending execution is retained and reported, without retrying it", async () => {
  const store = storage();
  let time = 0;
  const notes = [];
  const d = createDriver({ storage: store, now: () => time, note: async e => notes.push(e), execution: {
    start: async () => ({ call_id: CALL_ID, status: "pending" }),
    poll: async () => ({ status: "pending" }),
  } });
  await d.enqueue({ event: 1 });
  store.fired(); await d.alarm();
  time = PENDING_LIMIT;
  store.fired(); await d.alarm();
  assert.equal(store.queue()[0].paused, true);
  assert.equal(store.queue()[0].callId, CALL_ID);
  assert.equal(await store.getAlarm(), null);
  assert.match(notes[0].error, /pending after 15 minutes/);
});

test("only known pre-queue refusals can resubmit, respecting Retry-After", async () => {
  const store = storage();
  let submissions = 0;
  const d = createDriver({ storage: store, now: () => 0, execution: {
    start: async () => {
      if (++submissions === 1) throw new CallError("OutLayer HTTP 503", { refused: true, retryable: true, delay: 60_000 });
      return { call_id: CALL_ID, status: "completed", output: {} };
    },
  } });
  await d.enqueue({ event: 1 });
  store.fired(); await d.alarm();
  assert.equal(store.queue()[0].submitting, undefined);
  assert.equal(store.fired(), 60_000);
  await d.alarm();
  assert.equal(submissions, 2);
  assert.deepEqual(store.queue(), []);
});

test("a request arriving while a call is polled stays behind its next step", async () => {
  const store = storage();
  let d;
  d = createDriver({ storage: store, execution: {
    start: async () => ({ call_id: CALL_ID, status: "pending" }),
    poll: async () => {
      await d.enqueue({ event: 2 });
      return { status: "completed", output: { job: "j", more: true } };
    },
  } });
  await d.enqueue({ event: 1 });
  store.fired(); await d.alarm();
  store.fired(); await d.alarm();
  assert.deepEqual(store.queue().map(i => i.input), [{ step: "j" }, { event: 2 }]);
});

test("the HTTP transport submits asynchronously and polls only the saved API call id", async () => {
  const requests = [];
  const api = outlayer({ project: "hack.near/private-investigator", paymentKey: "secret", computeLimit: "50000", fetch: async (url, init) => {
    requests.push({ url, init });
    return Response.json({ call_id: CALL_ID, status: requests.length === 1 ? "pending" : "completed", output: {} });
  } });
  await api.start({ event: 1 });
  await api.poll(CALL_ID);
  assert.deepEqual(JSON.parse(requests[0].init.body), { input: { event: 1 }, async: true, resource_limits: { max_execution_seconds: 180 } });
  assert.equal(requests[0].init.headers["x-compute-limit"], "50000");
  assert.equal(requests[1].url, `https://api.outlayer.ai/calls/${CALL_ID}`);
  assert.equal(requests[1].init.method, "GET");
  assert.equal(requests[1].init.body, undefined);
  await assert.rejects(api.poll("https://attacker.invalid/"), /call id is invalid/);
});

test("the transport classifies refusals and never exposes upstream body text", async () => {
  for (const [status, reason, retryable, refused] of [
    [503, "upstream_unavailable", true, true], [503, "keystore_error", true, true],
    [503, "unknown", false, false], [524, undefined, false, false],
    [500, "internal_error", false, false], [408, "timeout", false, false],
    [429, "rate_limit_exceeded", true, true], [403, "project_not_allowed", false, true],
  ]) {
    const api = outlayer({ fetch: async () => Response.json({ reason, error: "private content and secret" }, { status, headers: { "retry-after": "45" } }) });
    await assert.rejects(api.start({}), e => {
      assert.equal(e.retryable, retryable);
      assert.equal(e.refused, refused);
      assert.equal(e.delay, 45_000);
      assert.doesNotMatch(e.message, /private|secret/);
      return true;
    });
  }
  const api = outlayer({ fetch: async () => { throw new Error("payment key: secret"); } });
  await assert.rejects(api.start({}), e => !e.refused && !/secret/.test(e.message));
});

test("malformed accepted results cannot trigger a second submission", async () => {
  for (const result of [{ status: "pending" }, { call_id: "../bad", status: "pending" }, { call_id: CALL_ID, status: "unknown" }]) {
    const api = outlayer({ fetch: async () => Response.json(result) });
    await assert.rejects(api.start({}), e => !e.refused && !e.retryable);
  }
  const api = outlayer({ fetch: async () => Response.json({ call_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", status: "pending" }) });
  await assert.rejects(api.poll(CALL_ID), /different call id/);
});

test("a deployment never replays a legacy synchronous queue with unknown acceptance", async () => {
  const store = storage();
  await store.put("queue", [{ input: { event: 1 }, tries: 1 }]);
  let calls = 0;
  const d = createDriver({ storage: store, execution: { start: async () => { calls++; } } });
  await d.alarm();
  assert.equal(calls, 0);
  assert.equal(store.queue()[0].paused, true);
});

test("a confirmed failed execution is retried, but terminal admission refusals are not", async () => {
  const store = storage();
  let calls = 0;
  const d = createDriver({ storage: store, execution: {
    start: async () => {
      calls++;
      if (calls === 1) return { call_id: CALL_ID, status: "failed" };
      throw new CallError("OutLayer HTTP 401", { refused: true });
    },
  } });
  await d.enqueue({ event: 1 });
  store.fired(); await d.alarm();
  assert.equal(store.queue()[0].callId, undefined, "a settled failed call can start a recovery run");
  store.fired(); await d.alarm();
  assert.equal(calls, 2);
  assert.deepEqual(store.queue(), []);
});
