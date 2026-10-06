// The relay's decisions: GitHub's signature, which events ask for a review,
// and that only ids (and a nonce) go on to OutLayer.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { MAX_QUEUED, enqueued, eventInput, reviewRequest, settled, signedByGitHub } from "../relay/relay.mjs";

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

test("opened, reopened and ready pull requests, /review comments and re-runs ask for a review; pushes do not", () => {
  const pr = action => ({ ...base, action, pull_request: { number: 7, title: "Secret plan", body: "private text" } });
  assert.deepEqual(reviewRequest("pull_request", pr("opened")), { installation: 11, repo_id: 22, pr: 7 });
  assert.deepEqual(reviewRequest("pull_request", pr("ready_for_review")), { installation: 11, repo_id: 22, pr: 7 });
  assert.equal(reviewRequest("pull_request", pr("synchronize")), null, "a later push waits for /review");
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
  const request = reviewRequest("pull_request", { ...base, action: "opened", pull_request: { number: 7, title: "Secret plan", body: "private text" } });
  const [a, b] = [eventInput(request), eventInput(request)];
  assert.match(a.event.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.event.nonce, b.event.nonce);
  assert.doesNotMatch(JSON.stringify(a), /secret|Secret|private|someone/);
});

test("a pull request's queue is bounded, and a call's outcome never loses requests that arrived during it", () => {
  let queue = [];
  for (let i = 0; i < MAX_QUEUED; i++) queue = enqueued(queue, { event: i });
  assert.equal(enqueued(queue, { event: "flood" }), null);

  const head = { input: { event: 1 }, tries: 0 };
  const arrived = { input: { event: 2 }, tries: 0 };
  // The call ran while a request arrived; the queue read after it has both.
  const more = settled([head, arrived], { output: { job: "j", more: true } });
  assert.deepEqual(more.queue, [{ input: { step: "j" }, tries: 0 }, arrived]);
  assert.equal(more.next, 0);
  assert.deepEqual(settled([head, arrived], { output: { job: "j", more: false } }).queue, [arrived]);
  const retried = settled([head, arrived], { error: "OutLayer 502" });
  assert.deepEqual(retried.queue, [{ ...head, tries: 1 }, arrived]);
  assert.equal(retried.next, 30_000);
  const gaveUp = settled([{ ...head, tries: 2 }, arrived], { error: "OutLayer 502" });
  assert.deepEqual(gaveUp.queue, [arrived]);
  assert.match(gaveUp.log, /gave up/);
  assert.equal(settled([head], { output: { job: "j", more: false } }).next, null);
});
