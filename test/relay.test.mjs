// The relay's decisions: GitHub's signature, which events ask for a review,
// and that only ids (and a nonce) go on to OutLayer.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { eventInput, reviewRequest, signedByGitHub } from "../relay/relay.mjs";

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
  const comment = text => ({ ...base, action: "created", issue: { number: 7, pull_request: {} }, comment: { id: 99, body: text, user: { login: "someone" } } });
  assert.deepEqual(reviewRequest("issue_comment", comment("/review please")), { installation: 11, repo_id: 22, pr: 7, comment: 99 });
  assert.equal(reviewRequest("issue_comment", comment("looks good")), null);
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
