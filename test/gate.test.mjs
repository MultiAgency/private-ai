import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { commentEvent, refusal, reviewGate, reviewStarter } from "../review/gate.mjs";

test("a /review comment starts a run only for someone with write access", async () => {
  const roles = { owner: "admin", lead: "maintain", dev: "write", helper: "triage", fan: "read", stranger: "none" };
  const gh = { role: async login => roles[login] };
  const comment = login => ({ comment: { user: { login } } });

  assert.equal(await reviewStarter(null, gh), null);
  assert.equal(await reviewStarter({ pull_request: {} }, gh), null);
  for (const login of ["owner", "lead", "dev"]) assert.equal((await reviewStarter(comment(login), gh)).allowed, true, login);
  for (const login of ["helper", "fan", "stranger"]) assert.equal((await reviewStarter(comment(login), gh)).allowed, false, login);
  assert.deepEqual(await reviewStarter(comment("fan"), gh), { login: "fan", role: "read", allowed: false });
});

test("only an issue_comment run reads the event as a comment", () => {
  const path = join(mkdtempSync(join(tmpdir(), "gate-")), "event.json");
  writeFileSync(path, JSON.stringify({ comment: { user: { login: "fan" } } }));
  assert.deepEqual(commentEvent({ GITHUB_EVENT_NAME: "issue_comment", GITHUB_EVENT_PATH: path }), { comment: { user: { login: "fan" } } });
  assert.equal(commentEvent({ GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: path }), null);
  assert.equal(refusal({ login: "fan", role: "read" }), "Not reviewing: @fan has the read role, and starting a review with /review needs write access.");
});

const command = body => ({ action: "created", issue: { number: 7, pull_request: {} }, comment: { body, user: { login: "dev" } } });
const pull = overrides => ({ state: "open", draft: false, head: { repo: { full_name: "owner/repo" } }, ...overrides });

test("the comment gate allows same-repository reviews without enabling forks", async () => {
  const gh = { role: async () => "write", pull: async number => { assert.equal(number, 7); return pull(); } };
  assert.deepEqual(await reviewGate(command("/review"), gh, { repo: "Owner/Repo", allowForks: false }), { allowed: true });
  assert.deepEqual(await reviewGate(command("/review please"), gh, { repo: "owner/repo", allowForks: false }), { allowed: true });
  assert.deepEqual(await reviewGate(null, {}, {}), { allowed: true }, "non-comment events keep their workflow conditions");
});

test("forks require opt-in, and closed or draft pull requests never start from comments", async () => {
  const fork = pull({ head: { repo: { full_name: "fork/repo" } } });
  const gh = pr => ({ role: async () => "write", pull: async () => pr });
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo", allowForks: false })).allowed, false);
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo", allowForks: true })).allowed, true);
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo" })).allowed, true, "existing gate workflows retain fork support");
  for (const pr of [pull({ draft: true }), pull({ state: "closed" }), pull({ head: { repo: null } })]) {
    assert.equal((await reviewGate(command("/review"), gh(pr), { repo: "owner/repo", allowForks: false })).allowed, false);
  }
});

test("non-commands and unauthorized comments stop before fetching the pull request", async () => {
  const gh = { role: async () => "read", pull: async () => assert.fail("must not fetch a pull request") };
  for (const event of [command("/reviewer"), command("/review-me"), command("looks good"), { ...command("/review"), action: "edited" }, { ...command("/review"), issue: { number: 7 } }, command("/review")]) {
    assert.equal((await reviewGate(event, gh, { repo: "owner/repo" })).allowed, false);
  }
});
