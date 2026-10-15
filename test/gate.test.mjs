import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { commentEvent, refusal, reviewGate, reviewStarter } from "../review/gate.mjs";
import { github } from "../review/github.mjs";

test("a /review comment starts a run only for someone with write access", async () => {
  const roles = { owner: "admin", lead: "maintain", dev: "write", helper: "triage", fan: "read", stranger: "none" };
  const gh = { access: async login => ({
    permission: ({ maintain: "write", triage: "read" })[roles[login]] ?? roles[login],
    role: roles[login],
  }) };
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
  const gh = { access: async () => ({ permission: "write", role: "write" }), pull: async number => { assert.equal(number, 7); return pull(); } };
  assert.deepEqual(await reviewGate(command("/review"), gh, { repo: "Owner/Repo", allowForks: false }), { allowed: true });
  assert.deepEqual(await reviewGate(command("/review please"), gh, { repo: "owner/repo", allowForks: false }), { allowed: true });
  assert.deepEqual(await reviewGate(null, {}, {}), { allowed: true }, "non-comment events keep their workflow conditions");
});

test("forks require opt-in, and closed or draft pull requests never start from comments", async () => {
  const fork = pull({ head: { repo: { full_name: "fork/repo" } } });
  const gh = pr => ({ access: async () => ({ permission: "write", role: "write" }), pull: async () => pr });
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo", allowForks: false })).allowed, false);
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo", allowForks: true })).allowed, true);
  assert.equal((await reviewGate(command("/review"), gh(fork), { repo: "owner/repo" })).allowed, true, "existing gate workflows retain fork support");
  assert.equal((await reviewGate(command("/review"), gh(pull({ head: { repo: null } })), { repo: "owner/repo", allowForks: true })).allowed, false);
  assert.equal((await reviewGate(command("/review"), gh(pull()), { allowForks: false })).allowed, false);
  for (const pr of [pull({ draft: true }), pull({ state: "closed" }), pull({ head: { repo: null } })]) {
    assert.equal((await reviewGate(command("/review"), gh(pr), { repo: "owner/repo", allowForks: false })).allowed, false);
  }
});

test("non-commands and unauthorized comments stop before fetching the pull request", async () => {
  const gh = { access: async () => ({ permission: "read", role: "read" }), pull: async () => assert.fail("must not fetch a pull request") };
  for (const event of [command("/reviewer"), command("/review-me"), command("looks good"), { ...command("/review"), action: "edited" }, { ...command("/review"), issue: { number: 7 } }, command("/review")]) {
    assert.equal((await reviewGate(event, gh, { repo: "owner/repo" })).allowed, false);
  }
});

test("existing gate workflows need no new pull-request API permission", async () => {
  const gh = {
    access: async () => ({ permission: "write", role: "write" }),
    pull: async () => { throw Object.assign(new Error("GitHub: 403"), { status: 403 }); },
  };
  assert.deepEqual(await reviewGate(command("/review"), gh, { repo: "owner/repo" }), { allowed: true });
  await assert.rejects(reviewGate(command("/review"), gh, { repo: "owner/repo", allowForks: false }), /403/);
});

test("the GitHub-backed gate and review backstop authorize effective access, including custom roles", async t => {
  let access;
  t.mock.method(globalThis, "fetch", async url => {
    if (url.endsWith("/collaborators/dev/permission")) return Response.json(access);
    assert.equal(url, "https://api.github.com/repos/owner/repo/pulls/7");
    return Response.json(pull());
  });
  const gh = github("fixture-token", "owner/repo");
  for (const [permission, role_name, allowed] of [
    ["write", "review-maintainer", true],
    ["admin", "custom-admin", true],
    ["write", "maintain", true],
    ["write", "", true],
    ["read", "custom-triage", false],
    ["read", "read", false],
    ["none", "none", false],
    [undefined, "admin", false],
    ["unexpected", "write", false],
  ]) {
    access = { permission, role_name };
    const starter = await reviewStarter(command("/review"), gh);
    assert.equal(starter.allowed, allowed, `${role_name}: ${permission}`);
    assert.equal(starter.role, role_name || permission, "keep a nonempty label for refusal messages");
    assert.equal((await reviewGate(command("/review"), gh, { repo: "owner/repo", allowForks: false })).allowed, allowed);
  }
});

test("missing users are denied and permission API failures fail closed", async t => {
  let status = 404;
  t.mock.method(globalThis, "fetch", async url => {
    assert.match(url, /\/collaborators\/dev\/permission$/);
    return Response.json({ message: "permission lookup failed" }, { status });
  });
  const gh = github("fixture-token", "owner/repo");
  assert.equal((await reviewGate(command("/review"), gh, { repo: "owner/repo", allowForks: false })).allowed, false);
  for (status of [403, 500]) {
    await assert.rejects(reviewGate(command("/review"), gh, { repo: "owner/repo", allowForks: false }), new RegExp(`GitHub GET .*: ${status}`));
  }
});
