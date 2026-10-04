import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { commentEvent, refusal, reviewStarter } from "../review/gate.mjs";

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
