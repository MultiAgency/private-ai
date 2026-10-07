import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { question } from "../eval/judge.mjs";

test("a reacted finding becomes one self-contained yes/no question", () => {
  const q = question('**Bugs, Important:** `closeIfPaid` closes the job before """delivery""".');
  assert.match(q, /^Does this code review raise, as a defect, the same issue as the following finding/);
  assert.match(q, /Finding: """\*\*Bugs, Important:\*\* `closeIfPaid` closes the job before '''delivery'''\."""/);
  assert.match(q, /Answer NO if the review does not raise this issue\.$/);
});

test("every eval case is complete: pinned commits, its description, and a yes/no question per known bug", () => {
  const dir = new URL("../eval/cases/", import.meta.url);
  const cases = readdirSync(dir).filter(f => f.endsWith(".json"));
  assert.ok(cases.length > 0);
  for (const file of cases) {
    const spec = JSON.parse(readFileSync(new URL(file, dir), "utf8"));
    assert.match(spec.repo, /^[\w.-]+\/[\w.-]+$/, file);
    assert.ok(Number.isInteger(spec.pull_request), file);
    for (const sha of [spec.base, spec.head]) assert.match(sha, /^[0-9a-f]{40}$/, `${file}: a commit is pinned in full`);
    assert.ok(existsSync(new URL(spec.description, dir)), `${file}: its description file exists`);
    assert.ok(spec.source, `${file}: says where the bugs come from`);
    const questions = { ...spec.bugs, ...spec.falsePositives };
    assert.ok(Object.keys(spec.bugs ?? {}).length > 0, `${file}: has a known bug`);
    for (const [id, q] of Object.entries(questions)) assert.match(q, /\?\s/, `${file}: ${id} is a question the judge can answer YES or NO`);
    assert.equal(Object.keys(questions).length, Object.keys(spec.bugs ?? {}).length + Object.keys(spec.falsePositives ?? {}).length, `${file}: a bug id is reused as a false positive`);
  }
});
