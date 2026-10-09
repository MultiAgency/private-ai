import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, test } from "node:test";
import { promisify } from "node:util";

import { question } from "../eval/judge.mjs";

const run = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const spec = JSON.parse(readFileSync(join(root, "review/review.json"), "utf8"));
const scratch = () => mkdtempSync(join(tmpdir(), "eval-scripts-"));

describe("eval/collect.mjs", () => {
  const collect = (cwd, ...args) => run("node", ["--import", join(root, "test/fixtures/fake-github-fetch.mjs"), join(root, "eval/collect.mjs"), ...args], {
    cwd,
    env: { ...process.env, GITHUB_TOKEN: "t", FAKE_REVIEW_AUTHOR: spec.authors[0], FAKE_REVIEW_NAME: spec.name },
  });

  test("turns reacted findings on our reviews into one case per commit, pinned to the description of the time", async () => {
    const cwd = scratch();
    const { stdout } = await collect(cwd, "--repo", "o/r", "--out", "feedback");
    assert.match(stdout, /^2 reacted findings → 1 cases in /);

    const files = readdirSync(join(cwd, "feedback")).sort();
    assert.deepEqual(files, ["o-r-5-abcdef1.json", "o-r-5-abcdef1.md"]);
    const made = JSON.parse(readFileSync(join(cwd, "feedback/o-r-5-abcdef1.json"), "utf8"));
    assert.deepEqual(made, {
      name: "o/r#5 at abcdef1: reactions on private-review findings",
      repo: "o/r",
      pull_request: 5,
      base: "basebase",
      head: "abcdef1234567",
      description: "o-r-5-abcdef1.md",
      source: "👍 and 👎 on private-review findings (eval/collect.mjs).",
      bugs: { "comment-1": question("real bug") },
      falsePositives: { "comment-2": question("noise") },
    });
    assert.equal(readFileSync(join(cwd, "feedback/o-r-5-abcdef1.md"), "utf8"), "description at review time");
  });

  test("a repository is required", async () => {
    await assert.rejects(collect(scratch()), error => /--repo is required/.test(error.stderr));
  });
});

describe("eval/compare.mjs", () => {
  // compare.mjs reads and writes eval/ under its working directory, so a stand-in
  // eval/run.mjs there answers for the reviewers without any model call.
  function project(results) {
    const cwd = scratch();
    mkdirSync(join(cwd, "eval/cases"), { recursive: true });
    writeFileSync(join(cwd, "eval/cases/one.json"), "{}");
    writeFileSync(join(cwd, "eval/cases/two.json"), "{}");
    writeFileSync(join(cwd, "eval/run.mjs"), `
      const args = process.argv.slice(2);
      const at = flag => args[args.indexOf(flag) + 1];
      const results = ${JSON.stringify(results)};
      const lines = results[at("--case").split("/").pop() + ":" + at("--runner")];
      if (!lines) process.exit(1);
      console.log(lines.join("\\n"));
    `);
    return cwd;
  }
  const compare = (cwd, ...args) => run("node", [join(root, "eval/compare.mjs"), "--cases", "eval/cases", "--runs", "4", ...args], { cwd });

  test("runs each case through both reviewers and writes one table with totals", async () => {
    const cwd = project({
      "one.json:node": ["auth: caught 4/4", "old-fp: false positive raised 0/4 (want 0)", "median time 9s, 0 failed"],
      "one.json:rust": ["auth: caught 3/4", "old-fp: false positive raised 1/4 (want 0)", "median time 9s, 0 failed"],
      "two.json:node": ["race: caught 2/4", "median time 9s, 0 failed"],
      "two.json:rust": ["race: caught 1/4", "median time 9s, 0 failed"],
    });
    const { stdout } = await compare(cwd);
    assert.match(stdout, /# Action vs App, \d{4}-\d\d-\d\d: 4 runs of 3 passes per case/);
    assert.match(stdout, /\| one \| auth 4\/4 \| auth 3\/4 \| old-fp 0\/4 \| old-fp 1\/4 \|/);
    assert.match(stdout, /\| two \| race 2\/4 \| race 1\/4 \| – \| – \|/);
    assert.match(stdout, /\| \*\*total\*\* \| \*\*6\/8\*\* \| \*\*4\/8\*\* \| \*\*0\/4\*\* \| \*\*1\/4\*\* \|/);

    const [written] = readdirSync(join(cwd, "eval/feedback"));
    assert.match(written, /^compare-\d{4}-\d\d-\d\d-\d\d-\d\d\.md$/);
    assert.match(readFileSync(join(cwd, "eval/feedback", written), "utf8"), /\| \*\*total\*\* /);
  });

  test("a runner that fails shows as no result instead of stopping the table", async () => {
    const cwd = project({
      "one.json:node": ["auth: caught 4/4", "median time 9s, 0 failed"],
      "two.json:node": ["race: caught 2/4", "median time 9s, 0 failed"],
      "two.json:rust": ["race: caught 1/4", "median time 9s, 0 failed"],
    });
    const { stdout } = await compare(cwd);
    assert.match(stdout, /one\.json \[rust\]: no result, 4 failed/);
    assert.match(stdout, /\| one \| auth 4\/4 \| – \| – \| – \|/);
    assert.match(stdout, /\| \*\*total\*\* \| \*\*6\/8\*\* \| \*\*1\/4\*\* \|/);
  });
});
