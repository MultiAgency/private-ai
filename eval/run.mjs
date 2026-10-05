// Measures the reviewer on pull requests whose bugs are known: each case pins a
// commit, the description as it stood then, the bugs a review should raise, and
// the false positives it should not, all as yes/no questions.
// It runs the same reviewChange the Action runs, several times in parallel,
// and reports how often each bug was caught. Nothing is posted.
//
// Usage: node eval/run.mjs [--case eval/cases/x.json] [--runs 4] [--passes 1]
//                          [--runner rust [--reply-cap N]]
// --runner rust scores the hosted App's reviewer (app/) on the same case, with
// --passes merged as the hosted job merges them, from its dry-run build:
//   cargo build --release --target wasm32-wasip2 --no-default-features --target-dir target/dry
// Env: NEARAI_API_KEY, GITHUB_TOKEN.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";

import { attest } from "../core/attest.mjs";
import { nearai } from "../core/nearai.mjs";
import { github } from "../review/github.mjs";
import { unpack } from "../review/repo.mjs";
import { reviewChange } from "../review/review.mjs";
import { judge } from "./judge.mjs";

const { values } = parseArgs({
  options: {
    case: { type: "string", default: "eval/cases/near-agencies-94.json" },
    runs: { type: "string", default: "4" },
    passes: { type: "string", default: "1" },
    runner: { type: "string", default: "node" },
    "reply-cap": { type: "string" },
  },
});
const casePath = resolve(values.case);
const spec = JSON.parse(readFileSync(casePath, "utf8"));
const model = process.env.MODEL || "z-ai/glm-5.3-flash";
const gh = github(process.env.GITHUB_TOKEN, spec.repo);
const client = nearai(process.env.NEARAI_API_KEY);

const compare = await fetch(`https://api.github.com/repos/${spec.repo}/compare/${spec.base}...${spec.head}`, {
  headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}`, accept: "application/vnd.github+json" },
}).then(r => r.json());
const live = await gh.pull(spec.pull_request);
const pr = {
  ...live,
  body: readFileSync(resolve(dirname(casePath), spec.description), "utf8"),
  base: { ref: live.base.ref, sha: spec.base },
  head: { ref: live.head.ref, sha: spec.head },
};
const rubric = (await Promise.all(["REVIEW.md", "AGENTS.md"].map(async path => {
  const text = await gh.text(path, spec.base);
  return text && `## ${path}\n\n${text}`;
}))).filter(Boolean).join("\n\n");
const tarball = await gh.tarball(spec.head);
const { attestation } = await attest(client, model);
const publicKey = attestation.model.publicKey;

/** One review by the App's reviewer: the dry-run build under wasmtime, on the same commit and description. */
function rustReview() {
  const wasm = resolve("target/dry/wasm32-wasip2/release/private-investigator.wasm");
  const input = JSON.stringify({
    repo: spec.repo, pr: spec.pull_request, base: spec.base, head: spec.head, description: pr.body, max_turns: 30, passes: Number(values.passes),
    ...(values["reply-cap"] && { reply_cap: Number(values["reply-cap"]) }),
  });
  return new Promise((done, fail) => {
    const child = execFile("wasmtime", ["run", "-S", "http", "-S", "inherit-env=n", "--env", "NEARAI_API_KEY", "--env", "GITHUB_TOKEN", wasm],
      { maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) return fail(new Error(`rust reviewer: ${stderr.trim().split("\n").at(-1) || error.message}`));
        const out = JSON.parse(stdout);
        done({ review: out.review, turns: Array(out.turns).fill(null) });
      });
    child.stdin.end(input);
  });
}

console.log(`${spec.name}: ${values.runs} runs of ${values.runner === "rust" ? "the App's reviewer, " : ""}${values.passes} pass${values.passes === "1" ? "" : "es"}`);
const runs = await Promise.all(Array.from({ length: Number(values.runs) }, async (_, i) => {
  const head = unpack(tarball);
  const started = Date.now();
  try {
    const { review, turns } = values.runner === "rust" ? await rustReview() : await reviewChange({
      client, model, publicKey, pr, files: compare.files, rubric, root: head.root,
      maxTurns: 30, passes: Number(values.passes),
    });
    const text = [review.summary, ...review.findings.map(f => `${f.path}:${f.line} ${f.pass}, ${f.severity}: ${f.body}`)].join("\n\n");
    const caught = await judge({ client, model, publicKey, bugs: { ...spec.bugs, ...spec.falsePositives }, text });
    const seconds = Math.round((Date.now() - started) / 1000);
    console.log(`run ${i}: ${seconds}s, ${turns.length} signed turns, ${review.findings.length} findings, ` +
      Object.entries(caught).map(([id, yes]) => id in (spec.bugs ?? {}) ? `${id} ${yes ? "CAUGHT" : "missed"}` : `${id} ${yes ? "RAISED (false positive)" : "not raised"}`).join(", "));
    return { seconds, caught };
  } catch (error) {
    console.log(`run ${i}: failed: ${error.message}`);
    return null;
  } finally {
    head.remove();
  }
}));
const done = runs.filter(Boolean);
for (const bug of Object.keys(spec.bugs ?? {})) console.log(`${bug}: caught ${done.filter(r => r.caught[bug]).length}/${done.length}`);
for (const fp of Object.keys(spec.falsePositives ?? {})) console.log(`${fp}: false positive raised ${done.filter(r => r.caught[fp]).length}/${done.length} (want 0)`);
console.log(`median time ${done.map(r => r.seconds).sort((a, b) => a - b)[Math.floor(done.length / 2)] ?? "-"}s, ${runs.length - done.length} failed`);
