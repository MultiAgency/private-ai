// Measures the reviewer on pull requests whose bugs are known: each case pins a
// commit, the description as it stood then, and the bugs as yes/no questions.
// It runs the same reviewChange the Action runs, several times in parallel,
// and reports how often each bug was caught. Nothing is posted.
//
// Usage: node eval/run.mjs [--case eval/cases/x.json] [--runs 4]
// Env: NEARAI_API_KEY, GITHUB_TOKEN.
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

console.log(`${spec.name}: ${values.runs} runs`);
const runs = await Promise.all(Array.from({ length: Number(values.runs) }, async (_, i) => {
  const head = unpack(tarball);
  const started = Date.now();
  try {
    const { review, turns } = await reviewChange({
      client, model, publicKey, pr, files: compare.files, rubric, root: head.root,
      maxTurns: 30,
    });
    const text = [review.summary, ...review.findings.map(f => `${f.path}:${f.line} ${f.pass}, ${f.severity}: ${f.body}`)].join("\n\n");
    const caught = await judge({ client, model, publicKey, bugs: spec.bugs, text });
    const seconds = Math.round((Date.now() - started) / 1000);
    console.log(`run ${i}: ${seconds}s, ${turns.length} signed turns, ${review.findings.length} findings, ` +
      Object.entries(caught).map(([bug, yes]) => `${bug} ${yes ? "CAUGHT" : "missed"}`).join(", "));
    return { seconds, caught };
  } catch (error) {
    console.log(`run ${i}: failed: ${error.message}`);
    return null;
  } finally {
    head.remove();
  }
}));
const done = runs.filter(Boolean);
for (const bug of Object.keys(spec.bugs)) console.log(`${bug}: caught ${done.filter(r => r.caught[bug]).length}/${done.length}`);
console.log(`median time ${done.map(r => r.seconds).sort((a, b) => a - b)[Math.floor(done.length / 2)] ?? "-"}s, ${runs.length - done.length} failed`);
