import assert from "node:assert/strict";
import test from "node:test";

import { checkSubmission, commentableLines, renderReview, reviewStarter, userPrompt } from "../review/review.mjs";

const files = [{
  filename: "src/add.js",
  status: "modified",
  additions: 2,
  deletions: 1,
  patch: "@@ -1,3 +1,4 @@\n context\n-old\n+new\n+added\n tail\n@@ -20,2 +21,2 @@\n x\n+y",
}];

test("comments may sit on added and context lines of the new file only", () => {
  assert.deepEqual([...commentableLines(files)], [
    "src/add.js:1", "src/add.js:2", "src/add.js:3", "src/add.js:4", "src/add.js:21", "src/add.js:22",
  ]);
});

test("findings on changed lines go inline; the rest, and the proof, go in the body", () => {
  const { body, comments } = renderReview({
    review: {
      summary: "Adds a line.",
      findings: [
        { path: "src/add.js", line: 3, pass: "Bugs", severity: "Important", body: "Wrong value." },
        { path: "src/other.js", line: 9, pass: "Security", severity: "Nit", body: "Unrelated." },
      ],
    },
    turns: [{}, {}],
    attestation: {
      gateway: { tcb: "OutOfDate" },
      model: { tcb: "UpToDate", composeHash: "c".repeat(64), signer: "5".repeat(64) },
    },
    model: "z-ai/glm-5.3-flash",
    receiptSha256: "r".repeat(64),
    commentable: commentableLines(files),
  });

  assert.deepEqual(comments, [{ path: "src/add.js", line: 3, side: "RIGHT", body: "**Bugs, Important:** Wrong value." }]);
  assert.match(body, /^\*\*Private review\*\* \(Bugs, Important: 1 · Security, Nit: 1\)/);
  assert.match(body, /- `src\/other.js:9` \*\*Security, Nit:\*\* Unrelated\./);
  assert.match(body, /- \*\*Model:\*\* `z-ai\/glm-5.3-flash` in an Intel TDX enclave .* TCB UpToDate, debug off; it binds signing key `5{64}`/);
  assert.match(body, /- \*\*GPUs:\*\* NVIDIA's signed verdict approves them for the same nonce\./);
  assert.match(body, /- \*\*Gateway:\*\* Quote verified, TCB OutOfDate\./);
  assert.match(body, /- \*\*Signed:\*\* 2 of 2 responses signed by the model enclave's key/);
});

test("a diff too large for the prompt is left for the model to read", () => {
  const pr = { number: 7, title: "t", body: "", base: { ref: "staging", sha: "b" }, head: { ref: "f", sha: "h" } };
  const huge = [{ ...files[0], patch: "+x\n".repeat(10_000) }];
  assert.match(userPrompt(pr, huge), /diff too large to include: read the file/);
  assert.match(userPrompt(pr, files), /```diff\n@@ -1,3 \+1,4 @@/);
});

test("a submission whose findings miss a field goes back to the model, naming what it sent", () => {
  const finding = { path: "a.js", line: 3, pass: "Bugs", severity: "Important", body: "x" };
  assert.equal(checkSubmission({ summary: "s", findings: [finding] }), undefined);
  assert.equal(checkSubmission({ summary: "s", findings: [] }), undefined);
  assert.equal(
    checkSubmission({ summary: "s", findings: [finding, { file: "a.js", line: 3, pass: "Bugs", severity: "Nit", body: "x" }] }),
    "finding 2 needs path (string), line (integer), pass, severity and body; it has file, line, pass, severity, body",
  );
  assert.match(checkSubmission({ summary: "s", findings: [{ ...finding, line: "3" }] }), /^finding 1 needs/);
  assert.match(checkSubmission({ findings: [] }), /needs a summary/);
});

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
