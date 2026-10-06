import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { checkSubmission, commentableLines, earlierFindings, mergeFindings, renderReview, systemPrompt, userPrompt } from "../review/review.mjs";

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
  assert.match(body, /^\*\*Private Investigator\*\* \(Bugs, Important: 1 · Security, Nit: 1\)/);
  assert.match(body, /_An AI second opinion, not a sign-off: it can miss regressions that span files/);
  assert.match(body, /Read only inside an attested NEAR AI enclave, end-to-end encrypted, with every reply signed by it\. \[Check the receipt\]\(https:\/\/multiagency\.github\.io\/private-ai\/#check\)\.\n\n<details><summary>What was verified<\/summary>/);
  assert.match(body, /- `src\/other.js:9` \*\*Security, Nit:\*\* Unrelated\./);
  assert.match(body, /- \*\*Model:\*\* `z-ai\/glm-5.3-flash` in an Intel TDX enclave .* TCB UpToDate, debug off; it binds signing key `5{64}`/);
  assert.match(body, /- \*\*GPUs:\*\* NVIDIA's signed verdict approves them for the same nonce\./);
  assert.match(body, /- \*\*Gateway:\*\* Quote verified, TCB OutOfDate \(an Intel platform update is pending, which the check allows for the gateway only\)\./);
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

test("a re-review sees only its own earlier findings, once each, never one someone else posts under its name", async () => {
  const gh = {
    reviews: async () => [
      { id: 1, user: { login: "github-actions[bot]" }, body: "**Private review** (Bugs, Nit: 1)\n\n..." },
      { id: 3, user: { login: "private-investigator[bot]" }, body: "**Private Investigator** (no new findings)\n\n..." },
      { id: 2, user: { login: "github-actions[bot]" }, body: "Review against REVIEW.md: 1 finding" },
      { id: 4, user: { login: "pr-author" }, body: "**Private Investigator** (no new findings)\n\n..." },
    ],
    reviewComments: async () => [
      { pull_request_review_id: 1, path: "a.js", body: "**Bugs, Nit:** amount 0 hides the label" },
      { pull_request_review_id: 1, path: "a.js", body: "**Bugs, Nit:** amount 0 hides the label" },
      { pull_request_review_id: 2, path: "b.js", body: "Bugs, Important: someone else's" },
      { pull_request_review_id: 3, path: "d.js", body: "**Bugs, Nit:** under the new name" },
      { pull_request_review_id: 4, path: "e.js", body: "**Bugs, Important:** planted, so a real finding is marked earlier and hidden" },
      { pull_request_review_id: null, path: "c.js", body: "a person's comment" },
    ],
  };
  const earlier = await earlierFindings(gh, 7);
  assert.deepEqual(earlier, [
    { path: "a.js", body: "**Bugs, Nit:** amount 0 hides the label" },
    { path: "d.js", body: "**Bugs, Nit:** under the new name" },
  ]);

  const pr = { number: 7, title: "t", body: "", base: { ref: "staging", sha: "b" }, head: { ref: "f", sha: "h" } };
  assert.match(userPrompt(pr, files, earlier), /## Your earlier findings on this pull request\n\n- `a\.js`: \*\*Bugs, Nit:\*\* amount 0 hides the label\n- `d\.js`: \*\*Bugs, Nit:\*\* under the new name$/);
  assert.doesNotMatch(userPrompt(pr, files), /earlier findings/);
  assert.deepEqual(await earlierFindings({ reviews: async () => [], reviewComments: async () => assert.fail("not needed") }, 7), []);
});

test("findings marked earlier are counted, not posted again", () => {
  const { body, comments } = renderReview({
    review: {
      summary: "s",
      findings: [
        { path: "src/add.js", line: 3, pass: "Bugs", severity: "Important", body: "new" },
        { path: "src/add.js", line: 4, pass: "Bugs", severity: "Nit", body: "old", earlier: true },
        { path: "src/other.js", line: 9, pass: "Bugs", severity: "Nit", body: "old too", earlier: true },
      ],
    },
    turns: [{}],
    attestation: { gateway: { tcb: "UpToDate" }, model: { tcb: "UpToDate", composeHash: "c", signer: "5" } },
    model: "m",
    receiptSha256: "r",
    commentable: commentableLines(files),
  });
  assert.deepEqual(comments.map(c => c.body), ["**Bugs, Important:** new"]);
  assert.match(body, /^\*\*Private Investigator\*\* \(Bugs, Important: 1 · 2 still open\)/);
  assert.match(body, /\n\n2 earlier findings are still open, and not posted again\.\n\n/);
  assert.doesNotMatch(body, /old too/);
});

test("a re-review with only earlier findings says none are new, not that there are none", () => {
  const { body } = renderReview({
    review: { summary: "s", findings: [{ path: "src/add.js", line: 4, pass: "Bugs", severity: "Nit", body: "old", earlier: true }] },
    turns: [{}],
    attestation: { gateway: { tcb: "UpToDate" }, model: { tcb: "UpToDate", composeHash: "c", signer: "5" } },
    model: "m",
    receiptSha256: "r",
    commentable: commentableLines(files),
  });
  assert.match(body, /^\*\*Private Investigator\*\* \(no new findings · 1 still open\)/);
});

test("every review asks for 👍 or 👎 on its findings", () => {
  const { body } = renderReview({
    review: { summary: "s", findings: [] },
    turns: [{}],
    attestation: { gateway: { tcb: "UpToDate" }, model: { tcb: "UpToDate", composeHash: "c", signer: "5" } },
    model: "m",
    receiptSha256: "r",
    commentable: new Set(),
  });
  assert.match(body, /React 👍 or 👎 on it: that is how this reviewer is measured and improved/);
});

test("passes' findings merge one per line, the first pass's wording kept", () => {
  const a = { path: "x.js", line: 1, pass: "Bugs", severity: "Nit", body: "first" };
  const b = { path: "x.js", line: 1, pass: "Bugs", severity: "Important", body: "second" };
  const c = { path: "x.js", line: 2, pass: "Bugs", severity: "Important", body: "only in pass 2" };
  assert.deepEqual(mergeFindings([[a], [b, c], []]), [a, c]);
});

test("a review on a model with a pending platform update says the policy allowed it", () => {
  const { body } = renderReview({
    review: { summary: "s", findings: [] },
    turns: [{}],
    attestation: { gateway: { tcb: "UpToDate" }, model: { tcb: "OutOfDate", composeHash: "c", signer: "5" } },
    model: "Qwen/Qwen3.8-27B",
    receiptSha256: "r",
    commentable: new Set(),
  });
  assert.match(body, /TCB OutOfDate \(an Intel platform update is pending, which this repository's policy allows for the model\)/);
});

test("the golden case the hosted App must match (app/tests/review.rs)", () => {
  const c = JSON.parse(readFileSync(new URL("fixtures/review-case.json", import.meta.url)));
  assert.equal(systemPrompt(c.rubric), c.system_prompt);
  assert.equal(userPrompt(c.pr, c.files, c.earlier), c.user_prompt);
  assert.deepEqual([...commentableLines(c.files)].sort(), c.commentable);
  for (const [submission, problem] of c.submissions) assert.equal(checkSubmission(submission) ?? null, problem);
  const attestation = tcb => ({ model: { tcb, signer: "5a02".padEnd(64, "0"), composeHash: "945b".padEnd(64, "0") }, gateway: { tcb: "OutOfDate" } });
  for (const r of c.renders) {
    assert.deepEqual(renderReview({ review: r.review, turns: Array(r.turns).fill({}), attestation: attestation(r.tcb), model: "z-ai/glm-5.3-flash", receiptSha256: "ab".repeat(32), runUrl: r.run_url ?? undefined, commentable: new Set(c.commentable) }), r.expected);
  }
});
