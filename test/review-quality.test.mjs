import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifiedEarlier, checkSubmission, checkConsolidation, consolidationPrompt, finalizeReview, mergeFindings, reviewChange } from "../review/review.mjs";

const fixture = JSON.parse(readFileSync(new URL("fixtures/review-quality.json", import.meta.url)));
const finding = fixture.cases[0].candidates[0];

test("invalid categories and severities are rejected for model repair, not silently relabeled", () => {
  for (const fields of [{ pass: "Nit" }, { pass: "bugs" }, { severity: "Critical" }, { earlier: "true" }]) {
    assert.ok(checkSubmission({ summary: "Checked.", findings: [{ ...finding, ...fields }] }));
  }
  assert.match(checkSubmission({ summary: "Checked.", findings: Array(6).fill(finding) }), /at most 5/);
  assert.equal(checkSubmission({ summary: "Checked.", findings: Array(6).fill({ ...finding, severity: "Important" }) }), undefined);
  assert.equal(checkSubmission({ summary: "Checked.", findings: Array(6).fill({ ...finding, earlier: true }) }), undefined);
  assert.match(checkSubmission(null), /summary/);
});

test("exact repeats at one anchor merge at highest severity; other anchors, defects and earlier findings survive", () => {
  const important = { ...finding, line: 37, severity: "Important", body: ` ${finding.body.replaceAll(" ", "\n")} ` };
  const distinct = { ...finding, body: "A different defect on the same line." };
  const earlier = { ...finding, earlier: true };
  assert.deepEqual(mergeFindings([[finding, distinct], [important, earlier]]), [finding, distinct, important, earlier]);
  const sameAnchor = { ...important, line: finding.line };
  assert.deepEqual(mergeFindings([[finding, distinct], [sameAnchor, earlier]]), [sameAnchor, distinct, earlier]);
});

test("shared quality cases consolidate PR21 paraphrases and cap new nits only after grouping", () => {
  for (const c of fixture.cases) assert.deepEqual(finalizeReview(c.candidates, c.decision), c.expected);
});

test("consolidation cannot drop, repeat, invent, cross files, or hide new findings as earlier", () => {
  const candidates = fixture.cases[0].candidates;
  const decision = groups => ({ summary: "Checked.", groups });
  for (const groups of [[], [[0, 1, 2, 3]], [[0, 1, 2, 3, 4, 4]], [[0, 1, 2, 3, 5]], [[0, 1, 2, -1, 4]], [[0, 1, 2, 3.5, 4]], [[], [0, 1, 2, 3, 4]], [[0, 1, 2, 3, 4]]]) {
    assert.ok(checkConsolidation(decision(groups), candidates), JSON.stringify(groups));
    assert.throws(() => finalizeReview(candidates, decision(groups)));
  }
  const crossFile = [finding, { ...finding, path: "other.yml" }];
  assert.match(checkConsolidation(decision([[0, 1]]), crossFile), /one file/);
  const upgrade = [finding, { ...finding, severity: "Important", pass: "Security" }];
  assert.deepEqual(finalizeReview(upgrade, decision([[0, 1]])).findings, [upgrade[1]]);
  assert.equal(checkConsolidation(decision([[0.0]]), [finding]), undefined);
});

test("candidate ids are assigned by the reviewer, not by arbitrary model fields", () => {
  assert.equal(JSON.parse(consolidationPrompt([{ ...finding, id: 999 }]))[0].id, 0);
});

const options = {
  client: {}, model: "fixture", publicKey: "fixture", root: "/unused", maxTurns: 5,
  pr: { number: 21, title: "Review", base: { ref: "main", sha: "a" }, head: { ref: "branch", sha: "b" } },
  files: [], rubric: "Custom repository constraints.",
};

test("all independent candidates reach one signed consolidation loop and all turns enter the receipt", async () => {
  const c = fixture.cases[0];
  const lists = [c.candidates.slice(0, 3), c.candidates.slice(3, 4), c.candidates.slice(4)];
  let calls = 0;
  const result = await reviewChange({ ...options, earlier: c.candidates.filter(f => f.earlier), passes: 3, agent: async input => {
    const index = calls++;
    if (index < 3) return { result: { summary: "Checked.", findings: lists[index] }, turns: [{ id: `pass-${index}` }] };
    assert.equal(input.finish.tool.function.name, "submit_consolidation");
    assert.ok(input.system.includes(options.rubric));
    assert.equal(JSON.parse(input.prompt).length, 5);
    assert.ok(input.finish.check({ summary: "Bad", groups: [[0]] }));
    assert.equal(input.finish.check(c.decision), undefined);
    return { result: c.decision, turns: [{ id: "signed-consolidation" }] };
  } });
  assert.equal(calls, 4);
  assert.deepEqual(result.review, c.expected);
  assert.deepEqual(result.turns.map(t => t.id), ["pass-0", "pass-1", "pass-2", "signed-consolidation"]);
});

test("zero or one unique candidate needs no extra model call", async () => {
  for (const findings of [[], [finding]]) {
    let calls = 0;
    const result = await reviewChange({ ...options, passes: 2, agent: async () => {
      calls++;
      return { result: { summary: "Checked.", findings }, turns: [{ id: `pass-${calls}` }] };
    } });
    assert.equal(calls, 2);
    assert.deepEqual(result.review.findings, findings);
  }
});

 test("conflicting earlier flags cannot repost a verified exact issue or hide a distinct new one", () => {
  const f = { ...finding, severity: "Important" };
  const prior = [{ path: f.path, body: `**Bugs, Important:** ${f.body}` }];
  const normalized = verifiedEarlier([{ ...f, earlier: true }, { ...f, earlier: false }, { ...f, body: "Different new defect", earlier: true }], prior);
  const candidates = mergeFindings([normalized]);
  assert.equal(candidates.length, 2);
  const review = finalizeReview(candidates, { summary: "Checked", groups: [[0], [1]] });
  assert.equal(review.findings.filter(f => !f.earlier).length, 1);
  assert.equal(review.findings[1].body, "Different new defect");
});
