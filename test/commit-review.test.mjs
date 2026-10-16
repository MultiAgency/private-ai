import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commitChange, commitCheck, userPrompt } from '../review/review.mjs';

const base = 'a'.repeat(40), head = 'b'.repeat(40);
function forge(overrides = {}) {
  return {
    commit: async ref => ({ sha: ref === 'main' || ref === base ? base : head, parents: [{ sha: base }], commit: { message: 'Change behavior' } }),
    compare: async (b, h) => {
      assert.equal(b, base); assert.equal(h, head);
      return { merge_base_commit: { sha: base }, files: [{ filename: 'a.js' }] };
    }, ...overrides,
  };
}
test('single commits use the first parent and immutable revisions', async () => {
  const change = await commitChange(forge(), { commit: 'feature' });
  assert.equal(change.base.sha, base);
  assert.equal(change.head.sha, head);
  assert.match(userPrompt(change, change.files), /^Commit range:/);
});
test('ranges resolve both refs before comparing', async () => {
  const change = await commitChange(forge(), { base: 'main', head: 'feature' });
  assert.equal(change.title, `${base}..${head}`);
});
test('invalid and incomplete comparisons stop rather than silently omit changes', async () => {
  await assert.rejects(commitChange(forge(), { commit: head, base }), /not both/);
  await assert.rejects(commitChange(forge(), { base }), /both/);
  await assert.rejects(commitChange(forge({ commit: async () => ({ parents: [] }) }), { commit: head }), /Root commits/);
  await assert.rejects(commitChange(forge({ compare: async () => ({ merge_base_commit: { sha: head }, files: [] }) }), { base, head }), /ancestor/);
  await assert.rejects(commitChange(forge({ compare: async () => ({ merge_base_commit: { sha: base }, files: Array(300).fill({}) }) }), { base, head }), /truncated/);
});
test('commit checks preserve inline findings, receipt, and reviewed revisions without approving', () => {
  const check = commitCheck({ base: { sha: base }, head: { sha: head } }, {
    body: 'Review and receipt hash', comments: [{ path: 'a.js', line: 4, body: 'Important: broken caller' }],
  }, 'https://github.com/o/r/actions/runs/1');
  assert.equal(check.head_sha, head);
  assert.equal(check.conclusion, 'neutral');
  assert.match(check.output.summary, /a.js:4/);
  assert.match(check.output.summary, /receipt hash/);
  assert.throws(() => commitCheck({ base: { sha: base }, head: { sha: head } }, { body: 'x'.repeat(66000), comments: [] }), /output limit/);
});
