import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { commitChange, commitCheck, main, resolveReviewTarget, systemPrompt, userPrompt, validateCommitCheck } from '../review/review.mjs';
import { github } from '../review/github.mjs';
import { sha256 } from '../core/sign.mjs';

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
  assert.throws(() => validateCommitCheck(commitCheck({ base: { sha: base }, head: { sha: head } }, { body: 'x'.repeat(66000), comments: [] })), /output limit/);
});

test('commit prompt adaptation preserves repository instructions verbatim', () => {
  const rubric = 'A pull request touching base branch selection must preserve the pull request policy.';
  const prompt = systemPrompt(rubric, { standalone: true });
  assert.match(prompt, /^You review a GitHub change\./);
  assert.ok(prompt.endsWith(rubric));
});

// Exercise argument/env routing, orchestration, rendering and receipt files.
// Crypto and filesystem isolation have their own tests; no paid model is used.
function workflow(t, ghOverrides = {}, serviceOverrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'commit-workflow-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const events = [], saved = [], inputs = [];
  const files = [{ filename: 'a.js', status: 'modified', additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-old\n+new' }];
  const gh = {
    ...forge(),
    compare: async (b, h) => {
      assert.equal(b, base); assert.equal(h, head);
      return { merge_base_commit: { sha: base }, files };
    },
    text: async (path, ref) => { assert.equal(ref, base); return path === 'REVIEW.md' ? 'Keep pull request rules verbatim.' : null; },
    tarball: async ref => { assert.equal(ref, head); events.push('snapshot'); return 'head snapshot'; },
    check: async body => { events.push('create check'); saved.push(body); return { id: 123 }; },
    updateCheck: async (id, body) => { assert.equal(id, 123); events.push('update check'); saved.push(body); },
    pull: async n => { assert.equal(n, 7); return { number: n, title: 'Example', base: { ref: 'main', sha: base }, head: { ref: 'feature', sha: head } }; },
    files: async () => files,
    reviews: async () => [{ id: 10, user: { login: 'github-actions[bot]' }, body: '**Private Investigator** (one finding)' }],
    reviewComments: async () => [{ pull_request_review_id: 10, path: 'a.js', body: 'Old finding' }],
    review: async (number, body) => { assert.equal(number, 7); events.push('post PR'); saved.push(body); },
    comment: async () => assert.fail('unexpected PR error comment'),
    ...ghOverrides,
  };
  const services = {
    github: () => gh, nearai: () => ({}), log: () => {},
    attest: async () => {
      events.push('attest');
      return {
        evidence: { nonce: 'fixture', report: {}, gpuToken: 'fixture' },
        attestation: { model: { tcb: 'UpToDate', signer: 'fixture signer', composeHash: 'fixture compose' }, gateway: { tcb: 'UpToDate' } },
      };
    },
    unpack: bytes => {
      assert.equal(bytes, 'head snapshot'); events.push('unpack');
      return { root: '/fixture/head', remove: () => events.push('cleanup') };
    },
    reviewChange: async input => {
      events.push('review'); inputs.push(input);
      return { review: { summary: 'Checked the change.', findings: [
        { path: 'a.js', line: 1, pass: 'Bugs', severity: 'Important', body: 'New finding' },
        { path: 'caller.js', line: 12, pass: 'Bugs', severity: 'Important', body: 'Caller finding' },
      ] }, turns: [{ id: 'fixture turn' }] };
    },
    ...serviceOverrides,
  };
  const receiptPath = join(dir, 'receipt.json'), reviewPath = join(dir, 'review.json');
  const env = { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'fixture', NEARAI_API_KEY: 'fixture' };
  return {
    events, saved, inputs, receiptPath, reviewPath, env,
    run: (args = [], extraEnv = {}) => main(['--receipt', receiptPath, '--review', reviewPath, ...args], { ...env, ...extraEnv }, services),
  };
}

test('manual Action range inputs create a check before paid work and update that check', async t => {
  const w = workflow(t);
  await w.run([], { GITHUB_EVENT_NAME: 'workflow_dispatch', REVIEW_BASE: 'main', REVIEW_HEAD: 'feature', GITHUB_RUN_ID: '42' });
  assert.deepEqual(w.events, ['create check', 'snapshot', 'attest', 'unpack', 'review', 'cleanup', 'update check']);
  assert.equal(w.saved[0].head_sha, head);
  assert.equal(w.saved[0].status, 'in_progress');
  const done = w.saved[1];
  assert.equal(done.conclusion, 'neutral');
  assert.match(done.output.summary, /a.js:1/);
  assert.match(done.output.summary, /caller.js:12/);
  const text = readFileSync(w.receiptPath, 'utf8');
  assert.deepEqual(JSON.parse(text).subject, { repository: 'owner/repo', base_sha: base, head_sha: head });
  assert.ok(done.output.summary.includes(sha256(text)));
  assert.match(done.output.summary, /https:\/\/github.com\/owner\/repo\/actions\/runs\/42/);
  assert.deepEqual(w.inputs[0].earlier, []);
  assert.equal(w.inputs[0].root, '/fixture/head');
});

test('commit dry-run previews the real check without any publishing permission', async t => {
  const w = workflow(t, { check: async () => assert.fail('dry-run must not publish'), updateCheck: async () => assert.fail('dry-run must not publish') });
  await w.run(['--commit', 'feature', '--dry-run', '--review', w.reviewPath]);
  const preview = JSON.parse(readFileSync(w.reviewPath, 'utf8'));
  assert.equal(preview.head_sha, head);
  assert.equal(preview.conclusion, 'neutral');
  assert.match(preview.output.summary, /New finding/);
  assert.ok(w.events.includes('cleanup'));
});

test('a token that cannot create checks fails before any model work or snapshot fetch', async t => {
  const w = workflow(t, { check: async () => { throw new Error('GitHub: 403'); } });
  await assert.rejects(w.run(['--commit', 'feature']), /403/);
  assert.deepEqual(w.events, []);
});

test('failed attestation closes the check without sending code to the model', async t => {
  const w = workflow(t, {}, { attest: async () => { throw new Error('bad quote'); } });
  await assert.rejects(w.run(['--commit', 'feature']), /attestation failed, so no code was sent/);
  assert.deepEqual(w.events, ['create check', 'snapshot', 'update check']);
  assert.equal(w.saved.at(-1).conclusion, 'failure');
});

test('model failure cleans up the snapshot and marks the check failed', async t => {
  const w = workflow(t, {}, { reviewChange: async () => { throw new Error('signed loop stopped'); } });
  await assert.rejects(w.run(['--commit', 'feature']), /signed loop stopped/);
  assert.ok(w.events.includes('cleanup'));
  assert.equal(w.saved.at(-1).conclusion, 'failure');
});

test('empty ranges do not spend model credits or create checks', async t => {
  const w = workflow(t, { compare: async () => ({ merge_base_commit: { sha: base }, files: [] }) });
  await assert.rejects(w.run(['--base', 'main', '--head', 'feature']), /No changed files/);
  assert.deepEqual(w.events, []);
});

test('ambiguous and incomplete targets fail before connecting to services', async () => {
  const env = { GITHUB_REPOSITORY: 'owner/repo' };
  const services = { github: () => assert.fail('must validate before connecting'), nearai: () => assert.fail('must validate before connecting') };
  for (const args of [
    ['--commit', head, '--pr', '7'], ['--commit', head, '--base', base],
    ['--base', base], ['--head', head], ['--check', '--commit', head], ['--pr', 'NaN'],
  ]) await assert.rejects(main(args, env, services), /Choose a PR|not both|requires both|cannot be combined|positive integer/);
});

test('existing PR reviews retain earlier findings and PR receipts without checks', async t => {
  const w = workflow(t, { check: async () => assert.fail('PR reviews must not create checks') });
  await w.run(['--pr', '7']);
  assert.equal(w.saved[0].commit_id, head);
  assert.equal(w.saved[0].event, 'COMMENT');
  assert.deepEqual(w.inputs[0].earlier, [{ path: 'a.js', body: 'Old finding' }]);
  assert.deepEqual(JSON.parse(readFileSync(w.receiptPath, 'utf8')).subject, { pull_request: 'owner/repo#7', base_sha: base, head_sha: head });
});

test('REST adapter encodes branch refs and uses the returned check id for updates', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, ...options });
    return Response.json({ id: 321 });
  });
  const gh = github('fixture token', 'owner/repo');
  await gh.commit('feature/a#b');
  await gh.compare('release/a', 'feature/b');
  const created = await gh.check({ name: 'Private Investigator', head_sha: head, status: 'in_progress' });
  await gh.updateCheck(created.id, { status: 'completed', conclusion: 'neutral' });
  assert.ok(calls[0].url.endsWith('/commits/feature%2Fa%23b'));
  assert.ok(calls[1].url.endsWith('/compare/release%2Fa...feature%2Fb'));
  assert.equal(calls[2].method, 'POST');
  assert.ok(calls[3].url.endsWith('/check-runs/321'));
  assert.equal(calls[3].method, 'PATCH');
  assert.equal(JSON.parse(calls[3].body).conclusion, 'neutral');
});

test('historical PR dry-runs retain their sample format and omit earlier findings', async t => {
  const w = workflow(t, {
    compare: async (b, h) => {
      assert.equal(b, 'main'); assert.equal(h, head);
      return { merge_base_commit: { sha: base }, files: [] };
    },
    reviews: async () => assert.fail('historical samples must not load earlier findings'),
    check: async () => assert.fail('historical samples must not create checks'),
  });
  await w.run(['--pr', '7', '--head', head, '--dry-run', '--review', w.reviewPath]);
  const sample = JSON.parse(readFileSync(w.reviewPath, 'utf8'));
  assert.equal(typeof sample.body, 'string');
  assert.ok(Array.isArray(sample.comments));
  assert.equal(sample.output, undefined);
  assert.deepEqual(w.inputs[0].earlier, []);
});

test('oversized reviews preserve every finding and receipt before rejecting publication or preview', async t => {
  for (const dryRun of [false, true]) await t.test(dryRun ? 'dry-run' : 'publishing', async t => {
    const findings = [0, 1, 2].map(i => ({
      path: `file-${i}.js`, line: 1, pass: 'Bugs', severity: 'Important',
      body: `Finding ${i}: ` + 'x'.repeat(24000),
    }));
    const w = workflow(t, {}, { reviewChange: async () => ({
      review: { summary: 'Combined findings from three passes.', findings }, turns: [{ id: 'fixture' }],
    }) });
    await assert.rejects(w.run(['--commit', 'feature', ...(dryRun ? ['--dry-run'] : [])]), /output limit; full report saved/);
    const report = JSON.parse(readFileSync(w.reviewPath, 'utf8'));
    for (const finding of findings) assert.ok(report.output.summary.includes(finding.body));
    assert.ok(report.output.summary.includes(sha256(readFileSync(w.receiptPath, 'utf8'))));
    if (dryRun) assert.equal(w.saved.length, 0, 'dry-runs must not write checks');
    else {
      assert.equal(w.saved.at(-1).conclusion, 'failure');
      assert.match(w.saved.at(-1).output.summary, /complete report and receipt were saved/);
      assert.ok(w.saved.every(check => check.conclusion !== 'neutral'), 'no partial review is published');
    }
  });
});

test('a failed final GitHub write leaves a recoverable complete report', async t => {
  let calls = 0;
  const w = workflow(t, { updateCheck: async () => { calls++; throw new Error('GitHub: 503'); } });
  await assert.rejects(w.run(['--commit', 'feature']), /503/);
  assert.equal(calls, 2, 'publishing and best-effort failure update both attempted');
  const report = JSON.parse(readFileSync(w.reviewPath, 'utf8'));
  assert.match(report.output.summary, /New finding/);
  assert.match(report.output.summary, /Caller finding/);
  assert.ok(report.output.summary.includes(sha256(readFileSync(w.receiptPath, 'utf8'))));
});

test('explicit commit and range targets take precedence over the event PR default', async t => {
  for (const target of [{ REVIEW_COMMIT: 'feature' }, { REVIEW_BASE: 'main', REVIEW_HEAD: 'feature' }]) {
    const w = workflow(t);
    await w.run([], { ...target, PR_NUMBER_DEFAULT: '7', GITHUB_EVENT_NAME: 'pull_request' });
    assert.equal(w.saved[0].head_sha, head);
    assert.equal(w.saved[1].conclusion, 'neutral');
    assert.deepEqual(w.inputs[0].earlier, []);
  }
});

test('PR events and comment events still default to PR reviews when no commit target is supplied', async t => {
  for (const event of ['pull_request', 'issue_comment']) {
    let authorized = 0;
    const w = workflow(t, {
      check: async () => assert.fail('must review the event PR'),
      access: async login => { assert.equal(login, 'dev'); authorized++; return { permission: 'write', role: 'write' }; },
    });
    const extraEnv = { PR_NUMBER_DEFAULT: '7', GITHUB_EVENT_NAME: event };
    if (event === 'issue_comment') {
      const eventPath = `${w.reviewPath}.event`;
      writeFileSync(eventPath, JSON.stringify({
        action: 'created', issue: { number: 7, pull_request: {} },
        comment: { body: '/review', user: { login: 'dev' } },
      }));
      extraEnv.GITHUB_EVENT_PATH = eventPath;
    }
    await w.run([], extraEnv);
    assert.equal(w.saved[0].commit_id, head);
    assert.equal(w.saved[0].event, 'COMMENT');
    assert.equal(authorized, event === 'issue_comment' ? 1 : 0);
  }
});

test('an explicit PR together with a commit still fails even when an event default exists', async t => {
  const w = workflow(t);
  await assert.rejects(w.run([], { REVIEW_COMMIT: 'feature', PR_NUMBER: '8', PR_NUMBER_DEFAULT: '7' }), /Choose a PR/);
  assert.deepEqual(w.events, []);
});

test('cross-repository checks and proof links point to the workflow repository', async t => {
  const w = workflow(t);
  await w.run(['--repo', 'reviewed/repo', '--commit', 'feature'], {
    GITHUB_REPOSITORY: 'runner/repo', GITHUB_SERVER_URL: 'https://github.example', GITHUB_RUN_ID: '42',
  });
  const url = 'https://github.example/runner/repo/actions/runs/42';
  assert.equal(w.saved[0].details_url, url);
  assert.ok(w.saved[1].output.summary.includes(url));
  const report = JSON.parse(readFileSync(w.reviewPath, 'utf8'));
  assert.equal(report.details_url, url);
  assert.equal(JSON.parse(readFileSync(w.receiptPath, 'utf8')).subject.repository, 'reviewed/repo');
});

test('a run id without a workflow repository does not invent an artifact URL', async t => {
  const w = workflow(t);
  await w.run(['--repo', 'reviewed/repo', '--commit', 'feature'], { GITHUB_REPOSITORY: '', GITHUB_RUN_ID: '42' });
  assert.equal(w.saved[0].details_url, undefined);
  assert.doesNotMatch(w.saved[1].output.summary, /actions\/runs\/42/);
});

test('Action distinguishes explicit PRs from event defaults and retains both report artifacts on failure', () => {
  const action = readFileSync(new URL('../review/action.yml', import.meta.url), 'utf8');
  const prInput = action.slice(action.indexOf('  pr:\n'), action.indexOf('  commit:\n'));
  assert.doesNotMatch(prInput, /default:/, 'the event number must not become an explicit conflicting PR');
  assert.match(action, /PR_NUMBER: \$\{\{ inputs.pr \}\}/);
  assert.match(action, /PR_NUMBER_DEFAULT: \$\{\{ github.event.pull_request.number \|\| github.event.issue.number \}\}/);
  assert.match(action, /--receipt "\$REVIEW_RECEIPT_PATH" --review "\$REVIEW_REPORT_PATH"/);
  for (const [output, variable] of [['receipt', 'REVIEW_RECEIPT_PATH'], ['report', 'REVIEW_REPORT_PATH']]) {
    assert.ok(action.includes(variable + ': ${{ steps.review-files.outputs.' + output + ' }}'));
    const path = 'path: ${{ steps.review-files.outputs.' + output + ' }}';
    const upload = action.slice(action.lastIndexOf('- if:', action.indexOf(path)), action.indexOf(path) + path.length);
    assert.ok(upload.includes("always() && steps.review-files.outcome == 'success'"));
    assert.ok(upload.includes(path));
  }
});


test('a report cannot overwrite its receipt', async t => {
  const w = workflow(t);
  await assert.rejects(w.run(['--commit', 'feature', '--review', w.receiptPath]), /paths must be different/);
  assert.deepEqual(w.events, []);
});


test('each Action invocation owns fresh files and unique unarchived artifact names', async t => {
  const action = readFileSync(new URL('../review/action.yml', import.meta.url), 'utf8');
  const setup = action.match(/    - id: review-files\n      shell: bash\n      run: \|\n((?:        .*\n)+)/);
  assert.ok(setup, 'reserve per-invocation outputs before running the reviewer');
  const script = setup[1].split('\n').map(line => line.slice(8)).join('\n');
  const root = mkdtempSync(join(tmpdir(), 'action outputs '));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  function invocation() {
    const output = join(root, `outputs-${counter++}`);
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', script], { env: { ...process.env, RUNNER_TEMP: root, GITHUB_OUTPUT: output }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const paths = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
    assert.ok(paths.receipt && paths.report);
    assert.notEqual(paths.receipt, paths.report);
    return paths;
  }
  let counter = 0;
  const first = invocation(), second = invocation(), third = invocation();
  let fail = false;
  const w = workflow(t, { check: async () => { if (fail) throw new Error('Fixture publishing permission denied'); return { id: 123 }; } });
  const run = paths => w.run(['--commit', 'feature', '--receipt', paths.receipt, '--review', paths.report]);
  await run(first);
  const original = [readFileSync(first.receipt, 'utf8'), readFileSync(first.report, 'utf8')];
  fail = true;
  await assert.rejects(run(second), /Fixture publishing permission denied/);
  assert.equal(existsSync(second.receipt), false);
  assert.equal(existsSync(second.report), false);
  assert.deepEqual([readFileSync(first.receipt, 'utf8'), readFileSync(first.report, 'utf8')], original);
  fail = false;
  await run(third);
  // With archive:false, upload-artifact ignores name: and uses the basename.
  const names = [first, second, third].flatMap(paths => Object.values(paths).map(path => path.split('/').at(-1)));
  assert.equal(new Set(names).size, 6);
});

test('repository setup dispatches do not cancel one another', () => {
  const workflow = readFileSync(new URL('../.github/workflows/private-review.yml', import.meta.url), 'utf8');
  const expression = workflow.match(/group: private-review-\$\{\{ (.+) \}\}/)[1];
  const group = new Function('github', `return (${expression});`);
  const manual = run_id => ({ run_id, event: { pull_request: {}, issue: {} } });
  assert.notEqual(group(manual(1)), group(manual(2)));
  assert.equal(group({ run_id: 1, event: { pull_request: { number: 7 }, issue: {} } }), 7);
});


test('target resolution makes setup, event defaults, explicit targets, and historical PRs distinct', () => {
  const cases = [
    [{ check: true }, {}, { kind: 'setup' }],
    [{}, { GITHUB_EVENT_NAME: 'workflow_dispatch' }, { kind: 'setup' }],
    [{}, { PR_NUMBER_DEFAULT: '7' }, { kind: 'pr', number: 7 }],
    [{ pr: '8' }, { PR_NUMBER_DEFAULT: '7' }, { kind: 'pr', number: 8 }],
    [{ commit: 'feature' }, { PR_NUMBER_DEFAULT: '7' }, { kind: 'commit', commit: 'feature' }],
    [{ base: 'main', head: 'feature' }, { PR_NUMBER_DEFAULT: '7' }, { kind: 'range', base: 'main', head: 'feature' }],
    [{ head: 'historic' }, { PR_NUMBER_DEFAULT: '7' }, { kind: 'pr', number: 7, historicalHead: 'historic' }],
    [{ pr: '8', head: 'historic' }, {}, { kind: 'pr', number: 8, historicalHead: 'historic' }],
    [{}, { REVIEW_BASE: 'main', REVIEW_HEAD: 'feature', PR_NUMBER_DEFAULT: '7' }, { kind: 'range', base: 'main', head: 'feature' }],
  ];
  for (const [values, environment, expected] of cases) assert.deepEqual(resolveReviewTarget(values, environment), expected);
  assert.throws(() => resolveReviewTarget({ head: 'feature' }, {}), /requires both/);
  assert.throws(() => resolveReviewTarget({}, { PR_NUMBER_DEFAULT: 'NaN' }), /positive integer/);
  assert.throws(() => resolveReviewTarget({}, {}), /PR_NUMBER is required/);
});

test('anonymous mode attests nothing, writes no receipt and says the review is unproven', async t => {
  const w = workflow(t);
  await w.run(['--pr', '7'], { ANONYMOUS: 'true' });
  assert.deepEqual(w.events, ['snapshot', 'unpack', 'review', 'cleanup', 'post PR']);
  assert.equal(w.inputs[0].publicKey, undefined);
  assert.equal(existsSync(w.receiptPath), false);
  const posted = w.saved.at(-1);
  assert.match(posted.body, /Anonymous mode: `z-ai\/glm-5\.3-flash` ran at its provider, outside any enclave/);
  assert.doesNotMatch(posted.body, /What was verified|Check the receipt/);
});
