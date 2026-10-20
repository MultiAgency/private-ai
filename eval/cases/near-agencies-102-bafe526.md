Fixes #70.

## Plan

Two coordinators acting at the same moment can each file a Transfer proposal for one task (both read the treasury before either lands a proposal). The proposals are identical — same payee, amount, token and task URL, exactly what `filedProposal` matches — and approving both pays the task twice. This adds the issue's cheap safety net around the approval, leaving the locks and the one-coordinator rule for later:

- `lib/payouts.mjs` — `filedProposal` is now the first of `matchingProposals`, the same predicate over every live proposal. `pendingPayouts` counts those matches for each task whose payout is pending a vote, and reports a problem when a task has more than one: the job page's approval panel already refuses to render any Approve button while `problem` stands, so `public/app.js` needs no change. The problem names every live id and the extra ones to reject.
- `lib/payouts.mjs` — new `flagDuplicateProposals`, called by the payout sweep (`lib/coordinator.mjs`) before the payout gate, so flagging never waits on whatever else holds a job: one comment on the task naming the duplicate proposal ids, asking an approver to reject the extras and approve the recorded proposal alone. It is said once per wording (the sweep reads its own comment back), and a further duplicate changes the ids, so it is named by a fresh comment.
- Recording paid was and stays keyed to the task's recorded proposal (`m.payout.proposal_id`, the first trusted `payout` fence): `recordApprovals` reads only that proposal's vote, so a duplicate is never recorded as paid. A test holds this property.

Volunteer tasks are untouched: they never file a proposal, so they never have a recorded payout, and both the panel check and the flag read only members with one. The treasury is read only for a job with something pending a vote, so a volunteer-only job costs no chain read.

Not done here, per the issue: the locks around payout filing and `/approve`, and dropping AGENTS.md's one-coordinator rule — both wait until the member list moves to shared storage.

## Verification

- `npm ci`, `npm run check`, `npm test`: all pass (321 tests, 0 failures), same commands CI runs.
- The tests the issue lists, each red before its change and green after (`node --test test/payouts.test.mjs` with the roster fixtures):
  - "two matching live proposals hold the job's approval, naming the extra" — `pendingPayouts` reports the problem naming both ids and the extra to reject; failed before `pendingPayouts` counted matches.
  - "two matching live proposals are flagged on their task, once" — over the sweep harness, one flag comment naming proposals 41 and 42 lands on the task and a second sweep adds none; failed before `flagDuplicateProposals` existed.
  - "one matching live proposal draws no flag" and "one live proposal behaves as today" — a single proposal changes nothing, on the panel and on the task.
  - "a duplicate proposal is never the payment that is recorded" — with the recorded proposal 41 voted through while duplicate 42 stands, exactly one `**Paid:**` record lands, naming 41.
- Edge cases covered by the same suite: a dead (`Rejected`) second proposal is no duplicate, and a live proposal paying another task is no duplicate.

## AI review

The ai-review check is failing on its own, an infrastructure problem of the review action rather than this PR: both of its runs here (37231580086 on open, 37232089034 re-triggered with `/review`) die inside `claude-code-action` before producing any review — `Internal error: directory mismatch for directory …/tsconfig.json`, then `result is_error:true` — and another open PR's ai-review fails the same way (run 37231228335). No ai-review findings exist to act on. This PR relies on the `test` check (passing) and its own REVIEW.md self-review above; the posted **Private review** is advisory for the owner.

