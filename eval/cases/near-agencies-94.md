Fixes #89

## Plan

A job's tasks may now be **volunteer tasks**: a `terms` amount of `0` coordinates the work but pays nothing. Paid tasks are unchanged — an owner sets an amount of 1 or more exactly as before. The job's buyer may also choose the deposit, within a range the server configures.

- `lib/team.mjs` — `teamProblem` accepts `amount: "0"` (or JSON number `0`); only paid amounts count against the deposit. `isVolunteer(task)` is the one test. `assembleTeam` writes the checklist line as `- [ ] #N — volunteer`.
- `lib/coordinator.mjs` — a volunteer task's claim reply confirms the claim and says nothing about payment; the **Team approved** comment shows `volunteer` where it showed an amount.
- `lib/payouts.mjs` — `payoutProblem` gates a volunteer task on its work alone (closed with a handoff, pinned; a code task still owes its merged pull request) and drops the payee checks for it; `proposePayouts` files proposals for paid tasks only and never reads the treasury for a volunteer-only job; `closeIfPaid` closes a job once its paid tasks are paid, and **Job complete** counts the paid payouts only.
- `lib/engagement-state.mjs` — `stage` treats a volunteer member as holding neither `accepting` nor the close.
- `lib/engagements.mjs`, `server.mjs` — a quote may carry the buyer's chosen deposit `amount`: whole USDC base units within `ENGAGEMENT_DEPOSIT_MIN`..`ENGAGEMENT_DEPOSIT_MAX`, each defaulting to `ENGAGEMENT_DEPOSIT`, which stays the default when no amount is named. The payer check and the deposit watcher read the quote's own amount, as they already did.
- `public/app.js`, `assemble.mjs` — a 0-amount task reads `volunteer` on the status page, the handoff form, the job page and in the assembler's summary; volunteers are left off the deposit strip.

Could break: the money paths. Every paid-task branch keeps its old shape — the new paths trigger only on an amount of 0.

## Verification

- `npm ci`, `npm run check`, `npm test`: 293 tests, 0 failures.
- The new tests fail before the change: with the five touched test files copied onto a detached `origin/staging` checkout, the volunteer assertions fail and three files cannot even load without the new exports (`claimed`, `chosenDeposit`, `stage`) — 8 failures, 32 passes there; 293 passes on this branch.
  - a volunteer task in a draft, counted only if paid — `test/team.test.mjs`
  - a claim reply with no payout line — `test/board.test.mjs`
  - a volunteer-only job closing with no proposals and no treasury reads — `test/payouts.test.mjs`
  - a mixed job paying only its paid tasks — `test/payouts.test.mjs`
  - a quote with a chosen amount, taken within the range and refused outside it — `test/quotes.test.mjs`
- The pre-existing payout, settle, team and quotes tests pass unchanged; paid-task text (`Claimed by @…` payout sentence, `**Payout proposed:**`, `**Paid:**`, `**Job complete.**`) is the same string it was.

