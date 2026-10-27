# Private Investigator

**AI code review that proves your code stayed private.** It reviews your pull
requests inside hardware-sealed enclaves, so nobody sees your code, us
included, and every review comes with a receipt you can check yourself.

**[Install on GitHub](https://github.com/apps/private-investigator/installations/new)**
· [See a real review](https://multiagency.github.io/private-ai/#sample)
· [Check a receipt](https://multiagency.github.io/private-ai/#check)

A second pair of private eyes on your pull requests. (Say the repo's name out loud.)

## What you get

When a pull request opens, a check named *Private Investigator* appears within
seconds. A few minutes later a review lands: findings on changed lines as
inline comments, with a one-click suggested fix when the fix is confined to the
lines it quotes, the rest in the review body, what the reviewer traced, and at
the end what was verified and a link to the review's receipt. The [page](https://multiagency.github.io/private-ai/#sample)
shows a real one.

## Why it's private

- **Sealed hardware.** Your code is read only inside attested enclaves (Intel
  TDX, with NVIDIA confidential GPUs for the model), and sent to the model
  end-to-end encrypted. The servers in between relay only ciphertext.
- **Signed answers.** Every reply the review uses is signed by the model's
  enclave, over the exact request and response.
- **A receipt anyone can check.** It records the attestations and signatures,
  and holds hashes, never your code. The page re-checks it in your browser.

The details, and the limits of the proof, are in [What a run proves](#what-a-run-proves).

## How good it is

It is a second opinion, not a sign-off, and every review says so.
`npm run eval` measures it on pull requests whose bugs are known, with the
same review the App and the Action run:

- **Planted bugs** (a dropped auth check, an off-by-one, an XSS sink, a logged
  secret, a cross-file break, a swallowed error, a race): the App and the
  Action each caught every one, in 4 runs of 4. These cases live in a private
  repository for now, and the App's runs used a longer reply limit than the
  hosted App's 4,096 tokens; the eval now runs it as hosted.
- **False positives:** none, in 8 runs on a clean pull request and on one
  where an earlier review raised a known false positive.
- **Real bugs:** it misses regressions that span files in money and permission
  paths. On [`near-agencies#94`](eval/cases/near-agencies-94.md), two such
  bugs that Claude's review caught, it found one in 1 run of 4 and the other
  in none. Every configuration tried so far misses them: more reasoning, the
  full changed files, an invariants prompt, a deep question-driven pass, and
  tracing each changed function's callers.

New cases and models are measured before any claim here changes. React 👍 or
👎 on a finding: that is how it is measured on real code.

## Review a commit or range without a PR

The CLI and GitHub Action also accept explicit commit reviews. The hosted App
still uses `/review` on PRs; it does not review standalone commits yet.

```sh
node review/review.mjs --repo owner/repo --commit COMMIT_SHA
node review/review.mjs --repo owner/repo --base BASE_REF --head HEAD_REF
```

Use `GITHUB_TOKEN` and `NEARAI_API_KEY` as for PR reviews. Posting needs
`contents: read` and `checks: write` with an installation token (including the
workflow's `github.token`). Findings and the receipt hash appear in an
informational Private Investigator check on the resolved head SHA. The receipt
records the repository and exact base/head SHAs. A running check is created
before model credits are spent; a failed review marks it as failed. A completed
review is neutral, even when findings exist: it is informational.

`--dry-run` previews the check without publishing and works with a read-only
token. It still runs the model review and spends model credits.
The complete check report is saved as `private-review.json` before publishing
or checking GitHub's output-size limit. `--review path.json` chooses another
path, including for dry-runs. This file contains findings and may include code;
it is separate from the receipt, which contains hashes rather than findings.
The Action retains it as a separate, uniquely named `private-review.<id>.json` report artifact even if publishing fails. Each invocation uses its own output directory, so a failed invocation cannot reuse an earlier report or receipt. CLI filenames remain unchanged.
An oversized report is saved in full and the check fails; no partial findings
are published. With PR reviews, `--review` also saves the report when supplied.
`--receipt path.json` selects the receipt file. Ordinary user/OAuth tokens cannot
publish checks; for local use, choose a GitHub App installation token or dry-run.

A single commit is compared to its first parent, including merge commits.
Ranges require the base to be an ancestor of the head; resolve a merge base
explicitly for diverged branches. Root commits and comparisons reaching GitHub's
300-file limit are refused; empty ranges stop without spending model credits.
Rubric files come from the resolved base revision.

For a manual Action workflow, use explicit inputs (replace the pin with the
feature's released commit SHA):

```yaml
name: Review commit range
on:
  workflow_dispatch:
    inputs:
      base:
        description: Ancestor revision
        required: true
      head:
        description: Head revision
        required: true
permissions:
  contents: read
  checks: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: MultiAgency/private-ai/review@<commit sha>
        with:
          nearai-api-key: ${{ secrets.NEARAI_API_KEY }}
          base: ${{ inputs.base }}
          head: ${{ inputs.head }}
```

Alternatively pass `commit:` alone. Explicit commit/range inputs take precedence
over the event's PR default. Explicitly combining them with `pr:` is rejected.
With no commit/range inputs, PR and `/review` comment events keep reviewing the
PR that triggered the workflow.
Automatic push reviews are not enabled by this example. Existing PR re-reviews
continue to check earlier findings and report those still open.

## Two ways to run it

### The GitHub App (zero setup)

[Install it](https://github.com/apps/private-investigator/installations/new)
and pick the repositories. Reviews are opt-in: someone with write access
comments `/review` on the pull request, or presses Re-run on its check. Opening
or pushing alone does not start a review. New installations get a 30-day trial
with 40 reviews; each check says how many reviews and days are left. When the
trial ends, the check points at the upgrade page. A shared monthly pool still
caps total free usage across all installations.

- **Where your code goes:** an attested OutLayer enclave fetches it from GitHub
  with the App's token and sends it end-to-end encrypted to the attested NEAR
  AI model. Each step of the review is an OutLayer run whose attestation binds
  what it returned, and nothing that leaves a run names your repository or
  holds your code.
- **The receipt** is published to OutLayer's public storage. It commits to your
  pull request with a salt that only the review's link carries, so the public
  receipt does not name your repository; the link opens and checks it.
- **What its operators can see:** GitHub's event notices (titles,
  descriptions, who pushed) pass through the relay, which forwards only ids and
  holds them only while a review runs, plus review counts per installation and
  when steps run. Never code, never the review.
- **What it keeps:** a review's working state is sealed in the enclave's
  storage and deleted when the review finishes or fails. What stays is the
  review on your pull request, the public receipt (with its count of new
  findings), the installation's trial (start time and review count), the shared
  monthly free-pool count, and a sealed marker per request (a hash of its ids,
  and when it ran) that stops a repeated delivery from reviewing twice.
  Uninstalling stops reviews; nothing else holds your code.
- **Who can start a review:** a `/review` comment (write access) or Re-run on
  the check, through our relay. The relay drops a `/review` from someone with
  no history in the repository; the enclave checks the rest on GitHub.

### The GitHub Action (your own runner, your own key)

Runs on your GitHub runner, which already has your code, with your own NEAR AI
Cloud key, so no enclave of ours touches it. [The page](https://multiagency.github.io/private-ai/#setup)
writes the workflow for a repository, pinned to the latest commit. By hand: add
a workflow, and a NEAR AI Cloud API key as the `NEARAI_API_KEY` secret.
The workflow reviews new commits and accepts `/review` comments from someone
with write access. It must be on the default branch for comment events to run.

```yaml
name: private-review

# Private AI review: the model reads this pull request only inside a NEAR AI
# Cloud enclave, end-to-end encrypted. See https://github.com/MultiAgency/private-ai
on:
  pull_request:
    types: [opened, synchronize, ready_for_review, reopened]
  issue_comment:
    types: [created]
  # Run by hand (Actions tab, Run workflow) to check the setup: no code is read.
  workflow_dispatch:

jobs:
  # A refused comment cannot load the model key or cancel an ongoing review.
  gate:
    if: >-
      github.event_name == 'workflow_dispatch'
      || (github.event_name == 'pull_request'
        && github.event.pull_request.head.repo.full_name == github.repository
        && !github.event.pull_request.draft)
      || (github.event_name == 'issue_comment'
        && github.event.issue.pull_request
        && startsWith(github.event.comment.body, '/review')
        && contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR"]'), github.event.comment.author_association))
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    outputs:
      allowed: ${{ steps.gate.outputs.allowed }}
    steps:
      - id: gate
        uses: MultiAgency/private-ai/review/gate@<commit sha>
        with:
          allow-forks: "false"
  review:
    needs: gate
    if: needs.gate.outputs.allowed == 'true'
    runs-on: ubuntu-latest
    concurrency:
      group: private-review-${{ github.event.pull_request.number || github.event.issue.number || github.run_id }}
      cancel-in-progress: true
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: MultiAgency/private-ai/review@<commit sha>
        with:
          nearai-api-key: ${{ secrets.NEARAI_API_KEY }}
```

The Action uploads each invocation’s receipt as a uniquely named
`private-review.<id>-receipt.json` artifact,
which downloads as that file, ready for the page's checker. It names the pull
request and commits it reviewed; what ties it to the review is the hash the
review quotes, so check that the two match.

**Existing setups.** Older generated workflows only listen for `/review` when
fork reviews are enabled. To migrate:

1. Replace the complete workflow with the example above, or regenerate it with
   the setup page. Adding `issue_comment` alone leaves the old job condition in
   place, which can still skip comment-triggered reviews.
2. Replace `<commit sha>` in both `uses` lines with the same 40-character commit
   containing this fix. Keep the separate gate job, its `pull-requests: read`
   permission, and the explicit `allow-forks` setting. The existing
   `NEARAI_API_KEY` secret needs no change.
3. Merge the workflow into the repository's default branch. On an open,
   non-draft PR, comment `/review` as someone with write access. The gate should
   pass, followed by a review and a receipt artifact. Fork PRs require
   `allow-forks: "true"`; read-only commenters cannot start a review.

**Forks.** Pull requests from forks get no secrets on their pull-request events.
To accept authorized `/review` comments on them, tick the fork option on
[the page](https://multiagency.github.io/private-ai/#setup), or set
`allow-forks: "true"` on the separate [`review/gate`](review/gate/action.yml) job.
The gate checks the commenter's effective repository permission. A
refused comment never starts the review job, so it never loads the key and
never cancels a review in progress through the job's concurrency group. The
review Action repeats the check for workflows without the gate.

**Choosing a model.** The `model` input takes any NEAR AI Cloud model that runs
in NEAR's own enclaves. Before any code is sent, the review checks the model
with the attestation checks below. If it fails, the review stops. To list the
models that pass today:

```sh
NEARAI_API_KEY=… npm run models
```

A model passes when its machine is fully patched (TCB `UpToDate`).
`allow-unpatched-model: "true"` also accepts a model whose Intel platform
update is pending, which is the Qwen models today, but never a revoked one.
That is a weaker guarantee, so the review and the receipt both state it, and a
receipt is re-checked under the policy it records. Models NEAR AI Cloud can't
attest, such as those served through third parties, can't be chosen. The App
uses `z-ai/glm-5.3-flash`.

**Anonymous mode.** `anonymous: "true"` trades the proof for a stronger
model: any NEAR AI Cloud model, including ones that run only at their provider,
outside an enclave, such as `anthropic/claude-sonnet-5-5` or `openai/gpt-5.5`.
NEAR AI Cloud relays each request from its own account, so the provider doesn't
see whose it is. But the code goes unencrypted, the replies are unsigned, and
there is no attestation or receipt: nothing proves where the code was read or
whether it was kept. Every review says so. The Action only; the App always
runs private.

**Locally,** without posting:

```sh
npm ci
GITHUB_TOKEN=… NEARAI_API_KEY=… node review/review.mjs --repo owner/name --pr 12 --dry-run
```

### What both review

The review follows `REVIEW.md` and `AGENTS.md` from the pull request's base
commit (`rubric:` names other files in the Action), or a default Bugs and
Security pass when neither exists. The model reads the diff, and the head
commit through read-only tools (list, read, search). It runs nothing, and no
path leaves the commit. Lockfiles, vendored and generated files are listed but
their diff is left out. Both run the same review,
[`review/review.json`](review/review.json):

1. **Review passes** (3 by default) trace each changed function through its
   callers and failure paths, and report findings that each quote the code
   they are about. Their findings are merged once each, by file and title.
2. **A verify pass** fact-checks the new findings against the code in its own
   signed loop. It removes only findings the code proves wrong, or that repeat
   another; concurrency, memory-safety and compatibility findings are removed
   only as duplicates. If it does not finish, the findings are posted, marked
   as not double-checked. Its turns are signed and in the receipt like the
   others. `verify: "false"` (Action) or `VERIFY=false` (CLI) skips it.

Model-written text cannot open a suggestion block or a hidden HTML comment in
what is posted.

## What a run proves

Before any data is sent, a run checks NEAR AI Cloud's attestation report for a fresh nonce:

- **Model enclave:** the TDX quote verifies against Intel's collateral with TCB
  status `UpToDate`, debug mode off. The quote binds the enclave's signing key
  and our nonce. Its configuration measurement matches the attested compose
  file, and its event log replays to RTMR3. NVIDIA's attestation service
  approves its GPUs for the same nonce, in a verdict NVIDIA signs. The receipt
  keeps that verdict, and the NVIDIA key that signed it with its certificate
  chain: NVIDIA rotates its keys within days, so the key counts as NVIDIA's
  when its certificate was issued by NVIDIA's attestation intermediate (pinned
  in `core/attest.mjs`) and was valid when the verdict was signed. Receipts
  written before they kept the key are served by an archive of NVIDIA's keys,
  `core/nvidia-keys.json` (`npm run nvidia-keys`), held to the same check.
- **Gateway enclave:** the same quote checks, except that a pending platform
  patch (`OutOfDate` and the like) is allowed and `Revoked` is not. Under
  end-to-end encryption the gateway relays only ciphertext.

Then every request is end-to-end encrypted to the model enclave's key, using
NEAR AI Cloud's E2EE v2 with all fields covered. That includes tool definitions
and tool calls, so the gateway sees roles, ids and token counts but no content.
Each reply is used only after the model enclave's signature over the exact
request and response bytes checks out. If any check fails, the run stops.

**What it does not prove:**

- **What happens on the machine that runs the service.** The Action runs on
  the client's own runner, which already has their code; this repository is
  public so anyone can read what it does. The App runs in an attested OutLayer
  enclave whose receipt names the exact build. Each release is recorded with
  its commit in [`app/builds.json`](app/builds.json) before it runs, and the
  checker accepts only recorded builds of our project. A recorded build
  rebuilds bit for bit from its commit in a pinned container (`app/build.sh`,
  with Docker), and CI rebuilds each one when it is recorded
  (`app/verify-builds.sh`).
- **Which model instance answered.** Instances of a model share one signing
  key, so the signature proves an attested enclave answered, not which one
  (see NEAR's [verification notes](https://docs.near.ai/cloud/verification/cloud-api/model-attestations)).
- **Which image the model enclave runs, and what it does.** The check proves a
  production Intel TDX enclave holds the signing key, and shows its compose
  hash; it does not compare its measurements with NEAR's published
  [compose files](https://github.com/nearai/cvm-compose-files), and auditing
  those images is a separate step. NVIDIA's verdict is tied to that enclave
  by the shared nonce, not by the quote itself.

### Verify a receipt

Drop it on [the page](https://multiagency.github.io/private-ai/#check), or:

```sh
git clone https://github.com/MultiAgency/private-ai && cd private-ai && npm ci
node core/verify.mjs private-review-receipt.json
```

Both run [`verifyReceipt`](core/receipt.mjs). It re-runs the attestation checks
on the recorded report against current Intel collateral, and checks NVIDIA's
recorded verdict against the NVIDIA key that signed it, back to NVIDIA's pinned
intermediate. It also checks every response
signature against the attested model key. The receipt holds hashes of the
encrypted requests and responses, not the bytes, so it carries none of the
reviewed code.

## This repository

Private Investigator is the first service of MultiAgency's private AI: services
that work on private data with AI, and prove where the data went.

- [`review/`](review/): the GitHub Action, and the review both paths run.
- [`app/`](app/): the GitHub App, in Rust, run on [OutLayer](https://outlayer.ai);
  [`relay/`](relay/) is its webhook relay.
- [`core/`](core/): what every service shares, in Node and in the browser alike.
- [`site/`](site/): [the page](https://multiagency.github.io/private-ai/), which
  sets a repository up, shows a real review, and checks receipts in the browser.
- [`eval/`](eval/): the quality measurements.

Questions and bugs: [open an issue](https://github.com/MultiAgency/private-ai/issues).

### Development

`npm test` runs offline. It uses a real attestation report recorded with its
Intel collateral and NVIDIA's verdict, a real signed turn, the page's sample
receipt, and a stand-in enclave for the loop.

`npm run sample` refreshes the page's sample: a dry-run review of
near-agencies#78 saved as `site/sample-review.json`, its receipt, and the Intel
collateral and NVIDIA key the tests check that receipt with. It needs
`GITHUB_TOKEN` and `NEARAI_API_KEY`.

`npm run site` builds the page into `_site/`, with the sample review rendered
in. esbuild bundles `site/app.js` with the lockfile's packages, so the browser
checker loads no code from a CDN. The `pages` workflow publishes it on every
push to `main`.
