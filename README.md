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
inline comments, the rest in the review body, and at the end what was verified
and a link to the review's receipt. The [page](https://multiagency.github.io/private-ai/#sample)
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

## Two ways to run it

### The GitHub App (zero setup)

[Install it](https://github.com/apps/private-investigator/installations/new)
and pick the repositories. It reviews a pull request when it opens, reopens or
leaves draft, and again when someone with write access comments `/review` or
presses Re-run on its check. Free for 10 reviews per installation a month,
while the free tier's monthly pool lasts.

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
  findings), the monthly count for your installation, and a sealed marker per
  request (a hash of its ids, and when it ran) that stops a repeated delivery
  from reviewing twice. Uninstalling stops reviews; nothing else holds your code.
- **Who can start a review:** GitHub's events, through our relay. A `/review`
  needs write access to the repository; the relay drops one from someone with
  no history there, and the enclave checks the rest on GitHub.

### The GitHub Action (your own runner, your own key)

Runs on your GitHub runner, which already has your code, with your own NEAR AI
Cloud key, so no enclave of ours touches it. [The page](https://multiagency.github.io/private-ai/#setup)
writes the workflow for a repository, pinned to the latest commit. By hand: add
a workflow, and a NEAR AI Cloud API key as the `NEARAI_API_KEY` secret.

```yaml
name: private-review
on:
  pull_request:
    types: [opened, synchronize, ready_for_review, reopened]
jobs:
  review:
    if: ${{ !github.event.pull_request.draft }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: MultiAgency/private-ai/review@<commit sha>
        with:
          nearai-api-key: ${{ secrets.NEARAI_API_KEY }}
```

The receipt is uploaded as the run's `private-review-receipt.json` artifact,
which downloads as that file, ready for the page's checker. It names the pull
request and commits it reviewed; what ties it to the review is the hash the
review quotes, so check that the two match.

**Forks.** Pull requests from forks get no secrets, so a `/review` comment
starts their review, from someone with write access to the repository. Put
[`review/gate`](review/gate/action.yml) in a job of its own ahead of the review
job, as [the page](https://multiagency.github.io/private-ai/#setup) writes it
when you tick the fork option. The gate looks up the commenter's role. A
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
path leaves the commit. Both run the same review,
[`review/review.json`](review/review.json).

## What a run proves

Before any data is sent, a run checks NEAR AI Cloud's attestation report for a fresh nonce:

- **Model enclave:** the TDX quote verifies against Intel's collateral with TCB
  status `UpToDate`, debug mode off. The quote binds the enclave's signing key
  and our nonce. Its configuration measurement matches the attested compose
  file, and its event log replays to RTMR3. NVIDIA's attestation service
  approves its GPUs for the same nonce, in a verdict NVIDIA signs. The receipt
  keeps that verdict.
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
recorded verdict against NVIDIA's published keys. It also checks every response
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
