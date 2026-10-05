# MultiAgency private AI

Services that work on private data with AI and prove where the data went. Each
service runs a model inside a [NEAR AI Cloud](https://docs.near.ai/cloud/private-inference)
enclave (Intel TDX with NVIDIA confidential GPUs), encrypts everything to that
enclave's key, and leaves a receipt anyone can re-check.

The first service is **private code review** of pull requests: a GitHub
Action in [`review/`](review/), and a hosted GitHub App in [`app/`](app/) (Rust,
run on [OutLayer](https://outlayer.ai)) with its webhook relay in
[`relay/`](relay/). Both run the same review ([`review/review.json`](review/review.json)).
[`core/`](core/) is what every service shares, and it runs in Node and in the
browser alike. The page at
**[multiagency.github.io/private-ai](https://multiagency.github.io/private-ai/)**
sets a repository up, shows a real review, and checks receipts in the browser.

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
  enclave whose receipt names the exact build; each release is recorded with
  its commit in [`app/builds.json`](app/builds.json) and rebuilds bit for bit
  from it (`app/verify-builds.sh`, run by CI).
- **Which model instance answered.** Instances of a model share one signing
  key, so the signature proves an attested enclave answered, not which one
  (see NEAR's [verification notes](https://docs.near.ai/cloud/verification/cloud-api/model-attestations)).
- **What NEAR's images do.** The receipt records the compose hashes, and
  NEAR publishes the [compose files](https://github.com/nearai/cvm-compose-files)
  they measure. Auditing those images is a separate step.

## Private Investigator: private code review

A second pair of private eyes on your pull requests. (Say the repo's name out loud.)

### The GitHub App

[Install it](https://github.com/apps/private-investigator/installations/new) and
pick the repositories. It reviews a pull request when it opens, reopens or
leaves draft, and again when someone with write access comments `/review` or
presses Re-run on its check. Free for 10 reviews per installation a month.

- **Where your code goes:** an attested OutLayer enclave fetches it from GitHub
  with the App's token, and sends it end-to-end encrypted to the attested NEAR
  AI model. Each step of the review is an OutLayer run whose attestation binds
  what it returned, and nothing that leaves a run names your repository or
  holds your code.
- **The receipt** is published to OutLayer's public storage. It commits to your
  pull request with a salt that only the review's link carries, so the public
  receipt does not name your repository; the link opens and checks it.
- **What its operators can see:** GitHub's event notices (titles, descriptions,
  who pushed) pass through the relay, which forwards only ids and keeps nothing,
  plus review counts per installation and when steps run. Never code, never the
  review.

### The GitHub Action

[The page](https://multiagency.github.io/private-ai/#setup) writes this for a
repository, pinned to the latest commit. By hand: add a workflow, and a NEAR AI
Cloud API key as the `NEARAI_API_KEY` secret.

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

The review follows `REVIEW.md` and `AGENTS.md` from the pull request's base
commit (`rubric:` names other files), or a default Bugs and Security pass when
neither exists. The model reads the diff, and the head commit through
read-only tools (list, read, search). It runs nothing, and no path leaves the
commit. Findings on changed lines become inline comments, and the rest go in
the review body. The body ends with what was verified and the receipt's hash.
The receipt is uploaded as the run's `private-review-receipt.json` artifact, which downloads as that file, ready for the page's checker.

Pull requests from forks get no secrets, so a `/review` comment starts their
review, from someone with write access to the repository. Put
[`review/gate`](review/gate/action.yml) in a job of its own ahead of the review
job, as [the page](https://multiagency.github.io/private-ai/#setup) writes it
when you tick the fork option. The gate looks up the commenter's role. A
refused comment never starts the review job, so it never loads the key and
never cancels a review in progress through the job's concurrency group. The
review Action repeats the check for workflows without the gate.

To run it locally without posting:

```sh
npm ci
GITHUB_TOKEN=… NEARAI_API_KEY=… node review/review.mjs --repo owner/name --pr 12 --dry-run
```

## Verify a receipt

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

## Choosing a model

The `model` input takes any NEAR AI Cloud model that runs in NEAR's own enclaves. Before any code is sent, the review checks the model with the attestation checks above. If it fails, the review stops. To list the models that pass today:

```sh
NEARAI_API_KEY=… npm run models
```

A model passes when its machine is fully patched (TCB `UpToDate`). `allow-unpatched-model: "true"` also accepts a model whose Intel platform update is pending, which is the Qwen models today, but never a revoked one. That is a weaker guarantee, so the review and the receipt both state it, and a receipt is re-checked under the policy it records. Models NEAR AI Cloud can't attest, such as those served through third parties, can't be chosen.

## How good it is

`npm run eval` runs the reviewer, unchanged, on pull requests whose bugs are known. Each case pins a commit, the description as it stood then, and the bugs as yes/no questions. A judge, the same attested model, asks those questions of each review. It was validated against real findings and real misses, with no errors in two rounds.

The first case is `near-agencies#94` at `34e6db3`. It has two regressions in money paths, both caught by Claude's review of that commit, and both in callers the diff doesn't touch. `z-ai/glm-5.3-flash` catches neither, in any of the configurations tried:
- standard review, 3 runs;
- more reasoning effort;
- the full changed files in the prompt;
- an invariants prompt;
- a question-driven deep pass, at about 28 minutes per review.

**Why it misses them:**
- When asked about the right caller, it finds the first bug every time. Left to choose its own questions, it doesn't ask that one.
- It traces the second bug correctly, then judges it intended.

**So every review says it is a second opinion, not a sign-off.** New cases and models are measured here before any claim about them changes.

## Development

`npm test` runs offline. It uses a real attestation report recorded with its
Intel collateral and NVIDIA's verdict, a real signed turn, the page's sample
receipt, and a stand-in enclave for the loop.

`npm run sample` refreshes the page's sample: a dry-run review of
near-agencies#78 saved as `site/sample-review.json`, its receipt, and the Intel
collateral and NVIDIA key the tests check that receipt with. It needs
`GITHUB_TOKEN` and `NEARAI_API_KEY`.

`npm run site` builds the page into `_site/`, with the sample review rendered in. esbuild bundles `site/app.js` with
the lockfile's packages, so the browser checker loads no code from a CDN. The
`pages` workflow publishes it on every push to `main`.
