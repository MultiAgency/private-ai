# MultiAgency private AI

Services that work on private data with AI and prove where the data went. Each
service runs a model inside a [NEAR AI Cloud](https://docs.near.ai/cloud/private-inference)
enclave (Intel TDX with NVIDIA confidential GPUs), encrypts everything to that
enclave's key, and leaves a receipt anyone can re-check.

The first service is **private code review** of pull requests, in
[`review/`](review/). [`core/`](core/) is what every service shares.

## What a run proves

Before any data is sent, a run checks NEAR AI Cloud's attestation report for a fresh nonce:

- **Model enclave:** the TDX quote verifies against Intel's collateral with TCB
  status `UpToDate`, debug mode off. The quote binds the enclave's signing key
  and our nonce. Its configuration measurement matches the attested compose
  file, and its event log replays to RTMR3. NVIDIA's attestation service
  approves its GPUs for the same nonce.
- **Gateway enclave:** the same quote checks, except that a pending platform
  patch (`OutOfDate` and the like) is allowed and `Revoked` is not. Under
  end-to-end encryption the gateway relays only ciphertext.

Then every request is end-to-end encrypted to the model enclave's key, using
NEAR AI Cloud's E2EE v2 with all fields covered. That includes tool definitions
and tool calls, so the gateway sees roles, ids and token counts but no content.
Each reply is used only after the model enclave's signature over the exact
request and response bytes checks out. If any check fails, the run stops.

**What it does not prove:**

- **What happens on the machine that runs the service.** Code review runs as a
  GitHub Action on the client's own runner, which already has their code. This
  repository is public so that anyone can read what that Action does.
- **Which model instance answered.** Instances of a model share one signing
  key, so the signature proves an attested enclave answered, not which one
  (see NEAR's [verification notes](https://docs.near.ai/cloud/verification/cloud-api/model-attestations)).
- **What NEAR's images do.** The receipt records the compose hashes, and
  NEAR publishes the [compose files](https://github.com/nearai/cvm-compose-files)
  they measure. Auditing those images is a separate step.

## Private code review

Add a workflow to the repository. It needs a NEAR AI Cloud API key as the
`NEARAI_API_KEY` secret.

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
The receipt is uploaded as the run's `private-review-receipt` artifact.

Pull requests from forks get no secrets, so they need an `issue_comment`
trigger that someone with write access starts, as in
[near-agencies](https://github.com/MultiAgency/near-agencies/blob/staging/.github/workflows/private-review.yml).

To run it locally without posting:

```sh
npm ci
GITHUB_TOKEN=… NEARAI_API_KEY=… node review/review.mjs --repo owner/name --pr 12 --dry-run
```

## Verify a receipt

```sh
git clone https://github.com/MultiAgency/private-ai && cd private-ai && npm ci
node core/verify.mjs private-review-receipt.json
```

This re-runs the attestation checks on the recorded report, against current
Intel collateral and NVIDIA's service. It also checks every response
signature against the attested model key. The receipt holds hashes of the
encrypted requests and responses, not the bytes, so it carries none of the
reviewed code.

## Development

`npm test` runs offline. It uses a real attestation report recorded with its
Intel collateral, a real signed turn, and a stand-in enclave for the loop.
