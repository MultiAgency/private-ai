// The same workflow is used by the setup page and its offline regression tests.
import review from "../review/review.json" with { type: "json" };

export function workflow({ forks = false, model = review.defaults.model, unpatched = false, ref = "main" } = {}) {
  const pinned = path => `MultiAgency/private-ai/${path}@${ref}${ref === "main" ? "" : ` # ${ref.slice(0, 7)}`}`;
  const inputs = ["nearai-api-key: \${{ secrets.NEARAI_API_KEY }}"];
  if (/^[\w.:-]+\/[\w.:-]+$/.test(model) && model !== review.defaults.model) inputs.push(`model: ${model}`);
  if (unpatched) inputs.push('allow-unpatched-model: "true"');
  return `name: private-review

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
      allowed: \${{ steps.gate.outputs.allowed }}
    steps:
      - id: gate
        uses: ${pinned("review/gate")}
        with:
          allow-forks: "${forks}"
  review:
    needs: gate
    if: needs.gate.outputs.allowed == 'true'
    runs-on: ubuntu-latest
    concurrency:
      group: private-review-\${{ github.event.pull_request.number || github.event.issue.number }}
      cancel-in-progress: true
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: ${pinned("review")}
        with:${inputs.map(line => `\n          ${line}`).join("")}
`;
}
