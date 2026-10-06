// The page's two tools. The workflow generator writes the setup for a
// repository; the receipt checker runs core/receipt.mjs, the same checks as
// `node core/verify.mjs`, in the browser.
import { provenClaims, verifyReceipt } from "../core/receipt.mjs";
import published from "../app/builds.json" with { type: "json" };

const $ = selector => document.querySelector(selector);
const escape = text => String(text).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const code = text => escape(text).replace(/`([^`]+)`/g, "<code>$1</code>");

// ---- Workflow generator ----------------------------------------------------

// The action is pinned to the latest commit on main, looked up when the page loads.
let actionRef = "main";
fetch("https://api.github.com/repos/MultiAgency/private-ai/commits/main", { headers: { accept: "application/vnd.github.sha" } })
  .then(r => (r.ok ? r.text() : Promise.reject()))
  .then(sha => { if (/^[0-9a-f]{40}$/.test(sha)) { actionRef = sha; render(); } })
  .catch(() => {});

const pinned = path => `MultiAgency/private-ai/${path}@${actionRef}${actionRef === "main" ? "" : ` # ${actionRef.slice(0, 7)}`}`;

const DEFAULT_MODEL = "z-ai/glm-5.3-flash";

// The review step's inputs: the key, and the model and policy when they differ
// from the defaults. A model id is a short path, so anything else is dropped.
function inputs({ model, unpatched }) {
  const lines = ["nearai-api-key: \${{ secrets.NEARAI_API_KEY }}"];
  if (/^[\w.:-]+\/[\w.:-]+$/.test(model) && model !== DEFAULT_MODEL) lines.push(`model: ${model}`);
  if (unpatched) lines.push('allow-unpatched-model: "true"');
  return lines.map(line => `\n          ${line}`).join("");
}

const reviewJob = (options, condition = "") => `
  review:${condition}
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
        with:${inputs(options)}`;

// With /review, a gate job of its own decides first: a refused comment never
// starts the review job, so it can't load the key or cancel a review in progress.
const gatedJobs = options => `
  gate:
    if: >-
      github.event_name == 'workflow_dispatch'
      || (github.event_name == 'pull_request'
        && github.event.pull_request.head.repo.full_name == github.repository
        && !github.event.pull_request.draft)
      || (github.event_name == 'issue_comment'
        && github.event.issue.pull_request
        && startsWith(github.event.comment.body, '/review')
        && contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association))
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      allowed: \${{ steps.gate.outputs.allowed }}
    steps:
      - id: gate
        uses: ${pinned("review/gate")}
${reviewJob(options, `
    needs: gate
    if: needs.gate.outputs.allowed == 'true'`)}`;

function workflow({ forks, ...options }) {
  return `name: private-review

# Private AI review: the model reads this pull request only inside a NEAR AI
# Cloud enclave, end-to-end encrypted. See https://github.com/MultiAgency/private-ai
on:
  pull_request:
    types: [opened, synchronize, ready_for_review, reopened]
  # Run by hand (Actions tab, Run workflow) to check the setup: no code is read.
  workflow_dispatch:${forks ? `
  issue_comment:
    types: [created]` : ""}

jobs:${forks ? gatedJobs(options) : reviewJob(options, `
    if: \${{ !github.event.pull_request.draft }}`)}
`;
}

function render() {
  const [owner, name] = $("#repo").value.trim().replace(/^https?:\/\/github\.com\//, "").replace(/\.git$/, "").split("/");
  const valid = /^[\w.-]+$/.test(owner ?? "") && /^[\w.-]+$/.test(name ?? "");
  const repo = valid ? `${owner}/${name}` : "OWNER/REPO";
  const branch = $("#branch").value.trim() || "main";
  const yaml = workflow({ forks: $("#forks").checked, model: $("#model").value.trim() || DEFAULT_MODEL, unpatched: $("#unpatched").checked });

  $("#workflow").textContent = yaml;
  $("#secret-command").textContent = `gh secret set NEARAI_API_KEY -R ${repo}`;
  const secrets = $("#secrets-link");
  secrets.href = `https://github.com/${repo}/settings/secrets/actions/new`;
  const create = $("#create-link");
  create.href = `https://github.com/${repo}/new/${encodeURIComponent(branch)}` +
    `?filename=${encodeURIComponent(".github/workflows/private-review.yml")}&value=${encodeURIComponent(yaml)}`;
  for (const link of [secrets, create]) link.toggleAttribute("aria-disabled", !valid);
}

for (const id of ["#repo", "#branch", "#forks", "#model", "#unpatched"]) $(id).addEventListener("input", render);
render();

for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText($(button.dataset.copy).textContent);
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = label; }, 1500);
  });
}

// ---- Theme ----------------------------------------------------------------

$("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch {}
});

// ---- Receipt checker -------------------------------------------------------

const result = $("#check-result");

/** A receipt's verified claims, or the reason it isn't verified (thrown). */
async function verify(text, options = {}) {
  const { receipt, sha256, gateway, model, runs, subjectConfirmed } = await verifyReceipt(text, { ...options, published });
  const claims = provenClaims({ model: receipt.model, attestation: { model, gateway }, turns: receipt.turns.length, runs });
  return { receipt, sha256, claims, subject: subjectConfirmed ? options.subject : receipt.subject };
}

async function check(text, label, options) {
  result.hidden = false;
  result.className = "card result running";
  result.innerHTML = `<p>Checking ${escape(label)}: verifying the Intel quotes, NVIDIA's verdict and every signature…</p>`;
  try {
    const { receipt, sha256, claims, subject: named } = await verify(text, options);
    const subject = named
      ? Object.entries(named).map(([k, v]) => `<dt>${escape(k.replace(/_/g, " "))}</dt><dd><code>${escape(v)}</code></dd>`).join("")
      : `<dt>subject</dt><dd>committed, not named: open the link in the review to see which pull request</dd>`;
    result.className = "card result ok";
    result.innerHTML = `
      <p class="verdict">Verified</p>
      <ul class="checks">
        ${claims.map(([claim, text]) => `<li><strong>${escape(claim)}:</strong> ${code(text)}</li>`).join("")}
      </ul>
      <dl>${subject}<dt>model</dt><dd><code>${escape(receipt.model)}</code></dd><dt>created</dt><dd>${escape(receipt.created_at)}</dd><dt>receipt sha256</dt><dd><code>${escape(sha256)}</code></dd></dl>`;
  } catch (error) {
    result.className = "card result failed";
    result.innerHTML = `<p class="verdict">Not verified</p><p>${escape(error.message)}</p>`;
  }
}

// The hero's seal: the same checks on the sample review's receipt. Its lines
// arrive one by one, the page's one piece of motion, in answer to the press.
const seal = $("#seal");
seal.addEventListener("click", async () => {
  const list = $("#seal-checks");
  const note = $("#seal-note");
  seal.disabled = true;
  seal.classList.remove("ok", "failed");
  seal.classList.add("checking");
  seal.querySelector("span").textContent = "Checking";
  note.textContent = "Fetching Intel's collateral and NVIDIA's keys, then checking every signature…";
  list.hidden = true;
  const started = performance.now();
  try {
    const { claims } = await verify(await fetch("sample-receipt.json").then(r => r.text()));
    list.innerHTML = claims.map(([claim, text], i) => `<li style="--i:${i}"><strong>${escape(claim)}</strong> ${code(text)}</li>`).join("");
    list.hidden = false;
    seal.classList.add("ok");
    seal.querySelector("span").textContent = "Sealed";
    note.textContent = `Verified in ${((performance.now() - started) / 1000).toFixed(1)} s, here in your browser.`;
  } catch (error) {
    seal.classList.add("failed");
    seal.querySelector("span").textContent = "Not verified";
    note.textContent = error.message;
  } finally {
    seal.classList.remove("checking");
    seal.disabled = false;
  }
});

// A hosted review links its receipt as #check&receipt=…&project=…&salt=…&subject=…:
// the receipt is fetched from OutLayer's public storage, and the salt and
// subject (in the fragment, which never reaches a server) open its commitment.
async function checkLinked() {
  const params = new URLSearchParams(location.hash.replace(/^#check&?/, ""));
  const [sha, project] = [params.get("receipt"), params.get("project")];
  if (!sha || !project) return;
  document.getElementById("check")?.scrollIntoView();
  try {
    const url = `https://api.outlayer.ai/public/storage/get?project=${encodeURIComponent(project)}&key=${encodeURIComponent(`receipt:${sha}`)}&format=raw`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`no receipt published at ${project} under ${sha} (${response.status})`);
    const text = await response.text();
    const subject = params.get("subject") && JSON.parse(atob(params.get("subject").replace(/-/g, "+").replace(/_/g, "/")));
    await check(text, "the receipt this review links", { salt: params.get("salt") ?? undefined, subject: subject || undefined, expectSha256: sha });
  } catch (error) {
    result.hidden = false;
    result.className = "card result failed";
    result.innerHTML = `<p class="verdict">Not verified</p><p>${escape(error.message)}</p>`;
  }
}
checkLinked();

// GitHub sends people here after they install the App.
if (location.hash === "#installed") {
  const banner = $("#installed-banner");
  banner.hidden = false;
  banner.scrollIntoView();
}

$("#check-sample").addEventListener("click", async () => {
  const response = await fetch("sample-receipt.json");
  check(await response.text(), "the sample receipt");
});

const drop = $("#drop");
const readFile = file => file && file.text().then(text => check(text, file.name));
$("#receipt-file").addEventListener("change", event => readFile(event.target.files[0]));
drop.addEventListener("dragover", event => { event.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", event => {
  event.preventDefault();
  drop.classList.remove("over");
  readFile(event.dataTransfer.files[0]);
});
