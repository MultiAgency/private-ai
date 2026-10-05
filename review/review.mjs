// Private code review of one pull request on NEAR AI Cloud. The code is read
// only inside an attested model enclave:
//
//   1. attest   verify the gateway's and the model's TDX quotes and the model's
//               GPUs before any code is sent; stop if a check fails
//   2. review   an end-to-end encrypted tool loop over the head commit, each
//               reply used only once its enclave signature checks out
//   3. post     one pull request review, ending with what was verified, and a
//               receipt anyone can re-check with verify.mjs
//
// Usage: node review.mjs --repo owner/name --pr N [--dry-run [--review path] [--head sha]] [--receipt path]
//        node review.mjs --repo owner/name --check   (also when the workflow is run by hand)
// --head reviews an earlier commit of the pull request, as it was then, without
// its earlier findings: the page's sample pins one this way.
// Env: NEARAI_API_KEY, GITHUB_TOKEN; optionally MODEL, RUBRIC, MAX_TURNS,
// PASSES, and ALLOW_UNPATCHED_MODEL=true to accept a model whose platform update
// is pending (stated in the review and the receipt). In
// GitHub Actions a `/review` comment starts a run only for someone who can write
// to the repository (see gate.mjs).
// It logs counts and hashes only: never code, prompts or the model's output.
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { runAgent } from "../core/agent.mjs";
import { attest } from "../core/attest.mjs";
import { nearai } from "../core/nearai.mjs";
import { provenClaims, receipt } from "../core/receipt.mjs";
import { commentEvent, refusal, reviewStarter } from "./gate.mjs";
import { github } from "./github.mjs";
import { checkSetup, modelProblem, report } from "./setup.mjs";
import { definitions, tools, unpack } from "./repo.mjs";
import spec from "./review.json" with { type: "json" };

// The review's text, schema and limits are shared with the hosted App (app/):
// review.json is the one place to change them.
const SUBMIT = { tool: spec.submit_tool, check: checkSubmission };

/** Why a submission is incomplete, for the model to fix; nothing when it is complete. */
export function checkSubmission({ summary, findings }) {
  if (typeof summary !== "string" || !Array.isArray(findings)) return "submit_review needs a summary and a findings array";
  const bad = findings.findIndex(f =>
    typeof f?.path !== "string" || !Number.isInteger(f.line) ||
    !["pass", "severity", "body"].every(key => typeof f[key] === "string" && f[key]));
  if (bad >= 0) {
    return `finding ${bad + 1} needs path (string), line (integer), pass, severity and body; it has ${Object.keys(findings[bad] ?? {}).join(", ") || "nothing"}`;
  }
}

// Measured on a real pull request (eval/), a clean result here has missed
// regressions that span files in money paths. Every review says so.
const LIMITS = spec.limits_note;

const CHECKER = spec.checker_url;
// Reactions on findings become eval cases (eval/collect.mjs).
const FEEDBACK = spec.feedback_note;

const PATCH_LIMIT = spec.patch_limit;
const PROMPT_LIMIT = spec.prompt_limit;

const DEFAULT_RUBRIC = spec.default_rubric;

/** "path:line" for every line a review comment may sit on: added and context lines of the new file. */
export function commentableLines(files) {
  const lines = new Set();
  for (const file of files) {
    let line = 0;
    for (const row of (file.patch ?? "").split("\n")) {
      const hunk = row.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
      if (hunk) line = Number(hunk[1]);
      else if (row.startsWith("+") || row.startsWith(" ")) lines.add(`${file.filename}:${line++}`);
    }
  }
  return lines;
}

export function systemPrompt(rubric) {
  return spec.system_prompt.replace("{rubric}", () => rubric);
}

export function userPrompt(pr, files, earlier = []) {
  let budget = PROMPT_LIMIT;
  const sections = files.map(f => {
    const header = `### ${f.filename} (${f.status}, +${f.additions} −${f.deletions})`;
    if (!f.patch) return `${header}\n(no text diff)`;
    if (f.patch.length > PATCH_LIMIT || f.patch.length > budget) return `${header}\n(diff too large to include: read the file)`;
    budget -= f.patch.length;
    return `${header}\n\`\`\`diff\n${f.patch}\n\`\`\``;
  });
  return `Pull request #${pr.number}: ${pr.title}
Base: ${pr.base.ref} (${pr.base.sha}). Head: ${pr.head.ref} (${pr.head.sha}).

## Description

${pr.body || "(none)"}

## Changed files (${files.length})

${sections.join("\n\n")}${earlier.length ? `

## Your earlier findings on this pull request

${earlier.map(f => `- \`${f.path}\`: ${f.body}`).join("\n")}` : ""}`;
}

// The product's name heads every review. Reviews posted before it had a name
// began "**Private review**", and still count as this reviewer's own.
export const NAME = spec.name;
export const isOurReview = body => [`**${NAME}**`, ...spec.legacy_headings].some(heading => body?.startsWith(heading));

/**
 * This reviewer's own earlier inline findings on the pull request, from the
 * reviews whose body starts as renderReview starts them, so a re-review can
 * report what is new instead of repeating itself on every push.
 */
export async function earlierFindings(gh, number) {
  const ours = new Set((await gh.reviews(number)).filter(r => isOurReview(r.body)).map(r => r.id));
  if (ours.size === 0) return [];
  const seen = new Set();
  return (await gh.reviewComments(number))
    .filter(c => ours.has(c.pull_request_review_id))
    .map(c => ({ path: c.path, body: c.body }))
    .filter(f => !seen.has(`${f.path}\n${f.body}`) && seen.add(`${f.path}\n${f.body}`));
}

/** The review GitHub receives: inline comments on changed lines, the rest in the body. */
export function renderReview({ review, turns, attestation, model, receiptSha256, runUrl, commentable }) {
  const label = f => `**${f.pass}, ${f.severity}:**`;
  // Findings the reviewer marked as its own earlier ones, still open, are
  // counted here instead of posted again on every push.
  const findings = review.findings.filter(f => !f.earlier);
  const stillOpen = review.findings.length - findings.length;
  const inline = findings.filter(f => commentable.has(`${f.path}:${f.line}`));
  const elsewhere = findings.filter(f => !commentable.has(`${f.path}:${f.line}`));

  const counts = new Map();
  for (const f of findings) counts.set(`${f.pass}, ${f.severity}`, (counts.get(`${f.pass}, ${f.severity}`) ?? 0) + 1);
  const tally = [
    counts.size ? [...counts].map(([k, n]) => `${k}: ${n}`).join(" · ") : stillOpen ? "no new findings" : "no findings",
    stillOpen && `${stillOpen} still open`,
  ].filter(Boolean).join(" · ");

  const body = [
    `**${NAME}** (${tally})`,
    review.summary,
    stillOpen && `${stillOpen === 1 ? "1 earlier finding is" : `${stillOpen} earlier findings are`} still open, and not posted again.`,
    LIMITS,
    FEEDBACK,
    elsewhere.length && ["**Not on a changed line**", ...elsewhere.map(f => `- \`${f.path}:${f.line}\` ${label(f)} ${f.body}`)].join("\n"),
    spec.proof_line.replace("{checker}", () => CHECKER),
    [
      "<details><summary>What was verified</summary>",
      "",
      ...provenClaims({ model, attestation, turns: turns.length }).map(([claim, text]) => `- **${claim}:** ${text}`),
      `- **Receipt:** sha256 \`${receiptSha256}\`${runUrl ? ` in the [run's artifacts](${runUrl})` : ""}. Anyone can [check it](${CHECKER}).`,
      "",
      "</details>",
    ].join("\n"),
  ].filter(Boolean).join("\n\n");

  return { body, comments: inline.map(f => ({ path: f.path, line: f.line, side: "RIGHT", body: `${label(f)} ${f.body}` })) };
}

/**
 * Reviews one change: the tool loop over the head commit unpacked at `root`,
 * `passes` times in parallel. One pass catches a real finding some runs and not
 * others (eval/), so several passes' findings are merged, one per line.
 */
export async function reviewChange({ client, model, publicKey, pr, files, rubric, root, maxTurns, earlier = [], passes = 1, log = () => {} }) {
  const runs = await Promise.all(Array.from({ length: passes }, (_, i) => runAgent({
    client,
    model,
    publicKey,
    system: systemPrompt(rubric),
    prompt: userPrompt(pr, files, earlier),
    tools: definitions,
    call: tools(root),
    finish: SUBMIT,
    maxTurns,
    log: passes > 1 ? line => log(`pass ${i + 1}: ${line}`) : log,
  })));
  return {
    review: { summary: runs[0].result.summary, findings: mergeFindings(runs.map(run => run.result.findings)) },
    turns: runs.flatMap(run => run.turns),
  };
}

/** Findings from several passes, keeping the first one reported for each line. */
export function mergeFindings(lists) {
  const seen = new Set();
  return lists.flat().filter(f => !seen.has(`${f.path}:${f.line}`) && seen.add(`${f.path}:${f.line}`));
}

async function loadRubric(gh, ref, paths) {
  const parts = [];
  for (const path of paths) {
    const text = await gh.text(path, ref);
    if (text !== null) parts.push(`## ${path}\n\n${text}`);
  }
  return parts.join("\n\n") || DEFAULT_RUBRIC;
}

async function main() {
  const { values } = parseArgs({
    options: {
      repo: { type: "string" },
      pr: { type: "string" },
      "dry-run": { type: "boolean" },
      head: { type: "string" },
      check: { type: "boolean" },
      review: { type: "string" },
      receipt: { type: "string" },
    },
  });
  const env = name => {
    if (!process.env[name]) throw new Error(`${name} is required`);
    return process.env[name];
  };
  const repo = values.repo ?? env("GITHUB_REPOSITORY");
  const dryRun = values["dry-run"] ?? false;
  const receiptPath = resolve(values.receipt ?? "private-review-receipt.json");
  const model = process.env.MODEL || "z-ai/glm-5.3-flash";
  const rubricPaths = (process.env.RUBRIC || "REVIEW.md,AGENTS.md").split(",").map(p => p.trim()).filter(Boolean);
  const maxTurns = Number(process.env.MAX_TURNS || "30");
  const passes = Number(process.env.PASSES || "1");
  const allowUnpatchedModel = process.env.ALLOW_UNPATCHED_MODEL === "true";
  if (!Number.isInteger(passes) || passes < 1 || passes > 5) throw new Error(`PASSES must be 1 to 5, not ${process.env.PASSES}`);
  const gh = github(env("GITHUB_TOKEN"), repo);
  const client = nearai(env("NEARAI_API_KEY"));

  if (values.check || process.env.GITHUB_EVENT_NAME === "workflow_dispatch") {
    if (!report(await checkSetup({ client, gh, model, allowUnpatchedModel }))) process.exitCode = 1;
    return;
  }
  const number = Number(values.pr ?? env("PR_NUMBER"));

  // The backstop for workflows without the review/gate job ahead of this one.
  const starter = await reviewStarter(commentEvent(), gh);
  if (starter && !starter.allowed) {
    console.log(`::notice::${refusal(starter)}`);
    return;
  }

  try {
    const pr = await gh.pull(number);
    if (values.head) {
      if (!dryRun) throw new Error("--head reviews an earlier commit, so it needs --dry-run");
      const commits = await gh.compare(pr.base.ref, values.head);
      Object.assign(pr, { base: { ...pr.base, sha: commits.merge_base_commit.sha }, head: { ...pr.head, sha: values.head }, files: commits.files });
    }
    const [files, rubric, tarball, earlier] = await Promise.all([
      pr.files ?? gh.files(number),
      loadRubric(gh, pr.base.sha, rubricPaths),
      gh.tarball(pr.head.sha),
      values.head ? [] : earlierFindings(gh, number),
    ]);
    console.log(`#${number}: ${files.length} files changed, ${earlier.length} earlier findings; head ${pr.head.sha}`);

    const { evidence, attestation } = await attest(client, model, { allowUnpatchedModel })
      .catch(error => { throw new Error(`attestation failed, so no code was sent: ${modelProblem(model, error)}`); });
    console.log(`attested: model TCB ${attestation.model.tcb}, gateway TCB ${attestation.gateway.tcb}, signer ${attestation.model.signer}`);

    const head = unpack(tarball);
    let result;
    try {
      result = await reviewChange({
        client, model, publicKey: attestation.model.publicKey, pr, files, rubric, root: head.root, maxTurns, earlier, passes, log: console.log,
      });
    } finally {
      head.remove();
    }
    console.log(`reviewed: ${result.review.findings.length} findings in ${result.turns.length} signed turns`);

    const { text, sha256: receiptSha256 } = receipt({
      subject: { pull_request: `${repo}#${number}`, base_sha: pr.base.sha, head_sha: pr.head.sha },
      model,
      evidence,
      turns: result.turns,
    });
    writeFileSync(receiptPath, text);
    console.log(`receipt: ${receiptPath} sha256 ${receiptSha256}`);

    const runUrl = process.env.GITHUB_RUN_ID &&
      `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`;
    const posted = renderReview({ review: result.review, turns: result.turns, attestation, model, receiptSha256, runUrl, commentable: commentableLines(files) });
    if (dryRun) {
      // --review keeps what would have been posted, e.g. as the page's sample.
      if (values.review) writeFileSync(resolve(values.review), `${JSON.stringify(posted, null, 2)}\n`);
      else console.log(JSON.stringify(posted, null, 2));
      return;
    }
    await gh.review(number, { commit_id: pr.head.sha, event: "COMMENT", ...posted });
    console.log(`posted: ${posted.comments.length} inline comments`);
  } catch (error) {
    if (!dryRun) await gh.comment(number, `**Private review stopped:** ${error.message}. No code was posted anywhere else. Re-run the job to try again; if it keeps stopping, the run's log names the step.`).catch(() => {});
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.message);
    process.exit(1);
  });
}
