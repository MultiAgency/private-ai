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
// Usage: node review.mjs --repo owner/name --commit REF [--dry-run] [--receipt path]
//        node review.mjs --repo owner/name --base REF --head REF [--dry-run]
//        node review.mjs --repo owner/name --pr N [--dry-run [--review path] [--head sha]] [--receipt path]
//        node review.mjs --repo owner/name --check   (also when the workflow is run by hand)
// --head reviews an earlier commit of the pull request, as it was then, without
// its earlier findings: the page's sample pins one this way.
// Env: NEARAI_API_KEY, GITHUB_TOKEN; optionally MODEL, RUBRIC, MAX_TURNS,
// PASSES, VERIFY=false to skip the pass that checks findings, and
// ALLOW_UNPATCHED_MODEL=true to accept a model whose platform update
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
const VERDICTS = { tool: spec.verify_tool, check: checkVerdicts };
const OPTIONAL_TEXT = ["category", "existing_code", "suggestion", "fix_code"];

/** Why a submission is incomplete, for the model to fix; nothing when it is complete. */
export function checkSubmission({ summary, checked, findings }) {
  if (typeof summary !== "string" || !Array.isArray(findings)) return "submit_review needs a summary and a findings array";
  if (checked !== undefined && !(Array.isArray(checked) && checked.every(c => typeof c === "string"))) return "checked must be a list of strings";
  const bad = findings.findIndex(f =>
    typeof f?.path !== "string" || !Number.isInteger(f.line) ||
    !["pass", "severity", "title", "body"].every(key => typeof f[key] === "string" && f[key]) ||
    OPTIONAL_TEXT.some(key => f[key] !== undefined && f[key] !== null && typeof f[key] !== "string"));
  if (bad >= 0) {
    return `finding ${bad + 1} needs path (string), line (integer), pass, severity, title and body, and existing_code as text; it has ${Object.keys(findings[bad] ?? {}).join(", ") || "nothing"}`;
  }
}

/** Why a verify submission is incomplete; nothing when it is complete. */
export function checkVerdicts({ verdicts }) {
  if (!Array.isArray(verdicts)) return "submit_verdicts needs a verdicts array";
  const bad = verdicts.findIndex(v => !Number.isInteger(v?.index) || typeof v.keep !== "boolean");
  if (bad >= 0) return `verdict ${bad + 1} needs index (integer) and keep (boolean)`;
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

/**
 * The lines a review comment may sit on, by file: added and context lines of
 * the new file, line number to text.
 */
export function newLines(files) {
  const byFile = new Map();
  for (const file of files) {
    const lines = new Map();
    let line = 0;
    for (const row of (file.patch ?? "").split("\n")) {
      const hunk = row.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
      if (hunk) line = Number(hunk[1]);
      else if (row.startsWith("+") || row.startsWith(" ")) lines.set(line++, row.slice(1));
    }
    if (lines.size) byFile.set(file.filename, lines);
  }
  return byFile;
}

/** "path:line" for every line a review comment may sit on. */
export function commentableLines(files) {
  return new Set([...newLines(files)].flatMap(([path, lines]) => [...lines.keys()].map(line => `${path}:${line}`)));
}

/**
 * Where a finding sits on the diff: the changed lines that hold its quoted
 * existing_code, nearest its reported line (`exact`, so fix_code can replace
 * them), else its reported line when that is commentable, else nowhere.
 */
export function place(finding, lines) {
  const inFile = lines.get(finding.path);
  if (!inFile) return null;
  const snippet = trimBlank((finding.existing_code ?? "").split("\n")).map(l => l.trim());
  let best = null;
  if (snippet.length) {
    for (const start of inFile.keys()) {
      if (!snippet.every((text, k) => inFile.get(start + k)?.trim() === text)) continue;
      if (!best || Math.abs(start - finding.line) < Math.abs(best.start - finding.line)) best = { start, end: start + snippet.length - 1, exact: true };
    }
  }
  if (best) return best;
  return inFile.has(finding.line) ? { start: finding.line, end: finding.line, exact: false } : null;
}

function trimBlank(lines) {
  let [start, end] = [0, lines.length];
  while (start < end && !lines[start].trim()) start++;
  while (end > start && !lines[end - 1].trim()) end--;
  return lines.slice(start, end);
}

/** Lockfiles, vendored and generated files: listed for the model, their diff left out. */
export function skipped(path) {
  const parts = path.split("/");
  const name = parts.at(-1);
  return spec.skip.names.includes(name) || parts.slice(0, -1).some(dir => spec.skip.dirs.includes(dir)) ||
    spec.skip.suffixes.some(suffix => name.endsWith(suffix));
}

export function systemPrompt(rubric, { standalone = false } = {}) {
  // Adapt the template before inserting repository instructions verbatim.
  return forChange(spec.system_prompt, standalone).replace("{rubric}", () => rubric);
}

/** A commit or range review says "change" where a PR review says "pull request". */
const forChange = (text, standalone) => standalone ? text.replaceAll("pull request", "change").replace("base branch", "base revision") : text;

/** Text on one line: each line trimmed, blank ones dropped. */
const oneLine = text => String(text ?? "").split("\n").map(line => line.trim()).filter(Boolean).join(" ");

export function userPrompt(pr, files, earlier = []) {
  let budget = PROMPT_LIMIT;
  const sections = files.map(f => {
    const header = `### ${f.filename} (${f.status}, +${f.additions} −${f.deletions})`;
    if (skipped(f.filename)) return `${header}\n(lockfile, vendored or generated: diff left out)`;
    if (!f.patch) return `${header}\n(no text diff)`;
    if (f.patch.length > PATCH_LIMIT || f.patch.length > budget) return `${header}\n(diff too large to include: read the file)`;
    budget -= f.patch.length;
    return `${header}\n\`\`\`diff\n${f.patch}\n\`\`\``;
  });
  return `${pr.number ? `Pull request #${pr.number}` : "Commit range"}: ${pr.title}
Base: ${pr.base.ref} (${pr.base.sha}). Head: ${pr.head.ref} (${pr.head.sha}).

## Description

${pr.body || "(none)"}

## Changed files (${files.length})

${sections.join("\n\n")}${earlier.length ? `

## Your earlier findings on this pull request

${earlier.map(f => `- \`${f.path}\`: ${oneLine(f.body)}`).join("\n")}` : ""}`;
}

// The product's name heads every review. Reviews posted before it had a name
// began "**Private review**", and still count as this reviewer's own. Only
// this reviewer's own accounts post them (spec.authors): a heading alone is
// something anyone can type.
export const NAME = spec.name;
export const isOurReview = review => spec.authors.includes(review.user?.login)
  && [`**${NAME}**`, ...spec.legacy_headings].some(heading => review.body?.startsWith(heading));

/**
 * This reviewer's own earlier inline findings on the pull request, from the
 * reviews whose body starts as renderReview starts them, so a re-review can
 * report what is new instead of repeating itself on every push.
 */
export async function earlierFindings(gh, number) {
  const reviews = await gh.reviews(number);
  return reviews.some(isOurReview) ? ownFindings(reviews, await gh.reviewComments(number)) : [];
}

/** The inline findings of this reviewer's own reviews, once each (app/src/review.rs `own_findings`). */
export function ownFindings(reviews, comments) {
  const ours = new Set(reviews.filter(isOurReview).map(r => r.id));
  const seen = new Set();
  return comments
    .filter(c => ours.has(c.pull_request_review_id))
    .map(c => ({ path: c.path, body: findingText(c.body ?? "") }))
    .filter(f => !seen.has(`${f.path}\n${f.body}`) && seen.add(`${f.path}\n${f.body}`));
}

/** A posted finding without its fix: what a re-review needs to recognise it. */
function findingText(body) {
  const cut = [SUGGESTED, "\n\n```suggestion"].map(marker => body.indexOf(marker)).filter(i => i >= 0);
  return cut.length ? body.slice(0, Math.min(...cut)) : body;
}

const SUGGESTED = "\n\n**Suggested fix:**";

/**
 * Model-written text is untrusted: it cannot open a one-click suggestion
 * block or a hidden HTML comment in what is posted.
 */
export function clean(text) {
  return String(text ?? "").replace(/```[ \t]*suggestion/gi, "```text").replaceAll("<!--", "&lt;!--");
}

/** The checked list, each item on one line, cut off once it passes 1500 characters in all. */
function checkedItems(checked) {
  const items = [];
  let length = 0;
  for (const raw of checked) {
    const item = clean(raw).replace(/\s+/g, " ").trim();
    if (!item) continue;
    if (length + item.length > 1500) {
      items.push(`…and ${checked.length - items.length} more`);
      break;
    }
    items.push(item);
    length += item.length;
  }
  return items;
}

/** The review GitHub receives: inline comments on changed lines, the rest in the body. */
export function renderReview({ review, turns, attestation, model, receiptSha256, runUrl, lines }) {
  const heading = f => `**${clean(f.pass)}, ${clean(f.severity)}: ${clean(f.title)}**`;
  // Findings the reviewer marked as its own earlier ones, still open, are
  // counted here instead of posted again on every push.
  const findings = review.findings.filter(f => !f.earlier);
  const stillOpen = review.findings.length - findings.length;
  const placed = findings.map(f => ({ f, at: place(f, lines) }));
  const inline = placed.filter(p => p.at);
  const elsewhere = placed.filter(p => !p.at).map(p => p.f);

  const counts = new Map();
  for (const f of findings) counts.set(`${f.pass}, ${f.severity}`, (counts.get(`${f.pass}, ${f.severity}`) ?? 0) + 1);
  const tally = [
    counts.size ? [...counts].map(([k, n]) => `${clean(k)}: ${n}`).join(" · ") : stillOpen ? "no new findings" : "no findings",
    stillOpen && `${stillOpen} still open`,
  ].filter(Boolean).join(" · ");

  const dropped = review.dropped ?? 0;
  const verification = {
    verified: dropped ? spec.dropped_note.replace("{dropped}", () => (dropped === 1 ? "1 finding" : `${dropped} findings`)) : spec.verified_note,
    unverified: spec.unverified_note,
  }[review.verification];
  const checked = checkedItems(review.checked ?? []);

  const body = [
    `**${NAME}** (${tally})`,
    clean(review.summary),
    stillOpen && `${stillOpen === 1 ? "1 earlier finding is" : `${stillOpen} earlier findings are`} still open, and not posted again.`,
    verification,
    LIMITS,
    FEEDBACK,
    elsewhere.length && ["**Not on a changed line**", ...elsewhere.map(f => `- \`${clean(f.path)}:${f.line}\` ${heading(f)} ${clean(f.body)}`)].join("\n"),
    checked.length && [`<details><summary>What was traced (${checked.length})</summary>`, "", ...checked.map(item => `- ${item}`), "", "</details>"].join("\n"),
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

  const comments = inline.map(({ f, at }) => ({
    path: f.path,
    ...(at.end > at.start && { start_line: at.start, start_side: "RIGHT" }),
    line: at.end,
    side: "RIGHT",
    body: commentBody(f, at.exact, heading),
  }));
  return { body, comments };
}

/** One inline finding: its heading and body, the fix in prose, and a one-click suggestion when it replaces exactly the quoted lines. */
function commentBody(f, exact, heading) {
  const parts = [heading(f), clean(f.body)];
  if (typeof f.suggestion === "string" && f.suggestion.trim()) parts.push(`**Suggested fix:** ${clean(f.suggestion)}`);
  if (exact && typeof f.fix_code === "string") parts.push(`\`\`\`suggestion\n${f.fix_code.replaceAll("```", "ˋˋˋ")}\n\`\`\``);
  return parts.join("\n\n");
}

/**
 * Reviews one change: the tool loop over the head commit unpacked at `root`,
 * `passes` times in parallel. One pass catches a real finding some runs and not
 * others (eval/), so several passes' findings are merged. Then, with `verify`,
 * a second loop checks the new findings against the code and removes those it
 * proves wrong, or that repeat another.
 */
export async function reviewChange({ client, model, publicKey, pr, files, rubric, root, maxTurns, earlier = [], passes = 1, verify = false, log = () => {} }) {
  const standalone = !pr.number;
  const prompt = userPrompt(pr, files, earlier);
  const runs = await Promise.all(Array.from({ length: passes }, (_, i) => runAgent({
    client,
    model,
    publicKey,
    system: systemPrompt(rubric, { standalone }),
    prompt,
    tools: definitions,
    call: tools(root),
    finish: SUBMIT,
    maxTurns,
    log: passes > 1 ? line => log(`pass ${i + 1}: ${line}`) : log,
  })));
  const findings = mergeFindings(runs.map(run => run.result.findings), newLines(files));
  const turns = runs.flatMap(run => run.turns);
  const review = {
    summary: runs[0].result.summary,
    // The first pass speaks for the review, as its summary does: passes trace much the same paths.
    checked: runs[0].result.checked ?? [],
    findings,
    verification: "skipped",
    dropped: 0,
  };
  const candidates = findings.filter(f => !f.earlier);
  if (!verify || !candidates.length) return { review, turns };

  try {
    const checked = await runAgent({
      client,
      model,
      publicKey,
      system: forChange(spec.verify_prompt, standalone),
      prompt: verifyPrompt(prompt, candidates),
      tools: definitions,
      call: tools(root),
      finish: VERDICTS,
      maxTurns,
      log: line => log(`verify: ${line}`),
      onTurn: record => turns.push(record),
    });
    const kept = applyVerdicts(candidates, checked.result.verdicts);
    log(`verify: kept ${kept.length} of ${candidates.length}`);
    return { review: { ...review, findings: [...kept, ...findings.filter(f => f.earlier)], verification: "verified", dropped: candidates.length - kept.length }, turns };
  } catch (error) {
    // The passes' findings stand on their own signed turns: a check that never
    // submits, or whose turn fails, leaves them posted, labelled unchecked.
    // A reply whose signature fails is never recorded, so it is not in the receipt.
    log(`verify: ${error.message}; findings kept unchecked`);
    return { review: { ...review, verification: "unverified" }, turns };
  }
}

/** The verify pass's prompt: the review's own prompt, then the candidate findings, numbered. */
export function verifyPrompt(prompt, findings) {
  const numbered = findings.map(({ path, line, category, title, body, existing_code }, index) => ({ index, path, line, category, title, body, existing_code }));
  return `${prompt}\n\n## Findings to check\n\n\`\`\`json\n${JSON.stringify(numbered, null, 2)}\n\`\`\``;
}

/**
 * Applies the verify pass's verdicts. A finding without a verdict is kept, so a
 * truncated answer never hides a real bug; protected categories are removed only
 * as duplicates, and a duplicate only while the finding it repeats stays.
 */
export function applyVerdicts(findings, verdicts) {
  const rejected = new Set();
  for (const v of verdicts) {
    if (v.keep || rejected.has(v.index) || !findings[v.index]) continue;
    const duplicateOf = /^duplicate of #?(\d+)/i.exec(v.reason ?? "")?.[1];
    if (duplicateOf !== undefined) {
      const target = Number(duplicateOf);
      if (target !== v.index && findings[target] && !rejected.has(target)) rejected.add(v.index);
    } else if (!spec.protected_categories.includes(findings[v.index].category)) {
      rejected.add(v.index);
    }
  }
  return findings.filter((_, index) => !rejected.has(index));
}

/** The same finding, however its line moved: its file and its title, lowercased, punctuation dropped. */
export function fingerprint(f) {
  return `${f.path}\n${String(f.title ?? "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()}`;
}

/**
 * Findings from several passes, once each: the first one reported is kept, and
 * a later one is the same finding when its comment would sit on the same line
 * (where its quoted code ends, by `lines`, else the line it names), or when its
 * fingerprint matches (its line moved). Passes often file one defect under
 * different lines, categories and titles, so where it lands decides.
 */
export function mergeFindings(lists, lines = new Map()) {
  const seen = new Set();
  return lists.flat().filter(f => {
    const keys = [fingerprint(f), `${f.path}:${place(f, lines)?.end ?? f.line}`];
    if (keys.some(k => seen.has(k))) return false;
    keys.forEach(k => seen.add(k));
    return true;
  });
}

/** Resolve refs once; reject comparisons whose API diff would omit changes. */
export async function commitChange(gh, { commit, base, head }) {
  if (commit && (base || head)) throw new Error("Use --commit or --base with --head, not both");
  if (!commit && (!base || !head)) throw new Error("A range requires both --base and --head");
  const target = await gh.commit(commit || head);
  const baseRef = commit ? target.parents?.[0]?.sha : base;
  if (!baseRef) throw new Error("Root commits are not supported; choose a range with an existing base");
  const source = await gh.commit(baseRef);
  const comparison = await gh.compare(source.sha, target.sha);
  if (comparison.merge_base_commit?.sha !== source.sha) {
    throw new Error("The base must be an ancestor of the head; choose their merge base explicitly");
  }
  // GitHub returns at most 300 files and does not paginate this list.
  if (!Array.isArray(comparison.files) || comparison.files.length >= 300) {
    throw new Error("Comparison may be truncated (300-file GitHub limit); review smaller ranges");
  }
  return {
    title: commit ? `Commit ${target.sha}` : `${source.sha}..${target.sha}`,
    body: target.commit.message,
    base: { ref: source.sha, sha: source.sha },
    head: { ref: target.sha, sha: target.sha },
    files: comparison.files,
  };
}

/** Checks are informational: a clean AI review is never an approval. */
export function commitCheck(pr, posted, runUrl) {
  const findings = posted.comments.map(c => `- \`${c.path}:${c.line}\` ${c.body}`).join("\n");
  const summary = `${pr.base.sha}..${pr.head.sha}\n\n${posted.body}${findings ? `\n\n**Findings on changed lines**\n${findings}` : ""}`;
  return {
    name: NAME, head_sha: pr.head.sha, status: "completed", conclusion: "neutral",
    ...(runUrl ? { details_url: runUrl } : {}),
    output: { title: "Commit review", summary },
  };
}

/** Validate only after saving the complete report, so a publishing limit loses no findings. */
export function validateCommitCheck(check) {
  if (Buffer.byteLength(check.output.summary, "utf8") > 65000) {
    throw new Error("Review exceeds GitHub's check output limit; full report saved, no findings posted");
  }
}

async function loadRubric(gh, ref, paths) {
  const parts = [];
  for (const path of paths) {
    const text = await gh.text(path, ref);
    if (text !== null) parts.push(`## ${path}\n\n${text}`);
  }
  return parts.join("\n\n") || DEFAULT_RUBRIC;
}

/** Resolve CLI/Action target precedence without contacting a service. */
export function resolveReviewTarget(values, environment) {
  const commit = values.commit || environment.REVIEW_COMMIT;
  const base = values.base || environment.REVIEW_BASE;
  const head = values.head || environment.REVIEW_HEAD;
  const requestedPr = values.pr || environment.PR_NUMBER;
  const defaultPr = environment.PR_NUMBER_DEFAULT;
  // Action head/base/commit inputs select standalone reviews, even on PR events.
  // CLI --head with a PR retains the historical PR dry-run path.
  const explicitStandalone = Boolean(commit || base || environment.REVIEW_HEAD);
  const historicalHead = !explicitStandalone && (requestedPr || defaultPr) ? values.head : undefined;
  const standalone = explicitStandalone || Boolean(head && !historicalHead);
  if (standalone && requestedPr) throw new Error("Choose a PR or a commit/range");
  if (standalone && commit && (base || head)) throw new Error("Use --commit or --base with --head, not both");
  if (standalone && !commit && (!base || !head)) throw new Error("A range requires both --base and --head");
  if (values.check && (standalone || values.pr || values.head)) throw new Error("--check cannot be combined with a review target");
  const pr = requestedPr || (!standalone && defaultPr);
  if (values.check || (environment.GITHUB_EVENT_NAME === "workflow_dispatch" && !standalone && !pr)) return { kind: "setup" };
  if (standalone) return commit ? { kind: "commit", commit } : { kind: "range", base, head };
  if (!pr) throw new Error("PR_NUMBER is required");
  const number = Number(pr);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error("PR number must be a positive integer");
  return { kind: "pr", number, ...(historicalHead && { historicalHead }) };
}

export async function main(args = process.argv.slice(2), environment = process.env, dependencies = {}) {
  const {
    github: connectGithub = github, nearai: connectModel = nearai,
    attest: attestModel = attest, reviewChange: runReview = reviewChange,
    unpack: unpackHead = unpack, log = console.log,
  } = dependencies;
  const { values } = parseArgs({
    args,
    options: {
      repo: { type: "string" },
      pr: { type: "string" },
      commit: { type: "string" },
      base: { type: "string" },
      "dry-run": { type: "boolean" },
      head: { type: "string" },
      check: { type: "boolean" },
      review: { type: "string" },
      receipt: { type: "string" },
    },
  });
  const env = name => {
    if (!environment[name]) throw new Error(`${name} is required`);
    return environment[name];
  };
  const repo = values.repo ?? env("GITHUB_REPOSITORY");
  const dryRun = values["dry-run"] ?? false;
  const receiptPath = resolve(values.receipt ?? "private-review-receipt.json");
  const model = environment.MODEL || spec.defaults.model;
  const rubricPaths = (environment.RUBRIC || spec.defaults.rubric.join(",")).split(",").map(p => p.trim()).filter(Boolean);
  const maxTurns = Number(environment.MAX_TURNS || spec.defaults.max_turns);
  const passes = Number(environment.PASSES || spec.defaults.passes);
  const allowUnpatchedModel = environment.ALLOW_UNPATCHED_MODEL === "true";
  const verify = environment.VERIFY ? environment.VERIFY !== "false" : spec.defaults.verify;
  if (!Number.isInteger(passes) || passes < 1 || passes > 5) throw new Error(`PASSES must be 1 to 5, not ${environment.PASSES}`);
  const target = resolveReviewTarget(values, environment);
  const standalone = target.kind === "commit" || target.kind === "range";
  const number = target.kind === "pr" ? target.number : null;
  const reviewPath = values.review ? resolve(values.review) : standalone ? resolve("private-review.json") : null;
  if (reviewPath === receiptPath) throw new Error("Review and receipt paths must be different");
  const gh = connectGithub(env("GITHUB_TOKEN"), repo);
  const client = connectModel(env("NEARAI_API_KEY"));

  if (target.kind === "setup") {
    if (!report(await checkSetup({ client, gh, model, allowUnpatchedModel }))) process.exitCode = 1;
    return;
  }

  // The backstop for workflows without the review/gate job ahead of this one.
  const starter = await reviewStarter(commentEvent(environment), gh);
  if (starter && !starter.allowed) {
    log(`::notice::${refusal(starter)}`);
    return;
  }

  const runUrl = environment.GITHUB_RUN_ID && environment.GITHUB_REPOSITORY &&
    `${environment.GITHUB_SERVER_URL || "https://github.com"}/${environment.GITHUB_REPOSITORY}/actions/runs/${environment.GITHUB_RUN_ID}`;
  let checkId;
  let reviewSaved = false;
  try {
    const pr = standalone ? await commitChange(gh, target) : await gh.pull(number);
    if (target.historicalHead) {
      if (!dryRun) throw new Error("--head reviews an earlier commit, so it needs --dry-run");
      const commits = await gh.compare(pr.base.ref, target.historicalHead);
      Object.assign(pr, { base: { ...pr.base, sha: commits.merge_base_commit.sha }, head: { ...pr.head, sha: target.historicalHead }, files: commits.files });
    }
    if (standalone && !pr.files.length) throw new Error("No changed files in this range; no review was started");
    if (standalone && !dryRun) {
      // Verify publishing permissions before spending model credits, and leave
      // an observable running check on the exact revision being reviewed.
      const check = await gh.check({
        name: NAME, head_sha: pr.head.sha, status: "in_progress",
        ...(runUrl ? { details_url: runUrl } : {}),
        output: { title: "Reviewing commit range", summary: `${pr.base.sha}..${pr.head.sha}` },
      });
      if (!Number.isInteger(check.id)) throw new Error("GitHub did not return a check run id");
      checkId = check.id;
    }
    const [files, rubric, tarball, earlier] = await Promise.all([
      pr.files ?? gh.files(number),
      loadRubric(gh, pr.base.sha, rubricPaths),
      gh.tarball(pr.head.sha),
      standalone || target.historicalHead ? [] : earlierFindings(gh, number),
    ]);
    log(`${standalone ? "commit range" : `#${number}`}: ${files.length} files changed, ${earlier.length} earlier findings; head ${pr.head.sha}`);

    const { evidence, attestation } = await attestModel(client, model, { allowUnpatchedModel })
      .catch(error => { throw new Error(`attestation failed, so no code was sent: ${modelProblem(model, error)}`); });
    log(`attested: model TCB ${attestation.model.tcb}, gateway TCB ${attestation.gateway.tcb}, signer ${attestation.model.signer}`);

    const head = unpackHead(tarball);
    let result;
    try {
      result = await runReview({
        client, model, publicKey: attestation.model.publicKey, pr, files, rubric, root: head.root, maxTurns, earlier, passes, verify, log,
      });
    } finally {
      head.remove();
    }
    log(`reviewed: ${result.review.findings.length} findings (${result.review.verification}) in ${result.turns.length} signed turns`);

    const { text, sha256: receiptSha256 } = receipt({
      subject: { ...(standalone ? { repository: repo } : { pull_request: `${repo}#${number}` }), base_sha: pr.base.sha, head_sha: pr.head.sha },
      model,
      evidence,
      turns: result.turns,
    });
    writeFileSync(receiptPath, text);
    log(`receipt: ${receiptPath} sha256 ${receiptSha256}`);

    const posted = renderReview({ review: result.review, turns: result.turns, attestation, model, receiptSha256, runUrl, lines: newLines(files) });
    const output = standalone ? commitCheck(pr, posted, runUrl) : posted;
    // Keep every finding before validation or network writes. The receipt
    // contains hashes, so it cannot recover a report that fails to publish.
    if (reviewPath) {
      writeFileSync(reviewPath, `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
      reviewSaved = true;
      log(`review: ${reviewPath}`);
    }
    if (standalone) validateCommitCheck(output);
    if (dryRun) {
      if (!values.review) log(JSON.stringify(output, null, 2));
      return;
    }
    if (standalone) {
      await gh.updateCheck(checkId, { status: output.status, conclusion: output.conclusion, output: output.output });
      log("posted: commit check");
      return;
    }
    await gh.review(number, { commit_id: pr.head.sha, event: "COMMENT", ...posted });
    log(`posted: ${posted.comments.length} inline comments`);
  } catch (error) {
    if (checkId !== undefined) await gh.updateCheck(checkId, {
      status: "completed", conclusion: "failure",
      output: {
        title: "Review stopped",
        summary: reviewSaved
          ? "Publishing the review failed. The complete report and receipt were saved by the runner; check the workflow artifacts or local files before trying again."
          : "The review did not complete. Check the review runner's log before trying again.",
      },
    }).catch(() => {});
    if (!dryRun && !standalone) await gh.comment(number, `**${NAME} stopped:** ${error.message}. No code was posted anywhere else. Re-run the job to try again; if it keeps stopping, the run's log names the step.`).catch(() => {});
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.message);
    process.exit(1);
  });
}
