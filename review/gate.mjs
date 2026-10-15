// Who may start a review by commenting `/review`: someone who could push to the
// repository. Each review spends the NEAR AI key's credits and posts to the
// pull request, and starting one cancels a review already running.
//
// The review/gate action runs this in a job of its own, ahead of the review
// job, so a refused comment never reaches the review job's concurrency group
// and so can't cancel anything. review.mjs repeats the check for workflows
// without that job. Dependency-free, so the gate job needs no `npm ci`.
//
// As a script: reads GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY
// and GITHUB_TOKEN, and writes `allowed=true|false` to GITHUB_OUTPUT.
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { github } from "./github.mjs";

const WRITE_PERMISSIONS = ["admin", "write"];

/** Who started the run and whether they may: null when it wasn't a comment. */
export async function reviewStarter(event, gh) {
  if (!event?.comment) return null;
  const login = event.comment.user.login;
  const { permission, role } = await gh.access(login);
  return { login, role, allowed: WRITE_PERMISSIONS.includes(permission) };
}

/** Comment-triggered runs spend the model key only after this separate job passes. */
export async function reviewGate(event, gh, { repo, allowForks } = {}) {
  if (!event) return { allowed: true };
  if (event.action !== "created" || !event.issue?.pull_request || !/^\/review(?:\s|$)/.test(event.comment?.body ?? "")) {
    return { allowed: false, reason: "Not a /review command on a pull request." };
  }
  const starter = await reviewStarter(event, gh);
  if (!starter?.allowed) return { allowed: false, reason: starter ? refusal(starter) : "No review requester." };
  // Old gate workflows grant only contents:read. Preserve their role-only
  // behavior until they explicitly opt into the new PR policy and permission.
  if (allowForks === undefined) return { allowed: true };
  const pr = await gh.pull(event.issue.number);
  if (pr.state !== "open" || pr.draft) return { allowed: false, reason: "Not reviewing a closed or draft pull request." };
  const headRepo = pr.head?.repo?.full_name;
  if (typeof headRepo !== "string") return { allowed: false, reason: "The pull request's source repository is unavailable." };
  if (!allowForks && (typeof repo !== "string" || headRepo.toLowerCase() !== repo.toLowerCase())) {
    return { allowed: false, reason: "Fork reviews are not enabled in this workflow." };
  }
  return { allowed: true };
}

/** The GitHub Actions event that started this run, when it was a comment. */
export function commentEvent(env = process.env) {
  return env.GITHUB_EVENT_NAME === "issue_comment" ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")) : null;
}

export const refusal = ({ login, role }) =>
  `Not reviewing: @${login} has the ${role} role, and starting a review with /review needs write access.`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const repo = process.env.GITHUB_REPOSITORY;
  const { allowed, reason } = await reviewGate(commentEvent(), github(process.env.GITHUB_TOKEN, repo), {
    repo, allowForks: process.env.ALLOW_FORKS ? process.env.ALLOW_FORKS === "true" : undefined,
  });
  if (!allowed) console.log(`::notice::${reason}`);
  appendFileSync(process.env.GITHUB_OUTPUT, `allowed=${allowed}\n`);
}
