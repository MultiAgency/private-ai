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

const WRITE_ROLES = ["admin", "maintain", "write"];

/** Who started the run and whether they may: null when it wasn't a comment. */
export async function reviewStarter(event, gh) {
  if (!event?.comment) return null;
  const login = event.comment.user.login;
  const role = await gh.role(login);
  return { login, role, allowed: WRITE_ROLES.includes(role) };
}

/** The GitHub Actions event that started this run, when it was a comment. */
export function commentEvent(env = process.env) {
  return env.GITHUB_EVENT_NAME === "issue_comment" ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")) : null;
}

export const refusal = ({ login, role }) =>
  `Not reviewing: @${login} has the ${role} role, and starting a review with /review needs write access.`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const starter = await reviewStarter(commentEvent(), github(process.env.GITHUB_TOKEN, process.env.GITHUB_REPOSITORY));
  const allowed = !starter || starter.allowed;
  if (!allowed) console.log(`::notice::${refusal(starter)}`);
  appendFileSync(process.env.GITHUB_OUTPUT, `allowed=${allowed}\n`);
}
