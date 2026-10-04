// Turns 👍 and 👎 on private-review findings into eval cases. A 👍 finding
// becomes a bug a review of that commit should raise, and a 👎 finding a false
// positive it should not. Each case pins the finding's commit and the pull
// request's description as it stood when the finding was posted, from the
// description's edit history, so a later edit can't hand the review the answer.
//
// Usage: node eval/collect.mjs --repo owner/name [--days 30] [--out eval/feedback]
// Env: GITHUB_TOKEN.
//
// The default out dir is gitignored. Feedback from a private repository holds
// its findings and description, so it stays on the machine that collected it.
// Only a public repository's cases belong in eval/cases.
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { github } from "../review/github.mjs";
import { isOurReview } from "../review/review.mjs";
import { question } from "./judge.mjs";

const { values } = parseArgs({
  options: { repo: { type: "string" }, days: { type: "string", default: "30" }, out: { type: "string", default: "eval/feedback" } },
});
if (!values.repo) throw new Error("--repo is required");
const token = process.env.GITHUB_TOKEN;
const gh = github(token, values.repo);
const since = new Date(Date.now() - Number(values.days) * 86_400_000).toISOString();
const api = path => fetch(`https://api.github.com${path}`, { headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" } })
  .then(r => (r.ok ? r.json() : Promise.reject(new Error(`GitHub GET ${path.split("?")[0]}: ${r.status}`))));

/** The description as it stood at `at`: the latest edit no later than that, else the current body. */
async function descriptionAt(number, at, current) {
  const [owner, name] = values.repo.split("/");
  const query = `query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){userContentEdits(first:100){nodes{editedAt diff}}}}}`;
  const r = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ query, variables: { o: owner, n: name, p: number } }),
  }).then(res => res.json());
  const edits = (r.data?.repository?.pullRequest?.userContentEdits?.nodes ?? []).filter(e => e.diff != null && e.editedAt <= at);
  return edits.sort((a, b) => a.editedAt.localeCompare(b.editedAt)).at(-1)?.diff ?? current ?? "";
}

const pulls = (await api(`/repos/${values.repo}/pulls?state=all&sort=updated&direction=desc&per_page=100`)).filter(p => p.updated_at >= since);
const out = resolve(values.out);
mkdirSync(out, { recursive: true });
let cases = 0, verdicts = 0;
for (const pr of pulls) {
  const ours = new Set((await gh.reviews(pr.number)).filter(r => isOurReview(r.body)).map(r => r.id));
  if (ours.size === 0) continue;
  const byCommit = new Map();
  for (const c of await gh.reviewComments(pr.number)) {
    if (!ours.has(c.pull_request_review_id)) continue;
    const net = (c.reactions?.["+1"] ?? 0) - (c.reactions?.["-1"] ?? 0);
    if (net === 0) continue;
    const entry = byCommit.get(c.commit_id) ?? { bugs: {}, falsePositives: {}, at: c.created_at };
    (net > 0 ? entry.bugs : entry.falsePositives)[`comment-${c.id}`] = question(c.body);
    byCommit.set(c.commit_id, entry);
    verdicts++;
  }
  for (const [head, entry] of byCommit) {
    const compare = await api(`/repos/${values.repo}/compare/${pr.base.ref}...${head}`);
    const slug = `${values.repo.replace("/", "-")}-${pr.number}-${head.slice(0, 7)}`;
    writeFileSync(join(out, `${slug}.md`), await descriptionAt(pr.number, entry.at, pr.body));
    writeFileSync(join(out, `${slug}.json`), `${JSON.stringify({
      name: `${values.repo}#${pr.number} at ${head.slice(0, 7)}: reactions on private-review findings`,
      repo: values.repo,
      pull_request: pr.number,
      base: compare.merge_base_commit.sha,
      head,
      description: `${slug}.md`,
      source: "👍 and 👎 on private-review findings (eval/collect.mjs).",
      bugs: entry.bugs,
      falsePositives: entry.falsePositives,
    }, null, 2)}\n`);
    cases++;
  }
}
console.log(`${verdicts} reacted findings → ${cases} cases in ${out}`);
