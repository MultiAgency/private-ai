// Preloaded (node --import) into eval/collect.mjs's process: answers its GitHub
// calls for one pull request whose review has two reacted findings on one
// commit, so the script runs with no network.
const reply = body => new Response(JSON.stringify(body));
const ours = { id: 500, user: { login: process.env.FAKE_REVIEW_AUTHOR }, body: `**${process.env.FAKE_REVIEW_NAME}**\n\nfindings` };

globalThis.fetch = async (url, init = {}) => {
  const { pathname } = new URL(url);
  if (pathname === "/graphql") {
    return reply({ data: { repository: { pullRequest: { userContentEdits: { nodes: [
      { editedAt: "2026-01-01T00:00:00Z", diff: "old description" },
      { editedAt: "2026-01-02T00:00:00Z", diff: "description at review time" },
      { editedAt: "2026-01-05T00:00:00Z", diff: "edited after the review" },
    ] } } } } });
  }
  if (pathname === "/repos/o/r/pulls") {
    return reply([
      { number: 5, base: { ref: "main" }, body: "current description", updated_at: new Date().toISOString() },
      { number: 4, base: { ref: "main" }, body: "stale", updated_at: "2000-01-01T00:00:00Z" },
    ]);
  }
  if (pathname === "/repos/o/r/pulls/5/reviews") {
    return reply([ours, { id: 501, user: { login: "someone" }, body: `**${process.env.FAKE_REVIEW_NAME}**` }]);
  }
  if (pathname === "/repos/o/r/pulls/5/comments") {
    return reply([
      { id: 1, pull_request_review_id: 500, commit_id: "abcdef1234567", created_at: "2026-01-03T00:00:00Z", body: "real bug", reactions: { "+1": 2, "-1": 0 } },
      { id: 2, pull_request_review_id: 500, commit_id: "abcdef1234567", created_at: "2026-01-03T00:00:00Z", body: "noise", reactions: { "+1": 0, "-1": 1 } },
      { id: 3, pull_request_review_id: 500, commit_id: "abcdef1234567", created_at: "2026-01-03T00:00:00Z", body: "split vote", reactions: { "+1": 1, "-1": 1 } },
      { id: 4, pull_request_review_id: 501, commit_id: "abcdef1234567", created_at: "2026-01-03T00:00:00Z", body: "not ours", reactions: { "+1": 9 } },
    ]);
  }
  if (pathname === "/repos/o/r/compare/main...abcdef1234567") return reply({ merge_base_commit: { sha: "basebase" } });
  return new Response("unexpected " + init.method + " " + pathname, { status: 404 });
};
