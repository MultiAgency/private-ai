import assert from "node:assert/strict";
import test from "node:test";

import { github } from "../review/github.mjs";

// Answers GitHub's REST calls from `routes` (method + path with query) and records them.
async function withGitHub(routes, run) {
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const { pathname, search } = new URL(url);
    calls.push({ method: init.method, path: pathname + search, headers: init.headers, body: init.body });
    const route = routes[`${init.method} ${pathname + search}`];
    if (!route) return new Response("not found", { status: 404 });
    return typeof route === "function" ? route() : Response.json(route);
  };
  try {
    return await run(github("t0ken", "o/r"), calls);
  } finally {
    globalThis.fetch = real;
  }
}

test("a request carries the token and the API version, and a refusal names the status without the query", async () => {
  await withGitHub({ "GET /repos/o/r/pulls/3": { number: 3 }, "GET /repos/o/r/pulls?per_page=1": () => new Response("no", { status: 403 }) }, async (gh, calls) => {
    assert.deepEqual(await gh.pull(3), { number: 3 });
    assert.equal(calls[0].headers.authorization, "Bearer t0ken");
    assert.equal(calls[0].headers["x-github-api-version"], "2022-11-28");
    await assert.rejects(gh.pulls(), error => error.status === 403 && error.message === "GitHub GET /pulls: 403");
  });
});

test("a list is read page by page until a page is short", async () => {
  const page = (from, n) => Array.from({ length: n }, (_, i) => ({ filename: `f${from + i}` }));
  await withGitHub({
    "GET /repos/o/r/pulls/3/files?per_page=100&page=1": page(0, 100),
    "GET /repos/o/r/pulls/3/files?per_page=100&page=2": page(100, 5),
  }, async (gh, calls) => {
    const files = await gh.files(3);
    assert.equal(files.length, 105);
    assert.equal(files[104].filename, "f104");
    assert.equal(calls.length, 2);
  });
});

test("a file's text is fetched raw by an encoded path, and a missing file is null, not an error", async () => {
  await withGitHub({
    "GET /repos/o/r/contents/docs/a%20b/REVIEW.md?ref=abc123": () => new Response("# rules\n"),
    "GET /repos/o/r/contents/boom.md?ref=abc123": () => new Response("x", { status: 500 }),
  }, async (gh, calls) => {
    assert.equal(await gh.text("docs/a b/REVIEW.md", "abc123"), "# rules\n");
    assert.equal(calls[0].headers.accept, "application/vnd.github.raw+json");
    assert.equal(await gh.text("AGENTS.md", "abc123"), null);
    await assert.rejects(gh.text("boom.md", "abc123"), error => error.status === 500);
  });
});

test("a user's role is read from GitHub, and someone GitHub doesn't know has none", async () => {
  await withGitHub({ "GET /repos/o/r/collaborators/dev/permission": { role_name: "write" } }, async gh => {
    assert.equal(await gh.role("dev"), "write");
    assert.equal(await gh.role("stranger"), "none");
  });
});

test("a review is posted to the pull request as JSON, a comment to its issue", async () => {
  await withGitHub({ "POST /repos/o/r/pulls/3/reviews": {}, "POST /repos/o/r/issues/3/comments": {} }, async (gh, calls) => {
    await gh.review(3, { event: "COMMENT", body: "hi", comments: [] });
    await gh.comment(3, "stopped");
    assert.deepEqual(JSON.parse(calls[0].body), { event: "COMMENT", body: "hi", comments: [] });
    assert.deepEqual(JSON.parse(calls[1].body), { body: "stopped" });
  });
});
