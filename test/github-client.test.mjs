import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";

import { github } from "../review/github.mjs";

describe("the Action's GitHub client", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => { globalThis.fetch = realFetch; });

  const gh = github("tok", "owner/repo");
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status });
  const record = reply => {
    const calls = [];
    globalThis.fetch = async (url, init) => { calls.push({ url: String(url), ...init }); return reply(calls.length, String(url)); };
    return calls;
  };

  test("sends the token and API version to the repository's endpoint", async () => {
    const calls = record(() => json({ number: 7 }));
    assert.deepEqual(await gh.pull(7), { number: 7 });
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/pulls/7");
    assert.equal(calls[0].method, "GET");
    assert.equal(calls[0].headers.authorization, "Bearer tok");
    assert.equal(calls[0].headers.accept, "application/vnd.github+json");
    assert.equal(calls[0].headers["x-github-api-version"], "2022-11-28");
    assert.equal(calls[0].body, undefined);
  });

  test("a failed call throws with the status, and the query string stays out of the message", async () => {
    record(() => json({}, 403));
    await assert.rejects(gh.pulls(), error => {
      assert.equal(error.message, "GitHub GET /pulls: 403");
      assert.equal(error.status, 403);
      return true;
    });
  });

  test("lists read every page until a short one", async () => {
    const calls = record(call => json(Array.from({ length: call < 3 ? 100 : 5 }, (_, i) => ({ id: call * 1000 + i }))));
    const files = await gh.files(3);
    assert.equal(files.length, 205);
    assert.deepEqual(calls.map(c => c.url), [1, 2, 3].map(page => `https://api.github.com/repos/owner/repo/pulls/3/files?per_page=100&page=${page}`));
  });

  test("a list that ends on a full page asks once more, and an empty list is one request", async () => {
    const calls = record(call => json(call === 1 ? Array.from({ length: 100 }, (_, i) => i) : []));
    assert.equal((await gh.reviews(3)).length, 100);
    assert.equal(calls.length, 2);
    const again = record(() => json([]));
    assert.deepEqual(await gh.reviewComments(3), []);
    assert.equal(again.length, 1);
    assert.match(again[0].url, /\/pulls\/3\/comments\?per_page=100&page=1$/);
  });

  test("a file's text is fetched raw, with each path segment encoded", async () => {
    const calls = record(() => new Response("hello"));
    assert.equal(await gh.text("src/a b/c#d.js", "abc123"), "hello");
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/contents/src/a%20b/c%23d.js?ref=abc123");
    assert.equal(calls[0].headers.accept, "application/vnd.github.raw+json");
  });

  test("a file that does not exist at the commit is null; other errors throw", async () => {
    record(() => json({}, 404));
    assert.equal(await gh.text("gone.js", "abc"), null);
    record(() => json({}, 500));
    await assert.rejects(gh.text("a.js", "abc"), /500/);
  });

  test("a user's role is read from the collaborator's permission, and 404 means none", async () => {
    const calls = record(() => json({ role_name: "maintain" }));
    assert.equal(await gh.role("some user"), "maintain");
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/collaborators/some%20user/permission");
    record(() => json({}, 404));
    assert.equal(await gh.role("stranger"), "none");
    record(() => json({}, 502));
    await assert.rejects(gh.role("x"), /502/);
  });

  test("compare, tarball, review and comment hit their endpoints", async () => {
    let calls = record(() => json({ files: [] }));
    await gh.compare("base", "head");
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/compare/base...head");

    calls = record(() => new Response(new Uint8Array([1, 2, 3])));
    const tarball = await gh.tarball("sha1");
    assert.ok(Buffer.isBuffer(tarball));
    assert.deepEqual([...tarball], [1, 2, 3]);
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/tarball/sha1");

    calls = record(() => json({}));
    await gh.review(9, { event: "COMMENT", body: "x" });
    assert.equal(calls[0].method, "POST");
    assert.equal(calls[0].url, "https://api.github.com/repos/owner/repo/pulls/9/reviews");
    assert.deepEqual(JSON.parse(calls[0].body), { event: "COMMENT", body: "x" });

    await gh.comment(9, "hi");
    assert.equal(calls[1].url, "https://api.github.com/repos/owner/repo/issues/9/comments");
    assert.deepEqual(JSON.parse(calls[1].body), { body: "hi" });
  });
});
