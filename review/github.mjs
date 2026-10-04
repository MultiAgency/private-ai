// The few GitHub REST calls a review makes, for one repository.
export function github(token, repo) {
  async function send(method, path, { body, accept = "application/vnd.github+json" } = {}) {
    const response = await fetch(`https://api.github.com/repos/${repo}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, accept, "x-github-api-version": "2022-11-28" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) {
      throw Object.assign(new Error(`GitHub ${method} ${path.split("?")[0]}: ${response.status}`), { status: response.status });
    }
    return response;
  }

  return {
    pull: number => send("GET", `/pulls/${number}`).then(r => r.json()),

    async files(number) {
      const files = [];
      for (let page = 1; ; page++) {
        const batch = await send("GET", `/pulls/${number}/files?per_page=100&page=${page}`).then(r => r.json());
        files.push(...batch);
        if (batch.length < 100) return files;
      }
    },

    /** A file's text at a commit, or null when it does not exist there. */
    async text(path, ref) {
      try {
        return await send("GET", `/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${ref}`, {
          accept: "application/vnd.github.raw+json",
        }).then(r => r.text());
      } catch (error) {
        if (error.status === 404) return null;
        throw error;
      }
    },

    /** A user's role on the repository: admin, maintain, write, triage, read or none. */
    async role(login) {
      try {
        return (await send("GET", `/collaborators/${encodeURIComponent(login)}/permission`).then(r => r.json())).role_name;
      } catch (error) {
        if (error.status === 404) return "none";
        throw error;
      }
    },

    tarball: ref => send("GET", `/tarball/${ref}`).then(async r => Buffer.from(await r.arrayBuffer())),

    review: (number, body) => send("POST", `/pulls/${number}/reviews`, { body }),
    comment: (number, body) => send("POST", `/issues/${number}/comments`, { body: { body } }),
  };
}
