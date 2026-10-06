// What the relay does with a GitHub webhook, kept free of Cloudflare so it can
// be tested anywhere: check GitHub's signature, decide whether the event asks
// for a review, and reduce it to ids. The payload (titles, descriptions,
// commenters) goes no further than this function: OutLayer receives ids and a
// nonce, and the enclave reads everything else from GitHub itself.

const encoder = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");

/** Whether `X-Hub-Signature-256` is GitHub's HMAC-SHA256 of the exact body under our secret. */
export async function signedByGitHub(secret, body, header) {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = `sha256=${hex(await crypto.subtle.sign("HMAC", key, encoder.encode(body)))}`;
  if (expected.length !== header.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ header.charCodeAt(i);
  return diff === 0;
}

// Reviewed on its own when a pull request opens, reopens or leaves draft; a
// later push is reviewed on request (/review, or Re-run on the check), which
// keeps the noise and the cost down (owner, 2026-10-05).
const PR_ACTIONS = new Set(["opened", "reopened", "ready_for_review"]);

// A `/review` from someone with no history in the repository is dropped here,
// before it costs an OutLayer call: they cannot write to it. Everyone else's
// goes on, and the enclave checks their permission on GitHub (an organization
// member can show as a contributor, so the association alone decides nothing more).
const STRANGERS = new Set(["NONE", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN"]);

/**
 * The ids of the pull request an event asks to review, or null. A `/review`
 * comment is passed on by its id: the enclave reads the comment from GitHub and
 * checks that its author can write to the repository. A Re-run passes the check
 * run's id, so a deliberate re-run is told from a repeated delivery. The relay
 * decides nothing that matters, and sends no names.
 */
export function reviewRequest(event, payload) {
  const installation = payload?.installation?.id;
  const repo = payload?.repository?.id;
  if (!Number.isInteger(installation) || !Number.isInteger(repo)) return null;
  let pr;
  let comment;
  let rerun;
  if (event === "pull_request" && PR_ACTIONS.has(payload.action)) pr = payload.pull_request?.number;
  else if (event === "issue_comment" && payload.action === "created" && payload.issue?.pull_request && /^\/review\b/.test(payload.comment?.body ?? "")
    && !STRANGERS.has(payload.comment?.author_association ?? "NONE")) {
    pr = payload.issue.number;
    comment = payload.comment.id;
  } else if (event === "check_run" && payload.action === "rerequested") {
    pr = payload.check_run?.pull_requests?.[0]?.number;
    rerun = payload.check_run?.id;
  }
  if (!Number.isInteger(pr)) return null;
  return { installation, repo_id: repo, pr, ...(Number.isInteger(comment) && { comment }), ...(Number.isInteger(rerun) && { rerun }) };
}

/** OutLayer's input for a new review: ids, and a nonce so its public input hash can't be guessed. */
export function eventInput(request) {
  return { event: { ...request, nonce: hex(crypto.getRandomValues(new Uint8Array(16))) } };
}

const RETRIES = 3;
/** Inputs a pull request may have waiting; more are dropped (a flood of requests). */
export const MAX_QUEUED = 10;

/**
 * One pull request's driver: a queue of OutLayer inputs, worked through one
 * call per alarm, and again while the output says there is more.
 *
 * - `storage`: `get`/`put` of the queue, and `getAlarm`/`setAlarm` (ms since
 *   the epoch), as a Durable Object's storage has them.
 * - `call(input)`: one OutLayer call; it resolves to the run's output and
 *   throws when there is none.
 * - `log(line)`: ids only.
 *
 * Retrying any input is safe: the enclave dedupes a repeated event (its
 * request marker) and a repeated step (a run that never answered counts once,
 * app/src/job.rs `in_flight`).
 */
export function driver({ storage, call, log = () => {}, now = Date.now }) {
  return {
    /** Queues an input and wakes the driver, unless the queue is full. */
    async enqueue(input) {
      const queue = (await storage.get("queue")) ?? [];
      if (queue.length >= MAX_QUEUED) return log("a pull request's queue is full; a request was dropped");
      await storage.put("queue", [...queue, { input, tries: 0 }]);
      if (!(await storage.getAlarm())) await storage.setAlarm(now());
    },

    /** One call on the queue's head, then the queue as the call left it. */
    async alarm() {
      const head = ((await storage.get("queue")) ?? [])[0];
      if (!head) return;
      let output;
      let error;
      try {
        output = await call(head.input);
        if (output == null) throw new Error("the run returned no output");
      } catch (e) {
        error = e.message;
      }
      // Read again: requests that arrived during the call joined the queue's
      // end, so the head is still first.
      const [, ...rest] = (await storage.get("queue")) ?? [head];
      let queue = rest;
      let delay = 0;
      if (error && head.tries + 1 < RETRIES) {
        queue = [{ ...head, tries: head.tries + 1 }, ...rest];
        delay = 30_000 * (head.tries + 1);
      } else if (error) {
        log(`gave up on an input after ${RETRIES} tries: ${error}`);
      } else {
        if (output.more === true && typeof output.job === "string") queue = [{ input: { step: output.job }, tries: 0 }, ...rest];
        if (output.job) log(`job ${output.job}: ${output.more ? "more" : output.failed ? `failed (${output.failed})` : "done"}`);
      }
      await storage.put("queue", queue);
      if (queue.length) await storage.setAlarm(now() + delay);
    },
  };
}
