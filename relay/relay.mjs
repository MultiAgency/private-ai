import { CallError } from "./outlayer.mjs";

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

// Opt-in only: a `/review` comment or a check Re-run starts a review. Opening,
// reopening, leaving draft, and later pushes do not (owner, 2026-10-13). That
// keeps noise and OutLayer spend down, and matches "ask when you want it."

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
  if (event === "issue_comment" && payload.action === "created" && payload.issue?.pull_request && /^\/review\b/.test(payload.comment?.body ?? "")
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

/**
 * Install / repo-scope changes for the stats Durable Object, or null.
 * Keeps account login (for internal "who installed") and counts — never repo names.
 */
export function installationEvent(event, payload) {
  const installation = payload?.installation?.id;
  if (!Number.isInteger(installation)) return null;
  const account = payload?.installation?.account?.login ?? payload?.account?.login ?? null;
  const account_type = payload?.installation?.account?.type ?? payload?.account?.type ?? null;
  if (event === "installation") {
    if (payload.action === "created") {
      const repos = Array.isArray(payload.repositories) ? payload.repositories.length : 0;
      return { type: "install", installation, account, account_type, repos };
    }
    if (payload.action === "deleted") return { type: "uninstall", installation, account, account_type };
    if (payload.action === "suspend") return { type: "suspend", installation, account, account_type };
    if (payload.action === "unsuspend") return { type: "unsuspend", installation, account, account_type };
  }
  if (event === "installation_repositories") {
    const added = Array.isArray(payload.repositories_added) ? payload.repositories_added.length : 0;
    const removed = Array.isArray(payload.repositories_removed) ? payload.repositories_removed.length : 0;
    if (!added && !removed) return null;
    return { type: "repos", installation, account, account_type, added, removed };
  }
  return null;
}

/** OutLayer's input for a new review: ids, and a nonce so its public input hash can't be guessed. */
export function eventInput(request) {
  return { event: { ...request, nonce: hex(crypto.getRandomValues(new Uint8Array(16))) } };
}

// A known failed execution can be retried: the enclave dedupes the event or
// resumes its saved step. A submission with an unknown outcome cannot.
export const RETRIES = 4;
export const MAX_QUEUED = 10;
export const POLL_INTERVAL = 10_000;
export const PENDING_LIMIT = 15 * 60_000;

/** One HTTP request per alarm; accepted call ids survive restarts and retries. */
export function driver({ storage, execution, log = () => {}, note = async () => {}, now = Date.now }) {
  // Re-read after I/O so a request enqueued during a call stays behind its head.
  async function save(head, delay) {
    const [, ...rest] = (await storage.get("queue")) ?? [];
    const queue = head ? [head, ...rest] : rest;
    await storage.put("queue", queue);
    if (queue.length && !queue[0].paused) await storage.setAlarm(now() + delay);
  }
  async function pause(head, error) {
    await save({ ...head, paused: true }, 0);
    const call = head.callId ? ` (call ${head.callId})` : "";
    log(`review paused${call}: ${error}`);
    await note({ type: "outlayer_error", error, ...(head.callId && { call_id: head.callId }) });
  }
  return {
    async enqueue(input) {
      const queue = (await storage.get("queue")) ?? [];
      if (queue.length >= MAX_QUEUED) {
        log("a pull request's queue is full; a request was dropped");
        await note({ type: "queue_drop" });
        return;
      }
      // A fresh command may resume polling an existing call, never resubmit it.
      if (queue[0]?.paused && queue[0].callId) {
        queue[0] = { ...queue[0], paused: false, waitingSince: now(), pollFailures: 0 };
      }
      await storage.put("queue", [...queue, { input, tries: 0, protocol: 1 }]);
      if (!queue[0]?.paused && !(await storage.getAlarm())) await storage.setAlarm(now());
    },

    async alarm() {
      let head = ((await storage.get("queue")) ?? [])[0];
      if (!head || head.paused) return;
      if (head.protocol !== 1 || (head.submitting && !head.callId)) {
        await pause(head, "submission outcome unknown; not resubmitting");
        return;
      }
      let result;
      try {
        if (head.callId) {
          result = await execution.poll(head.callId);
        } else {
          // Crash between POST and saving its id is ambiguous, so fail closed.
          // The watchdog alarm also recovers a handler interrupted by deployment.
          head = { ...head, submitting: true };
          await save(head, 30_000);
          result = await execution.start(head.input);
          head = { ...head, submitting: false, callId: result.call_id, waitingSince: now() };
        }
      } catch (e) {
        const error = e instanceof CallError ? e.message : "OutLayer request failed";
        if (head.callId) {
          const failures = (head.pollFailures ?? 0) + 1;
          if (failures < RETRIES) await save({ ...head, pollFailures: failures }, 30_000 * failures);
          else await pause(head, error);
        } else if (e instanceof CallError && e.refused) {
          const tries = head.tries + 1;
          if (e.retryable && tries < RETRIES) {
            await save({ input: head.input, tries, protocol: 1 }, Math.max(30_000 * tries, e.delay));
          } else {
            await save(null, 0);
            log(`OutLayer refused review: ${error}`);
            await note({ type: "outlayer_error", error });
          }
        } else {
          await pause(head, `${error}; submission outcome unknown; not resubmitting`);
        }
        return;
      }

      if (result.status === "pending") {
        head = { ...head, pollFailures: 0 };
        if (now() - head.waitingSince >= PENDING_LIMIT) {
          await pause(head, "OutLayer execution still pending after 15 minutes");
        } else {
          await save(head, POLL_INTERVAL);
          log(`call ${head.callId}: pending`);
        }
        return;
      }
      const output = result.output;
      if (result.status === "failed" || output == null || typeof output !== "object" || Array.isArray(output)) {
        const error = result.status === "failed" ? "OutLayer execution failed" : "OutLayer execution returned no valid output";
        if (head.tries + 1 < RETRIES) {
          await save({ input: head.input, tries: head.tries + 1, protocol: 1 }, 30_000 * (head.tries + 1));
        } else {
          await save(null, 0);
          log(`gave up on an input after ${RETRIES} tries: ${error}`);
          await note({ type: "outlayer_error", error, call_id: head.callId });
        }
        return;
      }
      await save(output.more === true && typeof output.job === "string"
        ? { input: { step: output.job }, tries: 0, protocol: 1 } : null, 0);
      if (output.job) {
        log(`job ${output.job}: ${output.more ? "more" : output.failed ? `failed (${output.failed})` : "done"}`);
        if (output.more !== true) {
          await note(output.failed
            ? { type: "job_failed", job: output.job, failed: output.failed }
            : { type: "job_done", job: output.job });
        }
      } else if (output.failed) {
        await note({ type: "job_failed", failed: output.failed });
      }
    },
  };
}
