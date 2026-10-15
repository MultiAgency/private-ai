// Pure stats store for the relay's observation layer. The Cloudflare Durable
// Object wraps this; tests run it in memory. Only ids and account logins —
// never repository names, titles, or code.

export const RECENT_MAX = 100;

/** Empty counters and lists. */
export function emptyStats() {
  return {
    installs: 0,
    uninstalls: 0,
    repos_added: 0,
    repos_removed: 0,
    review_requests: 0,
    jobs_done: 0,
    jobs_failed: 0,
    outlayer_errors: 0,
    queue_drops: 0,
    failed_by_reason: {},
    installations: {},
    recent: [],
  };
}

/**
 * Apply one observation. Returns the next state.
 * Events:
 * - install | uninstall | suspend | unsuspend
 * - repos ({ added, removed })
 * - review_request ({ installation, repo_id, pr, trigger })
 * - job_done | job_failed ({ job, failed? })
 * - outlayer_error ({ error })
 * - queue_drop
 */
export function applyStat(state, event, at = Date.now()) {
  const next = {
    ...state,
    failed_by_reason: { ...state.failed_by_reason },
    installations: { ...state.installations },
    recent: [...state.recent],
  };
  const id = event.installation;
  const bumpInstall = patch => {
    if (!Number.isInteger(id)) return;
    const cur = next.installations[id] ?? { installation: id, account: null, account_type: null, repos: 0, status: "unknown", updated_at: at };
    next.installations[id] = { ...cur, ...patch, updated_at: at };
  };

  switch (event.type) {
    case "install":
      next.installs += 1;
      bumpInstall({
        account: event.account ?? null,
        account_type: event.account_type ?? null,
        repos: event.repos ?? 0,
        status: "active",
      });
      break;
    case "uninstall":
      next.uninstalls += 1;
      bumpInstall({ status: "removed", account: event.account ?? next.installations[id]?.account ?? null });
      break;
    case "suspend":
      bumpInstall({ status: "suspended" });
      break;
    case "unsuspend":
      bumpInstall({ status: "active" });
      break;
    case "repos":
      next.repos_added += event.added ?? 0;
      next.repos_removed += event.removed ?? 0;
      if (Number.isInteger(id)) {
        const cur = next.installations[id] ?? { installation: id, account: event.account ?? null, account_type: event.account_type ?? null, repos: 0, status: "active", updated_at: at };
        next.installations[id] = {
          ...cur,
          account: event.account ?? cur.account,
          account_type: event.account_type ?? cur.account_type,
          repos: Math.max(0, (cur.repos ?? 0) + (event.added ?? 0) - (event.removed ?? 0)),
          status: cur.status === "removed" ? "removed" : "active",
          updated_at: at,
        };
      }
      break;
    case "review_request":
      next.review_requests += 1;
      break;
    case "job_done":
      next.jobs_done += 1;
      break;
    case "job_failed":
      next.jobs_failed += 1;
      if (event.failed) next.failed_by_reason[event.failed] = (next.failed_by_reason[event.failed] ?? 0) + 1;
      break;
    case "outlayer_error":
      next.outlayer_errors += 1;
      break;
    case "queue_drop":
      next.queue_drops += 1;
      break;
    default:
      return state;
  }

  next.recent = [{ at, ...event }, ...next.recent].slice(0, RECENT_MAX);
  return next;
}

/** Snapshot numbers for a dashboard or JSON API. */
export function summarize(state) {
  const active = Object.values(state.installations).filter(i => i.status === "active");
  const orgs = active.filter(i => i.account_type === "Organization").length;
  const users = active.filter(i => i.account_type === "User").length;
  return {
    installs: state.installs,
    uninstalls: state.uninstalls,
    active_installations: active.length,
    active_orgs: orgs,
    active_users: users,
    repos_on_active: active.reduce((n, i) => n + (i.repos ?? 0), 0),
    repos_added: state.repos_added,
    repos_removed: state.repos_removed,
    review_requests: state.review_requests,
    jobs_done: state.jobs_done,
    jobs_failed: state.jobs_failed,
    outlayer_errors: state.outlayer_errors,
    queue_drops: state.queue_drops,
    failed_by_reason: state.failed_by_reason,
    installations: Object.values(state.installations).sort((a, b) => b.updated_at - a.updated_at),
    recent: state.recent,
  };
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Minimal HTML dashboard (ids and account logins only). */
export function renderStatsHtml(summary) {
  const rows = summary.installations.map(i =>
    `<tr><td>${esc(i.installation)}</td><td>${esc(i.account ?? "—")}</td><td>${esc(i.account_type ?? "—")}</td><td>${esc(i.repos)}</td><td>${esc(i.status)}</td><td>${esc(new Date(i.updated_at).toISOString())}</td></tr>`).join("");
  const fails = Object.entries(summary.failed_by_reason).map(([k, v]) => `<li><code>${esc(k)}</code>: ${v}</li>`).join("") || "<li>none</li>";
  const recent = summary.recent.slice(0, 40).map(e =>
    `<li><time>${esc(new Date(e.at).toISOString())}</time> <code>${esc(e.type)}</code> ${e.installation != null ? `install ${esc(e.installation)}` : ""} ${e.job ? `job ${esc(e.job)}` : ""} ${e.failed ? `(${esc(e.failed)})` : ""} ${e.trigger ? esc(e.trigger) : ""} ${e.error ? esc(e.error) : ""}</li>`).join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Private Investigator — relay stats</title>
<style>
body{font:14px/1.45 system-ui,sans-serif;margin:2rem;max-width:56rem;color:#111}
h1{font-size:1.25rem} h2{font-size:1rem;margin-top:2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(9rem,1fr));gap:.75rem}
.card{border:1px solid #ddd;border-radius:8px;padding:.75rem}
.card b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #eee;text-align:left;padding:.35rem .5rem}
code,time{font-size:12px} ul{padding-left:1.2rem}
.muted{color:#666}
</style></head><body>
<h1>Private Investigator — relay stats</h1>
<p class="muted">Internal observation only. Ids and account logins; no repository names or code.</p>
<div class="grid">
<div class="card"><span>Active installs</span><b>${summary.active_installations}</b></div>
<div class="card"><span>Orgs</span><b>${summary.active_orgs}</b></div>
<div class="card"><span>Users</span><b>${summary.active_users}</b></div>
<div class="card"><span>Repos on active</span><b>${summary.repos_on_active}</b></div>
<div class="card"><span>Review requests</span><b>${summary.review_requests}</b></div>
<div class="card"><span>Jobs done</span><b>${summary.jobs_done}</b></div>
<div class="card"><span>Jobs failed</span><b>${summary.jobs_failed}</b></div>
<div class="card"><span>OutLayer errors</span><b>${summary.outlayer_errors}</b></div>
</div>
<p class="muted">Lifetime installs ${summary.installs} · uninstalls ${summary.uninstalls} · repos +${summary.repos_added}/−${summary.repos_removed} · queue drops ${summary.queue_drops}</p>
<h2>Failures by reason</h2>
<ul>${fails}</ul>
<h2>Installations</h2>
<table><thead><tr><th>id</th><th>account</th><th>type</th><th>repos</th><th>status</th><th>updated</th></tr></thead>
<tbody>${rows || "<tr><td colspan=6 class=muted>none yet</td></tr>"}</tbody></table>
<h2>Recent</h2>
<ul>${recent || "<li class=muted>none yet</li>"}</ul>
</body></html>`;
}
