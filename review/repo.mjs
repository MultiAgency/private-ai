// The pull request's head commit, unpacked to a temporary directory, and the
// read-only tools the model uses on it. Nothing in it is ever executed, and no
// path the model names may leave the directory, including through a symlink.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import spec from "./review.json" with { type: "json" };

// Shared with the hosted App (app/), like the tool definitions below.
const { max_file_bytes: MAX_FILE_BYTES, max_lines: MAX_LINES, max_matches: MAX_MATCHES, max_entries: MAX_ENTRIES } = spec.repo_limits;
const SKIP_DIRS = new Set(spec.repo_limits.skip_dirs);

// The model picks the pattern, and JavaScript's regex engine backtracks without
// limit: `^(a+)+$` on a long line of a's never finishes. A grep runs in a child
// process, killed after this long. (The hosted App's engine caps backtracking
// itself, so this limit is the Action's alone.)
const GREP_TIMEOUT_MS = 5000;
const GREP_WORKER = fileURLToPath(new URL("./grep-worker.mjs", import.meta.url));

export function unpack(tarball) {
  const dir = mkdtempSync(join(tmpdir(), "private-review-"));
  const archive = join(dir, "head.tar.gz");
  const root = join(dir, "head");
  writeFileSync(archive, tarball);
  mkdirSync(root);
  execFileSync("tar", ["-xzf", archive, "-C", root, "--strip-components=1"]);
  rmSync(archive);
  return { root: realpathSync(root), remove: () => rmSync(dir, { recursive: true, force: true }) };
}

export const definitions = spec.repo_tools;

// `guarded: false` is for the grep worker, which the timeout already bounds.
export function tools(root, { guarded = true } = {}) {
  function inside(path = ".") {
    const target = resolve(root, path);
    const real = realpathSync(target);
    if (real !== root && !real.startsWith(root + sep)) throw new Error(`${path} is outside the repository`);
    return real;
  }

  function* walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) yield* walk(path);
      } else if (entry.isFile()) yield path;
    }
  }

  function text(path) {
    if (statSync(path).size > MAX_FILE_BYTES) return null;
    const content = readFileSync(path);
    return content.includes(0) ? null : content.toString("utf8");
  }

  const run = {
    list_files({ path }) {
      const dir = inside(path);
      const entries = readdirSync(dir, { withFileTypes: true })
        .filter(e => !e.isSymbolicLink() && !SKIP_DIRS.has(e.name))
        .map(e => (e.isDirectory() ? `${e.name}/` : e.name))
        .sort();
      return entries.slice(0, MAX_ENTRIES).join("\n") + (entries.length > MAX_ENTRIES ? `\n… ${entries.length - MAX_ENTRIES} more` : "");
    },

    read_file({ path, start_line = 1, end_line }) {
      const content = text(inside(path));
      if (content === null) return `${path} is binary or larger than ${MAX_FILE_BYTES} bytes`;
      const lines = content.split("\n");
      const start = Math.max(1, start_line);
      const end = Math.min(lines.length, end_line ?? start + MAX_LINES - 1, start + MAX_LINES - 1);
      return lines.slice(start - 1, end).map((line, i) => `${start + i}\t${line}`).join("\n") +
        (end < lines.length ? `\n… ${lines.length - end} more lines` : "");
    },

    grep({ pattern, path }) {
      const regex = new RegExp(pattern);
      const base = inside(path);
      const files = statSync(base).isDirectory() ? walk(base) : [base];
      const matches = [];
      for (const file of files) {
        const content = text(file);
        if (content === null) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (!regex.test(lines[i])) continue;
          matches.push(`${relative(root, file)}:${i + 1}: ${lines[i].slice(0, 300)}`);
          if (matches.length === MAX_MATCHES) return `${matches.join("\n")}\n… stopped at ${MAX_MATCHES} matches`;
        }
      }
      return matches.join("\n") || "no matches";
    },
  };

  function guardedGrep(args) {
    const child = spawnSync(process.execPath, [GREP_WORKER, root, JSON.stringify(args)], {
      timeout: GREP_TIMEOUT_MS,
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024 * 1024,
      encoding: "utf8",
    });
    if (child.error?.code === "ETIMEDOUT") return `error: that pattern took longer than ${GREP_TIMEOUT_MS / 1000}s to search with; use a simpler one`;
    if (child.error || child.status !== 0) return "error: the search failed; try a different pattern";
    return child.stdout;
  }

  return function call(name, args) {
    if (!Object.hasOwn(run, name)) return `unknown tool ${name}`;
    if (name === "grep" && guarded) return guardedGrep(args ?? {});
    try {
      return run[name](args ?? {});
    } catch (error) {
      return `error: ${error.code === "ENOENT" ? `${args?.path} does not exist` : error.message}`;
    }
  };
}
