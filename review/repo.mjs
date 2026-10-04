// The pull request's head commit, unpacked to a temporary directory, and the
// read-only tools the model uses on it. Nothing in it is ever executed, and no
// path the model names may leave the directory, including through a symlink.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

const MAX_FILE_BYTES = 1_000_000;
const MAX_LINES = 2_000;
const MAX_MATCHES = 200;
const MAX_ENTRIES = 500;
const SKIP_DIRS = new Set([".git", "node_modules"]);

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

export const definitions = [
  {
    type: "function",
    function: {
      name: "list_files",
      description: "List the files and directories in a directory of the pull request's head commit.",
      parameters: { type: "object", properties: { path: { type: "string", description: "Directory, relative to the repository root. Default: the root." } } },
    },
  },
  {
    type: "function",
    function: {
      name: "read_file",
      description: `Read a file from the pull request's head commit, with line numbers. At most ${MAX_LINES} lines per call.`,
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" },
          start_line: { type: "integer", description: "First line, from 1. Default 1." },
          end_line: { type: "integer", description: "Last line. Default: start_line + 1999." },
        },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "grep",
      description: `Search the pull request's head commit with a JavaScript regular expression. Returns up to ${MAX_MATCHES} matching lines as path:line: text.`,
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string" },
          path: { type: "string", description: "Directory or file to search, relative to the repository root. Default: the root." },
        },
        required: ["pattern"],
      },
    },
  },
];

export function tools(root) {
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

  return function call(name, args) {
    if (!Object.hasOwn(run, name)) return `unknown tool ${name}`;
    try {
      return run[name](args ?? {});
    } catch (error) {
      return `error: ${error.code === "ENOENT" ? `${args?.path} does not exist` : error.message}`;
    }
  };
}
