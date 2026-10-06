import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { tools, unpack } from "../review/repo.mjs";

// A tarball shaped like GitHub's: one top-level directory holding the tree.
function tarball() {
  const dir = mkdtempSync(join(tmpdir(), "private-review-test-"));
  const top = join(dir, "owner-repo-abc123");
  mkdirSync(join(top, "src"), { recursive: true });
  writeFileSync(join(top, "src", "add.js"), "export const add = (a, b) => a - b;\nexport const one = 1;\n");
  writeFileSync(join(top, "README.md"), "# Example\n");
  writeFileSync(join(dir, "outside.txt"), "runner secret\n");
  symlinkSync(join(dir, "outside.txt"), join(top, "escape.txt"));
  execFileSync("tar", ["-czf", join(dir, "head.tar.gz"), "-C", dir, "owner-repo-abc123"]);
  const bytes = readFileSync(join(dir, "head.tar.gz"));
  rmSync(dir, { recursive: true });
  return bytes;
}

test("the head commit unpacks, and the tools read it with line numbers", () => {
  const head = unpack(tarball());
  try {
    const call = tools(head.root);
    assert.equal(call("list_files", {}), "README.md\nsrc/");
    assert.equal(call("read_file", { path: "src/add.js", start_line: 2, end_line: 2 }), "2\texport const one = 1;\n… 1 more lines");
    assert.equal(call("grep", { pattern: "a - b" }), "src/add.js:1: export const add = (a, b) => a - b;");
    assert.equal(call("grep", { pattern: "nothing" }), "no matches");
  } finally {
    head.remove();
  }
});

test("grep lists matches in path order, as the hosted App does, whatever order the disk gives", () => {
  const head = unpack(tarball());
  try {
    mkdirSync(join(head.root, "a"));
    writeFileSync(join(head.root, "a", "x.txt"), "needle\n");
    writeFileSync(join(head.root, "a.txt"), "needle\n");
    writeFileSync(join(head.root, "b.txt"), "needle\n");
    // "a.txt" sorts before "a/x.txt" ("." is before "/"), though directory "a" comes first on disk.
    assert.equal(tools(head.root)("grep", { pattern: "needle" }), "a.txt:1: needle\na/x.txt:1: needle\nb.txt:1: needle");
  } finally {
    head.remove();
  }
});

test("no path leaves the head commit, through .. or a symlink", () => {
  const head = unpack(tarball());
  try {
    const call = tools(head.root);
    assert.match(call("read_file", { path: "../../../../etc/hosts" }), /^error: /);
    assert.match(call("read_file", { path: "escape.txt" }), /outside the repository|does not exist/);
    assert.doesNotMatch(call("grep", { pattern: "runner secret" }), /runner secret/);
    assert.doesNotMatch(call("list_files", {}), /escape/);
  } finally {
    head.remove();
  }
});

test("bad input comes back as an error the model can read", () => {
  const head = unpack(tarball());
  try {
    const call = tools(head.root);
    assert.match(call("grep", { pattern: "(" }), /^error: /);
    assert.equal(call("read_file", { path: "missing.js" }), "error: missing.js does not exist");
    assert.equal(call("run_shell", { command: "id" }), "unknown tool run_shell");
  } finally {
    head.remove();
  }
});
