// Runs every eval case through both reviewers, the Action (Node) and the hosted
// App (Rust, its dry-run build), at the same number of passes, and writes one
// table: how often each planted or reported bug was caught, and how often a
// known false positive was raised. Nothing is posted.
//
// Usage: node eval/compare.mjs [--runs 4] [--passes 3] [--parallel 2] [--cases dir-or-file,...]
// Env: NEARAI_API_KEY, GITHUB_TOKEN. The App's runner needs its dry-run build:
//   cargo build --release --target wasm32-wasip2 --no-default-features --target-dir target/dry
import { execFile } from "node:child_process";
import { mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    runs: { type: "string", default: "4" },
    passes: { type: "string", default: "3" },
    parallel: { type: "string", default: "2" },
    cases: { type: "string", default: "eval/cases,eval/feedback" },
  },
});

const cases = values.cases.split(",").flatMap(p => (statSync(p).isDirectory() ? readdirSync(p).filter(f => f.endsWith(".json")).map(f => join(p, f)) : [p]));
const jobs = cases.flatMap(path => ["node", "rust"].map(runner => ({ path, runner })));

function run({ path, runner }) {
  const args = ["eval/run.mjs", "--case", path, "--runs", values.runs, "--passes", values.passes, "--runner", runner];
  return new Promise(done => execFile("node", args, { maxBuffer: 32 * 1024 * 1024 }, (error, stdout) => {
    const lines = stdout.split("\n");
    const rates = {};
    for (const line of lines) {
      const caught = line.match(/^(\S+): caught (\d+)\/(\d+)$/);
      const raised = line.match(/^(\S+): false positive raised (\d+)\/(\d+)/);
      if (caught) rates[caught[1]] = { kind: "bug", hit: +caught[2], of: +caught[3] };
      if (raised) rates[raised[1]] = { kind: "false positive", hit: +raised[2], of: +raised[3] };
    }
    const failed = Number(lines.find(l => l.includes(" failed"))?.match(/(\d+) failed/)?.[1] ?? (error ? values.runs : 0));
    done({ path, runner, rates, failed });
  }));
}

const results = [];
const queue = [...jobs];
await Promise.all(Array.from({ length: Number(values.parallel) }, async () => {
  for (let job; (job = queue.shift());) {
    const result = await run(job);
    results.push(result);
    console.log(`${result.path} [${result.runner}]: ${Object.entries(result.rates).map(([k, r]) => `${k} ${r.hit}/${r.of}`).join(", ") || "no result"}${result.failed ? `, ${result.failed} failed` : ""}`);
  }
}));

const name = path => path.split("/").pop().replace(/\.json$/, "");
const cell = (r, kind) => {
  const rows = Object.entries(r?.rates ?? {}).filter(([, v]) => v.kind === kind);
  return rows.length ? rows.map(([k, v]) => `${k} ${v.hit}/${v.of}`).join(", ") : "–";
};
const rows = cases.map(path => {
  const [node, rust] = ["node", "rust"].map(runner => results.find(r => r.path === path && r.runner === runner));
  return `| ${name(path)} | ${cell(node, "bug")} | ${cell(rust, "bug")} | ${cell(node, "false positive")} | ${cell(rust, "false positive")} |`;
});
const total = (runner, kind) => {
  const all = results.filter(r => r.runner === runner).flatMap(r => Object.values(r.rates).filter(v => v.kind === kind));
  return `${all.reduce((n, v) => n + v.hit, 0)}/${all.reduce((n, v) => n + v.of, 0)}`;
};
const table = [
  `# Action vs App, ${new Date().toISOString().slice(0, 10)}: ${values.runs} runs of ${values.passes} passes per case`,
  "",
  "| case | bugs caught (Action) | bugs caught (App) | false positives (Action) | false positives (App) |",
  "|---|---|---|---|---|",
  ...rows,
  `| **total** | **${total("node", "bug")}** | **${total("rust", "bug")}** | **${total("node", "false positive")}** | **${total("rust", "false positive")}** |`,
  "",
].join("\n");
const out = resolve(`eval/feedback/compare-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.md`);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, table);
console.log(`\n${table}\nwritten to ${out}`);
