// Builds the page into _site/: app.js bundled with the lockfile's packages, so
// the receipt checker runs the same core/ code as the CLI and loads nothing
// from a CDN; index.html with the sample review rendered in, from the review
// `npm run sample` saved beside its receipt; and the static files.
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

import { build } from "esbuild";

const site = new URL("./", import.meta.url);
const out = new URL("../_site/", import.meta.url);
rmSync(out, { recursive: true, force: true });
mkdirSync(out);

await build({
  entryPoints: [new URL("app.js", site).pathname],
  outfile: new URL("app.js", out).pathname,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  sourcemap: true,
  define: { "process.env.NODE_ENV": '"production"' },
});

// The subset of GitHub markdown the review uses: `code`, **bold**, [links](url).
// Fences such as ```changes stay literal code rather than opening a span.
function inline(text) {
  const escaped = text.replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
  const fences = [];
  return escaped
    .replace(/`{3}\w*/g, fence => `\u0000${fences.push(fence) - 1}\u0000`)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${fences[i]}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https:[^)\s]+)\)/g, '<a href="$2">$1</a>');
}

function renderSample({ body, comments }) {
  const [head, summary] = body.split("\n\n");
  // The proof block holds blank lines of its own, so take it whole.
  const proof = body.slice(body.indexOf("<details>"));
  const claims = proof.split("\n").filter(line => line.startsWith("- ")).map(line => `<li>${inline(line.slice(2))}</li>`);
  const findings = comments.map(c => `
          <li class="card"><p class="where"><code>${inline(`${c.path}:${c.line}`)}</code></p><p>${inline(c.body)}</p></li>`);
  if (claims.length === 0) throw new Error("sample review has no proof block");
  return `<article class="card review">
        <p class="review-head">${inline(head)}</p>
        <p class="muted">${inline(summary)}</p>
        <ol class="findings">${findings.join("")}
        </ol>
        <details open><summary>Verified privately</summary>
          <ul>${claims.join("")}</ul>
        </details>
      </article>`;
}

const sample = JSON.parse(readFileSync(new URL("sample-review.json", site), "utf8"));
const page = readFileSync(new URL("index.html", site), "utf8");
if (!page.includes("<!-- SAMPLE_REVIEW -->")) throw new Error("index.html has no <!-- SAMPLE_REVIEW --> marker");
writeFileSync(new URL("index.html", out), page.replace("<!-- SAMPLE_REVIEW -->", renderSample(sample)));

for (const file of ["style.css", "icon.svg", "sample-receipt.json"]) {
  copyFileSync(new URL(file, site), new URL(file, out));
}
console.log(`built ${out.pathname}`);
