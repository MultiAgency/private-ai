// "Check my setup": run the workflow by hand (workflow_dispatch), or
// `review.mjs --check`, to prove what a review needs before the first pull
// request: the NEAR AI key works, the chosen model passes its attestation
// under the repository's policy, and the token can read pull requests. It
// reads no code and posts nothing; the result goes to the run's summary.
import { appendFileSync } from "node:fs";

import { attest } from "../core/attest.mjs";

/** Each check as { ok, text }; a check that fails says how to fix it. */
export async function checkSetup({ client, gh, model, allowUnpatchedModel }) {
  const results = [];
  try {
    const { attestation } = await attest(client, model, { allowUnpatchedModel });
    results.push({ ok: true, text: `\`${model}\` passed its attestation: TCB ${attestation.model.tcb}, GPUs attested by NVIDIA, signing key \`${attestation.model.signer.slice(0, 16)}…\`.` });
  } catch (error) {
    results.push({ ok: false, text: modelProblem(model, error) });
  }
  try {
    await gh.pulls();
    results.push({ ok: true, text: "The token can read this repository's pull requests." });
  } catch (error) {
    results.push({ ok: false, text: `The token can't read pull requests (${error.message}). The workflow needs \`pull-requests: write\` and \`contents: read\`.` });
  }
  return results;
}

/** Why a model can't carry a review, and what to do about it. */
export function modelProblem(model, error) {
  const message = error.message;
  if (/\b401\b|\b403\b/.test(message)) return `NEAR AI refused the key (${message}). Check the \`NEARAI_API_KEY\` secret and that the account has credits.`;
  if (/TCB status OutOfDate|ConfigurationNeeded|SWHardeningNeeded/.test(message)) {
    return `\`${model}\` runs on a machine whose Intel platform update is pending (${message}). Choose a model that passes (\`npm run models\` in MultiAgency/private-ai lists them), or set \`allow-unpatched-model: "true"\` to accept it, which every review and receipt will state.`;
  }
  if (/No provider found|not found|404/i.test(message)) return `NEAR AI Cloud can't attest \`${model}\` (${message}). Choose a model that passes; \`npm run models\` lists them.`;
  return `\`${model}\` didn't pass its attestation (${message}).`;
}

/** Prints the results, and writes them to the run's summary in GitHub Actions. */
export function report(results) {
  const lines = results.map(r => `- ${r.ok ? "✅" : "❌"} ${r.text}`);
  const verdict = results.every(r => r.ok) ? "**Setup OK.** Open a pull request to get its first review." : "**Setup needs a fix** before reviews can run.";
  const text = `### Private Investigator setup check\n\n${lines.join("\n")}\n\n${verdict}\n`;
  console.log(text);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, text);
  return results.every(r => r.ok);
}
