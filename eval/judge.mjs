// The eval's grader: one yes/no question per known bug, about a review's text,
// asked of the same attested model. Validated against Claude's real findings
// and five private reviews that missed both bugs: no errors in two rounds.
import { ask } from "../core/turn.mjs";

const SYSTEM = "You grade code reviews. Answer with exactly one word: YES or NO.";

/** The question to ask about a finding a person reacted to, for either direction. */
export const question = body =>
  `Does this code review raise, as a defect, the same issue as the following finding (same root cause, any wording)? Finding: """${body.replace(/"""/g, "'''")}""" Answer NO if the review does not raise this issue.`;

export async function judge({ client, model, publicKey, bugs, text }) {
  const verdicts = await Promise.all(Object.entries(bugs).map(async ([bug, question]) => {
    const { text: answer } = await ask({
      client, model, publicKey, system: SYSTEM, effort: "low",
      prompt: `${question}\n\n--- REVIEW ---\n${text}\n--- END ---\n\nAnswer YES or NO.`,
    });
    return [bug, /\bYES\b/.test(answer.toUpperCase())];
  }));
  return Object.fromEntries(verdicts);
}
