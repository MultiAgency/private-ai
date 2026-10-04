// A private tool loop on NEAR AI Cloud, one signed turn at a time (turn.mjs).
// The model works through the caller's tools and finishes by calling the
// finish tool with arguments the caller accepts.
import { session } from "./e2ee.mjs";
import { MAX_REPLY_TOKENS, signedTurn } from "./turn.mjs";

// At the default effort a reasoning model can think until the server's 8k
// budget runs out, minutes per turn; "low" kept answers right in testing at a
// fifth of the time.
const REASONING_EFFORT = "low";
// With this many turns left, the model is told to finish.
const WRAP_UP_TURNS = 3;

const parse = text => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

/**
 * Runs the loop and returns the finish tool's arguments with one record per
 * signed turn. `finish` is { tool, check }: check(args) returns an error
 * message for the model, or nothing when the arguments are complete.
 */
export async function runAgent({ client, model, publicKey, system, prompt, tools, call, finish, maxTurns, log = () => {} }) {
  const e2ee = session(publicKey);
  const definitions = [...tools, finish.tool];
  const finishName = finish.tool.function.name;
  const messages = [{ role: "system", content: system }, { role: "user", content: prompt }];
  const turns = [];

  for (let turn = 1; turn <= maxTurns; turn++) {
    const started = Date.now();
    const { reply, finishReason, usage, record } = await signedTurn({ client, model, publicKey, e2ee, messages, tools: definitions, effort: REASONING_EFFORT });
    turns.push(record);

    const calls = reply.tool_calls ?? [];
    log(`turn ${turn}: ${((Date.now() - started) / 1000).toFixed(0)}s, ${usage?.prompt_tokens} in, ` +
      `${usage?.completion_tokens} out (${usage?.completion_tokens_details?.reasoning_tokens ?? usage?.reasoning_tokens ?? 0} reasoning), ` +
      `${calls.length} tool calls, ${finishReason}`);
    // A reply cut off at the cap may hold half a tool call: drop it and ask again.
    if (finishReason === "length") {
      messages.push({ role: "user", content: `Your last reply passed ${MAX_REPLY_TOKENS} tokens and was cut off. Think more briefly, then continue.` });
      continue;
    }
    messages.push({ role: "assistant", content: reply.content || null, ...(calls.length && { tool_calls: calls }) });
    if (calls.length === 0) {
      messages.push({ role: "user", content: `Call ${finishName} to finish.` });
      continue;
    }
    for (const c of calls) {
      const args = parse(c.function.arguments);
      const problem = args === null ? "arguments are not valid JSON" : c.function.name === finishName ? finish.check(args) : undefined;
      if (c.function.name === finishName && !problem) return { result: args, turns };
      messages.push({ role: "tool", tool_call_id: c.id, content: problem ? `error: ${problem}` : call(c.function.name, args) });
    }
    const left = maxTurns - turn;
    if (left > 0 && left <= WRAP_UP_TURNS) messages.push({ role: "user", content: `${left === 1 ? "1 turn" : `${left} turns`} left: call ${finishName} now with what you have.` });
  }
  throw new Error(`nothing submitted after ${maxTurns} turns`);
}
