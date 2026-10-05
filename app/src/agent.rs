//! The private tool loop as a resumable state machine. Port of `core/agent.mjs`
//! for a host that stops every few minutes: the network takes one signed turn
//! (`net::NearAi::agent_turn`), `apply` feeds its reply in, and the state goes
//! to sealed storage between runs as JSON. Messages to the model match the
//! Action's word for word.
use anyhow::{bail, Result};
use serde_json::{json, Value};

/// At the default effort a reasoning model can think for minutes per turn;
/// "low" kept answers right in testing at a fifth of the time.
pub const REASONING_EFFORT: &str = "low";
/// With this many turns left, the model is told to finish.
pub const WRAP_UP_TURNS: u64 = 3;
/// The most one reply may produce, reasoning included, as the Action allows.
/// A host whose runs stop sooner passes a smaller cap to `Agent::with_reply_cap`.
pub const MAX_REPLY_TOKENS: u64 = 16_384;

/// The finish tool and what it accepts: `check` returns a problem for the
/// model to fix, or `None` when the arguments are complete.
pub struct Finish<'a> {
    pub tool: &'a Value,
    pub check: &'a dyn Fn(&Value) -> Option<String>,
}

impl Finish<'_> {
    pub fn name(&self) -> &str {
        self.tool["function"]["name"].as_str().unwrap_or("")
    }
}

pub enum Next {
    /// The finish tool's accepted arguments.
    Finished(Value),
    /// Take another turn.
    Continue,
}

pub struct Agent {
    pub messages: Vec<Value>,
    /// One record per signed turn, for the receipt.
    pub turns: Vec<Value>,
    pub turn: u64,
    pub max_turns: u64,
    pub reply_cap: u64,
}

impl Agent {
    pub fn new(system: &str, prompt: &str, max_turns: u64) -> Self {
        Self {
            messages: vec![json!({ "role": "system", "content": system }), json!({ "role": "user", "content": prompt })],
            turns: Vec::new(),
            turn: 0,
            max_turns,
            reply_cap: MAX_REPLY_TOKENS,
        }
    }

    pub fn with_reply_cap(mut self, reply_cap: u64) -> Self {
        self.reply_cap = reply_cap;
        self
    }

    pub fn to_json(&self) -> Value {
        json!({ "messages": self.messages, "turns": self.turns, "turn": self.turn, "max_turns": self.max_turns, "reply_cap": self.reply_cap })
    }

    pub fn from_json(state: &Value) -> Result<Self> {
        let list = |k: &str| state[k].as_array().cloned();
        let (Some(messages), Some(turns), Some(turn), Some(max_turns)) = (list("messages"), list("turns"), state["turn"].as_u64(), state["max_turns"].as_u64()) else {
            bail!("agent state is incomplete");
        };
        let reply_cap = state["reply_cap"].as_u64().unwrap_or(MAX_REPLY_TOKENS);
        Ok(Self { messages, turns, turn, max_turns, reply_cap })
    }

    pub fn exhausted(&self) -> bool {
        self.turn >= self.max_turns
    }

    /// Feeds in one turn's decrypted reply, whose signature has been checked.
    /// `call` runs a tool; it is never given the finish tool.
    pub fn apply(&mut self, reply: &Value, finish_reason: Option<&str>, record: Value, finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        self.turn += 1;
        self.turns.push(record);
        let finish_name = finish.name().to_string();

        // A reply cut off at the cap may hold half a tool call: drop it and ask again.
        if finish_reason == Some("length") {
            self.messages.push(json!({ "role": "user", "content": format!("Your last reply passed {} tokens and was cut off. Think more briefly, then continue.", self.reply_cap) }));
            return self.next();
        }
        let calls = reply["tool_calls"].as_array().cloned().unwrap_or_default();
        let content = reply["content"].as_str().filter(|c| !c.is_empty());
        let mut assistant = json!({ "role": "assistant", "content": content });
        if !calls.is_empty() {
            assistant["tool_calls"] = Value::Array(calls.clone());
        }
        self.messages.push(assistant);
        if calls.is_empty() {
            self.messages.push(json!({ "role": "user", "content": format!("Call {finish_name} to finish.") }));
            return self.next();
        }
        for c in &calls {
            let name = c["function"]["name"].as_str().unwrap_or("");
            let args = serde_json::from_str::<Value>(c["function"]["arguments"].as_str().unwrap_or("")).ok().filter(|v| !v.is_null());
            let problem = match &args {
                None => Some("arguments are not valid JSON".to_string()),
                Some(args) if name == finish_name => (finish.check)(args),
                Some(_) => None,
            };
            if name == finish_name && problem.is_none() {
                return Ok(Next::Finished(args.unwrap_or(Value::Null)));
            }
            let content = match (problem, &args) {
                (Some(problem), _) => format!("error: {problem}"),
                (None, Some(args)) => call(name, args),
                (None, None) => unreachable!("missing arguments are a problem"),
            };
            self.messages.push(json!({ "role": "tool", "tool_call_id": c["id"], "content": content }));
        }
        let left = self.max_turns.saturating_sub(self.turn);
        if left > 0 && left <= WRAP_UP_TURNS {
            let turns = if left == 1 { "1 turn".to_string() } else { format!("{left} turns") };
            self.messages.push(json!({ "role": "user", "content": format!("{turns} left: call {finish_name} now with what you have.") }));
        }
        self.next()
    }

    fn next(&self) -> Result<Next> {
        if self.exhausted() {
            bail!("nothing submitted after {} turns", self.max_turns);
        }
        Ok(Next::Continue)
    }
}
