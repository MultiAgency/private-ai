//! The tool loop's state machine, as test/agent.test.mjs checks the Action's
//! loop: tool calls, the nudge to finish, a submission sent back, the wrap-up
//! warning, the turn cap and a cut-off reply. Encryption and signatures are
//! tested in core.rs; here the replies arrive already opened and checked.
use private_investigator::agent::{Agent, Finish, Next};
use serde_json::{json, Value};

fn tool(name: &str) -> Value {
    json!({ "type": "function", "function": { "name": name, "description": name, "parameters": { "type": "object" } } })
}

fn call(name: &str, args: Value) -> Value {
    json!({ "role": "assistant", "content": "", "tool_calls": [{ "id": format!("call_{name}"), "type": "function", "function": { "name": name, "arguments": args.to_string() } }] })
}

fn check(args: &Value) -> Option<String> {
    if args["answer"].is_string() { None } else { Some("submit needs an answer".into()) }
}

fn record(n: u64) -> Value {
    json!({ "id": format!("chat-{n}") })
}

#[test]
fn tool_calls_a_nudge_then_the_submitted_result() {
    let submit = tool("submit");
    let finish = Finish { tool: &submit, check: &check };
    let mut agent = Agent::new("rules", "p", 10);
    let mut calls = Vec::new();
    let mut run = |name: &str, args: &Value| {
        calls.push((name.to_string(), args.clone()));
        "value".to_string()
    };

    assert!(matches!(agent.apply(&call("lookup", json!({ "key": "a" })), Some("tool_calls"), record(1), &finish, &mut run).unwrap(), Next::Continue));
    assert_eq!(agent.messages.last().unwrap()["content"], "value");
    assert!(matches!(agent.apply(&json!({ "content": "Thinking it over." }), Some("stop"), record(2), &finish, &mut run).unwrap(), Next::Continue));
    assert_eq!(agent.messages.last().unwrap()["content"], "Call submit to finish.");
    let Next::Finished(result) = agent.apply(&call("submit", json!({ "answer": "done" })), Some("tool_calls"), record(3), &finish, &mut run).unwrap() else {
        panic!("not finished");
    };
    assert_eq!(result, json!({ "answer": "done" }));
    assert_eq!(calls, vec![("lookup".to_string(), json!({ "key": "a" }))]);
    assert_eq!(agent.turns.len(), 3);
}

#[test]
fn an_incomplete_submission_is_sent_back_the_model_is_told_to_wrap_up_and_the_cap_ends_the_loop() {
    let submit = tool("submit");
    let finish = Finish { tool: &submit, check: &check };
    let mut agent = Agent::new("rules", "p", 2);
    let mut run = |_: &str, _: &Value| String::new();
    agent.apply(&call("submit", json!({})), Some("tool_calls"), record(1), &finish, &mut run).unwrap();
    let last: Vec<&Value> = agent.messages.iter().rev().take(2).map(|m| &m["content"]).collect();
    assert_eq!(last, vec!["1 turn left: call submit now with what you have.", "error: submit needs an answer"]);
    let end = agent.apply(&json!({ "content": "done" }), Some("stop"), record(2), &finish, &mut run);
    assert_eq!(end.err().unwrap().to_string(), "nothing submitted after 2 turns");
}

#[test]
fn a_reply_cut_off_at_the_cap_is_dropped_and_the_model_is_asked_to_be_briefer() {
    let submit = tool("submit");
    let finish = Finish { tool: &submit, check: &check };
    let mut agent = Agent::new("rules", "p", 10);
    let mut ran = 0;
    let mut run = |_: &str, _: &Value| {
        ran += 1;
        String::new()
    };
    agent.apply(&call("lookup", json!({ "key": "a" })), Some("length"), record(1), &finish, &mut run).unwrap();
    assert_eq!(ran, 0);
    assert!(agent.messages.last().unwrap()["content"].as_str().unwrap().contains("was cut off"));
    assert_eq!(agent.turns.len(), 1);
}

#[test]
fn bad_json_arguments_go_back_as_an_error() {
    let submit = tool("submit");
    let finish = Finish { tool: &submit, check: &check };
    let mut agent = Agent::new("rules", "p", 10);
    let mut reply = call("lookup", json!({}));
    reply["tool_calls"][0]["function"]["arguments"] = json!("{not json");
    agent.apply(&reply, Some("tool_calls"), record(1), &finish, &mut |_, _| unreachable!()).unwrap();
    assert_eq!(agent.messages.last().unwrap()["content"], "error: arguments are not valid JSON");
}

#[test]
fn the_state_survives_a_save_and_restore_between_runs() {
    let submit = tool("submit");
    let finish = Finish { tool: &submit, check: &check };
    let mut agent = Agent::new("rules", "p", 10);
    agent.apply(&call("lookup", json!({ "key": "a" })), Some("tool_calls"), record(1), &finish, &mut |_, _| "v".into()).unwrap();

    let mut resumed = Agent::from_json(&serde_json::from_str(&agent.to_json().to_string()).unwrap()).unwrap();
    assert_eq!(resumed.messages, agent.messages);
    let Next::Finished(_) = resumed.apply(&call("submit", json!({ "answer": "x" })), Some("tool_calls"), record(2), &finish, &mut |_, _| unreachable!()).unwrap() else {
        panic!("not finished");
    };
    assert_eq!(resumed.turns, vec![record(1), record(2)]);
}
