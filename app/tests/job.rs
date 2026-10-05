//! The hosted review as a job of short runs, against a fake GitHub and a fake
//! model (encryption, signatures and attestation are tested in core.rs).
use anyhow::{bail, Result};
use private_investigator::agent::{Agent, Finish, Next};
use private_investigator::attest::{Attestation, Model as Attested, Summary};
use private_investigator::job::{run_step, start, Forge, Model, Outcome, Run, Settings};
use private_investigator::receipt::Evidence;
use private_investigator::store::{take, Memory, Store};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};

#[derive(Default)]
struct Hub {
    draft: bool,
    checks: RefCell<Vec<Value>>,
    reviews: RefCell<Vec<Value>>,
}

fn tarball() -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let data = b"export const pay = total => total >= 0 && send(total);\n";
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "o-r-abc/lib/pay.mjs", &data[..]).unwrap();
    b.into_inner().unwrap().finish().unwrap()
}

impl Forge for Hub {
    fn pull(&self, _: u64) -> Result<Value> {
        Ok(json!({ "number": 7, "title": "Pay", "body": "", "state": "open", "draft": self.draft, "base": { "ref": "main", "sha": "a".repeat(40) }, "head": { "ref": "pay", "sha": "b".repeat(40) } }))
    }
    fn files(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![json!({ "filename": "lib/pay.mjs", "status": "modified", "additions": 1, "deletions": 1, "patch": "@@ -1,1 +1,1 @@\n-export const pay = total => total > 0 && send(total);\n+export const pay = total => total >= 0 && send(total);" })])
    }
    fn text(&self, _: &str, _: &str) -> Result<Option<String>> {
        Ok(None)
    }
    fn tarball(&self, _: &str) -> Result<Vec<u8>> {
        Ok(tarball())
    }
    fn reviews(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![])
    }
    fn review_comments(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![])
    }
    fn review(&self, _: u64, body: &Value) -> Result<()> {
        self.reviews.borrow_mut().push(body.clone());
        Ok(())
    }
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        self.checks.borrow_mut().push(json!({ "id": id, "body": body }));
        Ok(id.unwrap_or(42))
    }
}

/// Reads the file, then submits one finding, one turn each.
struct Scripted {
    fail_attestation: bool,
    die_on_turn: Cell<Option<u64>>,
}

fn summary(tcb: &str) -> Summary {
    Summary { tcb: tcb.into(), advisories: vec![], signer: "5a".repeat(32), compose_hash: "94".repeat(32) }
}

impl Model for Scripted {
    fn attest(&self, _: &str, allow: bool) -> Result<(Evidence, Attestation)> {
        if self.fail_attestation {
            bail!("model: TCB status OutOfDate not accepted (repository owner/secret-repo)");
        }
        let evidence = Evidence { nonce: "00".repeat(32), report: json!({}), gpu_token: "t".into(), allow_unpatched_model: allow };
        Ok((evidence, Attestation { gateway: summary("OutOfDate"), model: Attested { summary: summary("UpToDate"), gpu_token: "t".into(), public_key: "5a".repeat(32) } }))
    }
    fn turn(&self, agent: &mut Agent, _: &str, _: &str, _: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        if self.die_on_turn.get() == Some(agent.turn + 1) {
            self.die_on_turn.set(None);
            panic!("the run was killed mid-turn");
        }
        let reply = if agent.turn == 0 {
            json!({ "content": "", "tool_calls": [{ "id": "c1", "type": "function", "function": { "name": "read_file", "arguments": "{\"path\":\"lib/pay.mjs\"}" } }] })
        } else {
            let read = agent.messages.iter().any(|m| m["role"] == "tool" && m["content"].as_str().unwrap_or("").contains(">= 0"));
            assert!(read, "the tool read the head commit");
            let submission = json!({ "summary": "Checked the payout guard.", "findings": [{ "path": "lib/pay.mjs", "line": 1, "pass": "Bugs", "severity": "Important", "body": "Zero totals are sent." }] });
            json!({ "content": "", "tool_calls": [{ "id": "c2", "type": "function", "function": { "name": "submit_review", "arguments": submission.to_string() } }] })
        };
        let record = json!({ "id": format!("chat-{}", agent.turn + 1), "request_sha256": "", "response_sha256": "", "signature": {} });
        agent.apply(&reply, Some("tool_calls"), record, finish, call)
    }
}

/// A run at a given age; each run gets the next call id.
struct At(Cell<u64>, Cell<u64>);
impl Run for At {
    fn elapsed(&self) -> u64 {
        self.0.get()
    }
    fn now(&self) -> (u64, u32) {
        (1_791_103_153, 0)
    }
    fn call_id(&self) -> Option<String> {
        self.1.set(self.1.get() + 1);
        Some(format!("call-{}", self.1.get()))
    }
    fn project(&self) -> Option<String> {
        Some("hack.near/private-investigator".into())
    }
}

fn at(age: u64) -> At {
    At(Cell::new(age), Cell::new(0))
}

fn settings(passes: u64) -> Settings {
    Settings { model: "z-ai/glm-5.3-flash".into(), passes, max_turns: 10, allow_unpatched_model: false, dry: false, caller: "alice.near".into(), caps: None, trigger: None }
}

fn model() -> Scripted {
    Scripted { fail_attestation: false, die_on_turn: Cell::new(None) }
}

/// The published receipt (raw text) under `public:receipt:<sha>`.
fn published(store: &Memory) -> (String, Value) {
    let key = store.keys().into_iter().find(|k| k.starts_with("public:receipt:")).expect("a published receipt");
    let text = String::from_utf8(store.get(&key).unwrap().unwrap()).unwrap();
    (key["public:receipt:".len()..].to_string(), serde_json::from_str(&text).unwrap())
}

#[test]
fn a_job_runs_to_a_posted_review_a_finished_check_and_a_published_receipt() {
    let (store, hub, model, young) = (Memory::default(), Hub::default(), model(), at(0));
    assert_eq!(start(&store, &hub, &young, "j1", 1, "owner/secret-repo", 7, &settings(2)).unwrap().1.outcome, Outcome::More);
    assert_eq!(run_step(&store, &hub, &model, &young, "j1").outcome, Outcome::More, "attest");
    assert_eq!(run_step(&store, &hub, &model, &young, "j1").outcome, Outcome::Done, "two passes of two turns, then post");

    let reviews = hub.reviews.borrow();
    assert_eq!(reviews.len(), 1);
    let body = reviews[0]["body"].as_str().unwrap();
    assert!(body.starts_with("**Private Investigator** (Bugs, Important: 1)"), "{body}");
    assert!(body.contains("&receipt=") && body.contains("&salt="), "the review links the receipt with its salt");
    assert!(body.contains("read only inside attested enclaves (OutLayer") || body.contains("Fetched and read only inside attested enclaves (OutLayer"), "the App's own proof sentence");
    assert!(!body.contains("[Check the receipt](https://multiagency.github.io/private-ai/#check)."), "no receipt link without its receipt");
    assert!(body.contains("- **Reader:**"), "the proof names the reader");
    assert_eq!(reviews[0]["comments"][0]["path"], "lib/pay.mjs");
    let last = hub.checks.borrow().last().unwrap().clone();
    assert_eq!(last["body"]["status"], "completed");
    assert_eq!(last["body"]["output"]["title"], "Case closed: 1 lead");
    assert!(!store.keys().iter().any(|k| k.starts_with("job:")), "the job's state is gone");
    let (_, receipt) = published(&store);
    assert_eq!(receipt["version"], 2);
    assert_eq!(receipt["turns"].as_array().unwrap().len(), 4);
    assert!(receipt.get("subject").is_none() && !receipt.to_string().contains("secret-repo"), "the public receipt does not name the repository");
}

/// What a checker does with a version 2 receipt, short of fetching attestations.
#[test]
fn a_receipt_lists_every_run_and_their_outputs_prove_its_parts() {
    use private_investigator::receipt::{subject_commitment, turn_hash};
    let (store, hub, model, run) = (Memory::default(), Hub::default(), model(), at(100));
    let mut outputs = vec![start(&store, &hub, &run, "j8", 1, "owner/secret-repo", 7, &settings(2)).unwrap().1.to_json("j8")];
    loop {
        let step = run_step(&store, &hub, &model, &run, "j8");
        outputs.push(step.to_json("j8"));
        if step.outcome != Outcome::More {
            break;
        }
    }
    let (sha, receipt) = published(&store);
    let runs = receipt["outlayer"]["runs"].as_array().unwrap();
    assert_eq!(runs.len(), outputs.len(), "one entry per run");
    assert_eq!(receipt["outlayer"]["project"], "hack.near/private-investigator");
    for (i, entry) in runs.iter().enumerate() {
        assert_eq!(entry["call_id"], format!("call-{}", i + 1));
        if i + 1 < runs.len() {
            assert_eq!(entry["output"], outputs[i], "the receipt keeps each run's exact output");
        }
    }
    let last = outputs.last().unwrap();
    assert_eq!(last["receipt_sha256"], sha, "the last run attests this receipt");
    assert!(runs.last().unwrap().get("output").is_none(), "its output is rebuilt by the checker");
    assert_eq!(outputs[1]["nonce"], receipt["nonce"], "the attest run generated the evidence's nonce");
    let mut attested: Vec<String> = outputs.iter().flat_map(|o| o["turns"].as_array().cloned().unwrap_or_default()).map(|t| t.as_str().unwrap().to_string()).collect();
    let mut listed: Vec<String> = receipt["turns"].as_array().unwrap().iter().map(|t| turn_hash(t)).collect();
    attested.sort();
    listed.sort();
    assert_eq!(attested, listed, "the runs' outputs account for every receipt turn, once each");

    let link = hub.reviews.borrow()[0]["body"].as_str().unwrap().to_string();
    let salt = link.split("&salt=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let subject = json!({ "pull_request": "owner/secret-repo#7", "base_sha": "a".repeat(40), "head_sha": "b".repeat(40) });
    assert_eq!(receipt["subject_sha256"], subject_commitment(&salt, &subject), "the salt in the review opens the commitment");
    assert_eq!(last["subject_sha256"], receipt["subject_sha256"]);
}

#[test]
fn an_old_run_takes_one_turn_and_hands_on() {
    let (store, hub, model, old) = (Memory::default(), Hub::default(), model(), at(100));
    start(&store, &hub, &at(0), "j2", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &old, "j2");
    assert_eq!(run_step(&store, &hub, &model, &old, "j2").outcome, Outcome::More, "one turn");
    assert_eq!(run_step(&store, &hub, &model, &old, "j2").outcome, Outcome::Done, "the second turn submits and posts");
}

#[test]
fn a_run_killed_mid_turn_is_retried_and_the_job_goes_on() {
    let (store, hub, model, old) = (Memory::default(), Hub::default(), model(), at(100));
    start(&store, &hub, &at(0), "j3", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &old, "j3");
    model.die_on_turn.set(Some(1));
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &old, "j3")));
    assert!(killed.is_err());
    assert_eq!(take(&store, "job:j3").unwrap().unwrap()["in_flight"], 1, "the mark survives the kill");
    assert_eq!(run_step(&store, &hub, &model, &old, "j3").outcome, Outcome::More);
    assert_eq!(take(&store, "job:j3").unwrap().unwrap()["in_flight"], 0);
    assert_eq!(run_step(&store, &hub, &model, &old, "j3").outcome, Outcome::Done);
}

#[test]
fn a_turn_that_never_fits_fails_the_job_cleanly() {
    let (store, hub, model, old) = (Memory::default(), Hub::default(), model(), at(100));
    start(&store, &hub, &at(0), "j4", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &old, "j4");
    for _ in 0..3 {
        model.die_on_turn.set(Some(1));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &old, "j4")));
    }
    assert_eq!(run_step(&store, &hub, &model, &old, "j4").outcome, Outcome::Failed("turn too long"));
    assert!(hub.reviews.borrow().is_empty());
    assert_eq!(hub.checks.borrow().last().unwrap()["body"]["output"]["title"], "Review stopped");
    assert!(store.keys().is_empty(), "nothing is left behind, not even the request marker");
    assert_eq!(start(&store, &hub, &old, "j4b", 1, "o/r", 7, &settings(1)).unwrap().0, "j4b", "a failed review can be asked for again at once");
}

#[test]
fn drafts_are_skipped() {
    let (store, hub) = (Memory::default(), Hub { draft: true, ..Hub::default() });
    assert_eq!(start(&store, &hub, &at(0), "j5", 1, "o/r", 7, &settings(1)).unwrap().1.outcome, Outcome::Skipped);
    assert!(hub.checks.borrow().is_empty() && store.keys().is_empty());
}

#[test]
fn a_failed_attestation_posts_nothing_and_says_so_without_repository_details() {
    let (store, hub, young) = (Memory::default(), Hub::default(), at(0));
    let model = Scripted { fail_attestation: true, die_on_turn: Cell::new(None) };
    start(&store, &hub, &at(0), "j6", 1, "owner/secret-repo", 7, &settings(1)).unwrap();
    let step = run_step(&store, &hub, &model, &young, "j6");
    assert_eq!(step.outcome, Outcome::Failed("attestation"));
    assert_eq!(step.to_json("j6"), json!({ "job": "j6", "more": false, "failed": "attestation" }), "only the id and a category leave the run");
    assert!(hub.reviews.borrow().is_empty());
    let summary = hub.checks.borrow().last().unwrap()["body"]["output"]["summary"].as_str().unwrap().to_string();
    assert!(summary.starts_with("Attestation failed, so no code was sent"), "{summary}");
}

#[test]
fn a_dry_run_writes_nothing_to_github_and_answers_with_counts_only() {
    let (store, hub, model, young) = (Memory::default(), Hub::default(), model(), at(0));
    let dry = Settings { dry: true, ..settings(1) };
    start(&store, &hub, &young, "j7", 0, "o/r", 7, &dry).unwrap();
    run_step(&store, &hub, &model, &young, "j7");
    let last = run_step(&store, &hub, &model, &young, "j7");
    assert_eq!(last.outcome, Outcome::Done);
    let out = last.to_json("j7");
    assert_eq!((out["findings"].as_u64(), out["turns"].as_array().map(Vec::len)), (Some(1), Some(2)));
    assert!(hub.checks.borrow().is_empty() && hub.reviews.borrow().is_empty(), "nothing written to GitHub");
    assert!(store.keys().iter().all(|k| k.starts_with("public:receipt:") || k.starts_with("request:")), "only the published receipt (and the request marker) is kept");
}

#[test]
fn the_free_tier_stops_an_installation_at_its_monthly_cap_and_says_so() {
    use private_investigator::job::Caps;
    let (store, hub, young) = (Memory::default(), Hub::default(), at(0));
    let capped = Settings { caps: Some(Caps { per_installation: 2, global: 100 }), ..settings(1) };
    for (job, pr) in [("c1", 1), ("c2", 2)] {
        assert_eq!(start(&store, &hub, &young, job, 5, "o/r", pr, &capped).unwrap().1.outcome, Outcome::More);
    }
    let (_, third) = start(&store, &hub, &young, "c3", 5, "o/r", 3, &capped).unwrap();
    assert_eq!(third.outcome, Outcome::Skipped);
    assert_eq!(third.to_json("c3")["capped"], true);
    let last = hub.checks.borrow().last().unwrap().clone();
    assert_eq!(last["body"]["output"]["title"], "Monthly free reviews used");
    assert!(!store.keys().iter().any(|k| k == "job:c3"), "no job is opened");
    assert_eq!(start(&store, &hub, &young, "c4", 6, "o/r", 4, &capped).unwrap().1.outcome, Outcome::More, "another installation has its own count");
    let all = Settings { caps: Some(Caps { per_installation: 10, global: 3 }), ..settings(1) };
    assert_eq!(start(&store, &hub, &young, "c5", 7, "o/r", 5, &all).unwrap().1.outcome, Outcome::Skipped, "the global budget binds everyone");
}

#[test]
fn turns_saved_by_a_run_that_was_then_killed_are_attested_by_the_last_run() {
    use private_investigator::receipt::turn_hash;
    let (store, hub, model, young) = (Memory::default(), Hub::default(), model(), at(0));
    let mut outputs = vec![start(&store, &hub, &young, "j9", 1, "o/r", 7, &settings(1)).unwrap().1.to_json("j9")];
    outputs.push(run_step(&store, &hub, &model, &young, "j9").to_json("j9"));
    // A young run saves turn 1, starts turn 2 and is killed: it never answers.
    model.die_on_turn.set(Some(2));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &young, "j9"))).is_err());
    let last = run_step(&store, &hub, &model, &young, "j9");
    assert_eq!(last.outcome, Outcome::Done);
    let (_, receipt) = published(&store);
    let listed: Vec<Value> = receipt["turns"].as_array().unwrap().iter().map(|t| json!(turn_hash(t))).collect();
    assert_eq!(listed.len(), 2);
    assert_eq!(last.to_json("j9")["turns"], json!(listed), "the last run attests the orphaned turn and its own");
    assert_eq!(receipt["outlayer"]["runs"].as_array().unwrap().len(), 3, "the killed run is not listed");
}

#[test]
fn a_repeated_delivery_continues_the_running_job_or_is_dropped_once_it_finished() {
    let (store, hub, model, young) = (Memory::default(), Hub::default(), model(), at(0));
    let (first, step) = start(&store, &hub, &young, "d1", 1, "o/r", 7, &settings(1)).unwrap();
    assert_eq!((first.as_str(), step.outcome), ("d1", Outcome::More));
    let (again, step) = start(&store, &hub, &young, "d2", 1, "o/r", 7, &settings(1)).unwrap();
    assert_eq!((again.as_str(), step.outcome), ("d1", Outcome::More), "a retried webhook continues the same job");
    assert_eq!(hub.checks.borrow().len(), 1, "one check run, not two");
    while run_step(&store, &hub, &model, &young, "d1").outcome == Outcome::More {}
    let (late, step) = start(&store, &hub, &young, "d3", 1, "o/r", 7, &settings(1)).unwrap();
    assert_eq!((late.as_str(), step.outcome), ("d1", Outcome::Skipped), "a repeat right after the review is dropped");
    assert_eq!(step.to_json(&late)["duplicate"], true);
    assert_eq!(hub.reviews.borrow().len(), 1, "one review");
}

#[test]
fn a_deliberate_review_request_always_runs() {
    let (store, hub, young) = (Memory::default(), Hub::default(), at(0));
    start(&store, &hub, &young, "e1", 1, "o/r", 7, &settings(1)).unwrap();
    let asked = Settings { trigger: Some("comment:99".into()), ..settings(1) };
    let (id, step) = start(&store, &hub, &young, "e2", 1, "o/r", 7, &asked).unwrap();
    assert_eq!((id.as_str(), step.outcome), ("e2", Outcome::More), "a /review comment opens its own job");
    let rerun = Settings { trigger: Some("rerun:5".into()), ..settings(1) };
    assert_eq!(start(&store, &hub, &young, "e3", 1, "o/r", 7, &rerun).unwrap().0, "e3", "so does a Re-run");
}
