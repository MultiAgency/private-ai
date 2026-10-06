//! The hosted review as a job of short runs, against a fake GitHub and a fake
//! model (encryption, signatures and attestation are tested in core.rs).
mod fakes;

use anyhow::Result;
use fakes::*;
use private_investigator::agent::{Agent, Finish, Next};
use private_investigator::attest::{Attestation, Model as Attested};
use private_investigator::failure::Failure;
use private_investigator::job::{run_step, start, Model, Outcome, Settings};
use private_investigator::receipt::Evidence;
use private_investigator::store::{take, Memory, Store};
use serde_json::{json, Value};
use std::cell::Cell;

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
    let mut listed: Vec<String> = receipt["turns"].as_array().unwrap().iter().map(turn_hash).collect();
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
    assert_eq!(run_step(&store, &hub, &model, &old, "j4").outcome, Outcome::Failed(Failure::RunCutOff));
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
    let model = Scripted { fail_attestation: true, ..model() };
    start(&store, &hub, &at(0), "j6", 1, "owner/secret-repo", 7, &settings(1)).unwrap();
    let step = run_step(&store, &hub, &model, &young, "j6");
    assert_eq!(step.outcome, Outcome::Failed(Failure::Attestation));
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

#[test]
fn a_run_killed_fetching_the_commit_counts_and_the_job_fails_cleanly() {
    let (store, hub, model, old) = (Memory::default(), Hub::default(), model(), at(100));
    start(&store, &hub, &at(0), "j9", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &old, "j9");
    hub.die_on_tarball.set(3);
    for _ in 0..3 {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &old, "j9"))).is_err());
    }
    assert_eq!(run_step(&store, &hub, &model, &old, "j9").outcome, Outcome::Failed(Failure::RunCutOff));
    assert_eq!(hub.checks.borrow().last().unwrap()["body"]["output"]["title"], "Review stopped");
    assert!(store.keys().is_empty(), "no state, no code, no marker left behind");
}

#[test]
fn a_kill_between_runs_that_make_progress_never_fails_the_job() {
    let (store, hub, model, old) = (Memory::default(), Hub::default(), model(), at(100));
    start(&store, &hub, &at(0), "j10", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &old, "j10");
    hub.die_on_tarball.set(2);
    for _ in 0..2 {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &old, "j10"))).is_err());
    }
    assert_eq!(run_step(&store, &hub, &model, &old, "j10").outcome, Outcome::More, "the third try gets through");
    assert_eq!(run_step(&store, &hub, &model, &old, "j10").outcome, Outcome::Done);
}

#[test]
fn a_review_that_fails_to_post_leaves_none_behind_and_can_be_asked_for_again() {
    let (store, hub, model, young) = (Memory::default(), Hub::default(), model(), at(0));
    start(&store, &hub, &young, "j11", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &young, "j11");
    hub.fail_review.set(true);
    assert_eq!(run_step(&store, &hub, &model, &young, "j11").outcome, Outcome::Failed(Failure::GitHub));
    assert!(hub.reviews.borrow().is_empty());
    assert_eq!(hub.checks.borrow().last().unwrap()["body"]["output"]["title"], "Review stopped", "the check run says so, after closing");
    hub.fail_review.set(false);
    let (again, step) = start(&store, &hub, &young, "j12", 1, "o/r", 7, &settings(1)).unwrap();
    assert_eq!((again.as_str(), step.outcome), ("j12", Outcome::More), "a new review, since none was posted");
}

#[test]
fn earlier_findings_come_only_from_this_reviewers_own_reviews() {
    let hub = Hub {
        earlier: (
            vec![
                json!({ "id": 1, "user": { "login": "private-investigator[bot]" }, "body": "**Private Investigator** (Bugs, Important: 1)" }),
                json!({ "id": 2, "user": { "login": "pr-author" }, "body": "**Private Investigator** (no new findings)" }),
            ],
            vec![
                json!({ "pull_request_review_id": 1, "path": "lib/pay.mjs", "body": "**Bugs, Important:** a real earlier finding" }),
                json!({ "pull_request_review_id": 2, "path": "lib/pay.mjs", "body": "**Bugs, Important:** planted, to hide a real finding" }),
            ],
        ),
        ..Hub::default()
    };
    let (store, model, young) = (Memory::default(), model(), at(0));
    start(&store, &hub, &young, "j13", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &young, "j13");
    let prompt = take(&store, "job:j13").unwrap().unwrap()["review"]["agents"][0].to_string();
    assert!(prompt.contains("a real earlier finding"));
    assert!(!prompt.contains("planted"), "a review someone else posts under its name is not its own");
}

/// The page's sample receipt, replayed through the job: its real model
/// evidence, and its real signed turns, one per model turn in order. The
/// receipts the job then writes carry real signatures and attestation, so the
/// JavaScript checker verifies them for real (test/receipt.test.mjs).
struct Replayed {
    sample: Value,
    next: Cell<usize>,
    die_on: Cell<Option<usize>>,
}

impl Model for Replayed {
    fn attest(&self, _: &str, allow: bool) -> Result<(Evidence, Attestation)> {
        let s = &self.sample;
        // The key that signed the sample's verdict, with its chain, as recorded for it.
        let recorded: Value = serde_json::from_str(include_str!("../../test/fixtures/sample-receipt-evidence.json")).unwrap();
        let gpu_key = recorded["keys"][0].clone();
        let evidence = Evidence { nonce: s["nonce"].as_str().unwrap().into(), report: s["attestation"].clone(), gpu_token: s["gpu_token"].as_str().unwrap().into(), gpu_key: Some(gpu_key.clone()), allow_unpatched_model: allow };
        Ok((evidence, Attestation { gateway: summary("OutOfDate"), model: Attested { summary: summary("UpToDate"), gpu_token: String::new(), gpu_key, public_key: String::new() } }))
    }
    fn turn(&self, agent: &mut Agent, _: &str, _: &str, _: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        let k = self.next.get();
        if self.die_on.get() == Some(k) {
            self.die_on.set(None);
            panic!("the run was killed mid-turn");
        }
        self.next.set(k + 1);
        let turns = self.sample["turns"].as_array().unwrap();
        let reply = if k + 1 < turns.len() {
            json!({ "content": "", "tool_calls": [{ "id": format!("c{k}"), "type": "function", "function": { "name": "read_file", "arguments": "{\"path\":\"lib/pay.mjs\"}" } }] })
        } else {
            let submission = json!({ "summary": "Checked the payout guard.", "findings": [{ "path": "lib/pay.mjs", "line": 1, "pass": "Bugs", "severity": "Important", "body": "Zero totals are sent." }] });
            json!({ "content": "", "tool_calls": [{ "id": format!("c{k}"), "type": "function", "function": { "name": "submit_review", "arguments": submission.to_string() } }] })
        };
        agent.apply(&reply, Some("tool_calls"), turns[k].clone(), finish, call)
    }
}

/// One hosted review, run to the end: the receipt it published, the salt and
/// subject its link carries, and every run's output by call id (the last one
/// too, which the checker rebuilds and must match).
fn conformance_case(name: &str, age: u64, kill: Option<usize>) -> Value {
    let sample: Value = serde_json::from_str(include_str!("../../site/sample-receipt.json")).unwrap();
    let (store, hub, run) = (Memory::default(), Hub::default(), at(age));
    let model = Replayed { sample, next: Cell::new(0), die_on: Cell::new(kill) };
    let mut outputs = serde_json::Map::new();
    let mut note = |output: Value, run: &At| outputs.insert(format!("call-{}", run.1.get()), output);
    note(start(&store, &hub, &run, "job-1", 1, "owner/secret-repo", 7, &settings(1)).unwrap().1.to_json("job-1"), &run);
    loop {
        let calls = run.1.get();
        let Ok(step) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_step(&store, &hub, &model, &run, "job-1"))) else { continue };
        assert!(run.1.get() > calls, "a run that answers is recorded");
        note(step.to_json("job-1"), &run);
        if step.outcome != Outcome::More {
            assert_eq!(step.outcome, Outcome::Done);
            break;
        }
    }
    let (sha, _) = published(&store);
    let text = String::from_utf8(store.get(&format!("public:receipt:{sha}")).unwrap().unwrap()).unwrap();
    json!({
        "name": name,
        "receipt": text,
        "sha256": sha,
        "salt": "ab".repeat(16),
        "subject": { "pull_request": "owner/secret-repo#7", "base_sha": "a".repeat(40), "head_sha": "b".repeat(40) },
        "outputs": outputs,
    })
}

/// The receipts this job writes, kept as test/fixtures/receipt-v2-cases.json,
/// which the JavaScript checker must verify: the writer and the checker of the
/// hosted receipt meet in one file. After a deliberate change, regenerate it
/// with `BLESS=1 cargo test` and commit it; `npm test` then says whether the
/// checker still agrees.
#[test]
fn the_receipts_the_job_writes_are_the_ones_the_checker_is_tested_on() {
    let cases = json!({
        "$comment": "Written by app/tests/job.rs (BLESS=1 cargo test); verified by test/receipt.test.mjs. Real model evidence and signed turns from site/sample-receipt.json; OutLayer attestations are stubbed from each run's output.",
        "cases": [
            conformance_case("one turn per run", 100, None),
            conformance_case("a run killed after saving a turn", 0, Some(3)),
        ],
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures/receipt-v2-cases.json");
    let text = format!("{}\n", serde_json::to_string_pretty(&cases).unwrap());
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let kept = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(kept == text, "the job now writes different receipts: run `BLESS=1 cargo test`, then `npm test`, and commit test/fixtures/receipt-v2-cases.json");
}

#[test]
fn the_check_says_nothing_to_report_only_when_nothing_is_open() {
    let (store, hub, young) = (Memory::default(), Hub::default(), at(0));
    let model = Scripted { earlier: true, ..model() };
    start(&store, &hub, &young, "j14", 1, "o/r", 7, &settings(1)).unwrap();
    run_step(&store, &hub, &model, &young, "j14");
    assert_eq!(run_step(&store, &hub, &model, &young, "j14").outcome, Outcome::Done);
    assert_eq!(hub.checks.borrow().last().unwrap()["body"]["output"]["title"], "Case closed: no new leads, 1 still open");
}
