//! Who may open and step a review, through either door (doors.rs), against
//! the fakes the job is tested with.
mod fakes;

use anyhow::Result;
use fakes::*;
use private_investigator::doors::{dispatch, Host, Installations};
use private_investigator::failure::Failure;
use private_investigator::job::Forge;
use private_investigator::store::Memory;
use serde_json::{json, Value};

/// GitHub before a job: one repository, `o/r`, seen as installation 1 or by
/// the author's token; or nothing at all.
struct Github {
    hub: Hub,
    down: bool,
    /// The repository's full name, as GitHub gives it.
    name: &'static str,
}

impl Installations for Github {
    fn by_id(&self, _: u64, _: u64) -> Result<(String, Box<dyn Forge + '_>)> {
        if self.down {
            return Err(Failure::GitHub.into());
        }
        Ok((self.name.into(), Box::new(&self.hub)))
    }
    fn by_name(&self, _: u64, _: &str) -> Result<Box<dyn Forge + '_>> {
        if self.down {
            return Err(Failure::GitHub.into());
        }
        Ok(Box::new(&self.hub))
    }
}

const AUTHOR: &str = "hack.near";

fn github(hub: Hub) -> Github {
    Github { hub, down: false, name: "o/r" }
}

fn call(input: Value, caller: &str, github: &Github, store: &Memory) -> Value {
    let (model, run) = (model(), at(100));
    dispatch(&input, caller, Some(AUTHOR), &Host { store, model: &model, run: &run, github })
}

fn event(extra: Value) -> Value {
    let mut event = json!({ "installation": 1, "repo_id": 22, "pr": 7, "nonce": "n" });
    event.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    json!({ "event": event })
}

#[test]
fn only_the_author_opens_a_review_through_either_door() {
    let (gh, store) = (github(Hub::default()), Memory::default());
    assert_eq!(call(event(json!({})), "mallory.near", &gh, &store), json!({ "failed": "not allowed", "more": false }));
    assert_eq!(call(json!({ "operation": "review_start", "repo": "o/r", "pr": 7 }), "mallory.near", &gh, &store), json!({ "failed": "not allowed", "more": false }));
    assert!(gh.hub.checks.borrow().is_empty(), "nothing reached GitHub");
    assert!(store.keys().is_empty(), "nothing was stored, nothing counted against the free tier");
    assert_eq!(dispatch(&event(json!({})), AUTHOR, None, &Host { store: &store, model: &model(), run: &at(0), github: &gh })["failed"], "not allowed", "a build with no author opens nothing");

    let opened = call(event(json!({})), AUTHOR, &gh, &store);
    assert_eq!(opened["more"], true);
    assert_eq!(gh.hub.checks.borrow()[0]["body"]["status"], "queued");
    assert!(store.keys().iter().any(|k| k.starts_with("cap:")), "an App review counts against the free tier");
    let started = call(json!({ "operation": "review_start", "repo": "o/r", "pr": 7 }), AUTHOR, &github(Hub::default()), &Memory::default());
    assert_eq!(started["more"], true);
}

#[test]
fn only_the_caller_who_opened_a_job_steps_it() {
    let (gh, store) = (github(Hub::default()), Memory::default());
    let job = call(event(json!({})), AUTHOR, &gh, &store)["job"].as_str().unwrap().to_string();
    assert_eq!(call(json!({ "step": job }), "mallory.near", &gh, &store), json!({ "failed": "not your job", "job": job, "more": false }));
    assert_eq!(call(json!({ "operation": "review_step", "job": job }), "mallory.near", &gh, &store)["failed"], "not your job");
    assert_eq!(call(json!({ "step": job }), AUTHOR, &gh, &store)["more"], true, "the attest step");
    assert_eq!(call(json!({ "step": "nope" }), AUTHOR, &gh, &store), json!({ "failed": "unknown job", "job": "nope", "more": false }));
}

#[test]
fn a_review_comment_from_someone_who_cannot_write_is_skipped_before_anything_starts() {
    let (gh, store) = (github(Hub { refuse_comments: true, ..Hub::default() }), Memory::default());
    let out = call(event(json!({ "comment": 99 })), AUTHOR, &gh, &store);
    assert_eq!((out["more"].clone(), out["skipped"].clone()), (json!(false), json!(true)));
    assert!(gh.hub.checks.borrow().is_empty() && store.keys().is_empty());
}

#[test]
fn a_deliberate_request_is_a_new_review_and_a_repeated_event_is_not() {
    let (gh, store) = (github(Hub::default()), Memory::default());
    let first = call(event(json!({})), AUTHOR, &gh, &store)["job"].clone();
    assert_eq!(call(event(json!({})), AUTHOR, &gh, &store)["job"], first, "a redelivery continues the same job");
    assert_ne!(call(event(json!({ "comment": 99 })), AUTHOR, &gh, &store)["job"], first, "a /review starts its own");
    assert_ne!(call(event(json!({ "rerun": 5 })), AUTHOR, &gh, &store)["job"], first, "so does a Re-run");
}

#[test]
fn failures_come_back_as_categories() {
    let (down, store) = (Github { hub: Hub::default(), down: true, name: "o/r" }, Memory::default());
    let out = call(event(json!({})), AUTHOR, &down, &store);
    assert_eq!((out["failed"].clone(), out["more"].clone()), (json!("github"), json!(false)));
    assert_eq!(call(json!({ "event": { "installation": 1 } }), AUTHOR, &down, &store), json!({ "failed": "bad event", "more": false }));
    assert_eq!(call(json!({ "operation": "review_start" }), AUTHOR, &down, &store), json!({ "failed": "bad input", "more": false }));
    assert_eq!(call(json!({ "operation": "rm -rf" }), AUTHOR, &down, &store), json!({ "failed": "unknown operation", "more": false }));
    assert_eq!(call(json!(null), AUTHOR, &down, &store), json!({ "failed": "bad input", "more": false }));
    assert_eq!(call(json!({ "operation": "status" }), "anyone.near", &down, &store)["name"], "Private Investigator", "status is open to all");
}

#[test]
fn a_later_push_gets_a_check_saying_how_to_ask_and_costs_no_review() {
    let (gh, store) = (github(Hub::default()), Memory::default());
    let out = call(event(json!({ "push": true })), AUTHOR, &gh, &store);
    assert_eq!((out["more"].clone(), out["skipped"].clone()), (json!(false), json!(true)));
    let check = gh.hub.checks.borrow()[0]["body"].clone();
    assert_eq!((check["status"].clone(), check["output"]["title"].clone()), (json!("completed"), json!("Not reviewed: new commits")));
    assert!(check["output"]["summary"].as_str().unwrap().contains("/review"));
    assert!(store.keys().is_empty(), "no job, and nothing counted against the free tier");
    assert_eq!(call(event(json!({ "push": true })), "mallory.near", &gh, &store)["failed"], "not allowed");
}

#[test]
fn the_checks_say_what_the_free_tier_has_left() {
    let (gh, store) = (github(Hub::default()), Memory::default());
    call(event(json!({})), AUTHOR, &gh, &store);
    let queued = gh.hub.checks.borrow()[0]["body"]["output"]["summary"].as_str().unwrap().to_string();
    assert!(queued.ends_with("9 of 10 free reviews left this month."), "{queued}");
}

#[test]
fn multiagencys_own_repositories_review_outside_the_free_tier() {
    let (gh, store) = (Github { hub: Hub::default(), down: false, name: "MultiAgency/private-investigator-test" }, Memory::default());
    assert_eq!(call(event(json!({})), AUTHOR, &gh, &store)["more"], true);
    assert!(!store.keys().iter().any(|k| k.starts_with("cap:")), "nothing counted, against the installation or the pool");
    assert!(!gh.hub.checks.borrow()[0]["body"]["output"]["summary"].as_str().unwrap().contains("free reviews left"));
    // A look-alike name is someone else's.
    let (other, store) = (Github { hub: Hub::default(), down: false, name: "MultiAgency-fan/repo" }, Memory::default());
    call(event(json!({})), AUTHOR, &other, &store);
    assert!(store.keys().iter().any(|k| k.starts_with("cap:")));
}
