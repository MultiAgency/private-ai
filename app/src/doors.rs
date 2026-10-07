//! The two ways into a review, as one OutLayer run receives them, and who may
//! use each. The GitHub App's relay sends ids from an event (`{"event": …}`,
//! then `{"step": id}`); a connector-style caller names an operation
//! (`status`, `review_start`, `review_step`). Only the author (the account
//! whose secrets the build reads) opens reviews, since they run on its NEAR AI
//! key; only a job's caller steps it. Every answer is ids, flags and a fixed
//! category: never a repository name, a path or code.
use anyhow::Result;
use serde_json::{json, Value};

use crate::failure::Failure;
use crate::job::{self, Forge, Model, Outcome, Run, Settings, Step};
use crate::store::Store;

/// GitHub before there is a job: how a run reaches a repository.
pub trait Installations {
    /// The repository `repo_id` as the App's `installation` sees it, with its name.
    fn by_id(&self, installation: u64, repo_id: u64) -> Result<(String, Box<dyn Forge + '_>)>;
    /// A repository by name, as `installation` sees it, or (installation 0)
    /// with the author's own token, or none for a public repository.
    fn by_name(&self, installation: u64, repo: &str) -> Result<Box<dyn Forge + '_>>;
}

/// What a run has to work with.
pub struct Host<'a> {
    pub store: &'a dyn Store,
    pub model: &'a dyn Model,
    pub run: &'a dyn Run,
    pub github: &'a dyn Installations,
}

/// Accounts whose own repositories review without the free tier's limits: the
/// author's organization, whose NEAR AI key pays for every review anyway, so
/// its own use neither stops at a cap nor draws on the pool others share
/// (owner, 2026-10-07). The name is GitHub's, read inside the enclave.
const UNCAPPED: &[&str] = &["MultiAgency"];

fn refused(category: &str) -> Value {
    json!({ "failed": category, "more": false })
}

fn failed(job: &str, category: &str) -> Value {
    json!({ "failed": category, "job": job, "more": false })
}

/// Settings for a review the author asks for: the defaults, on the author's key.
fn settings(caller: &str, dry: bool, passes: Option<u64>) -> Settings {
    let defaults = crate::review::defaults();
    Settings {
        model: defaults.model,
        passes: passes.unwrap_or(defaults.passes).clamp(1, 5),
        max_turns: defaults.max_turns,
        allow_unpatched_model: false,
        dry,
        caller: caller.to_string(),
        caps: None,
        trigger: None,
    }
}

/// One run's answer to its input. `caller` is who OutLayer says called (the
/// payment key's owner); `author` is the account whose secrets this build reads.
pub fn dispatch(input: &Value, caller: &str, author: Option<&str>, host: &Host) -> Value {
    let may_open = author.is_some_and(|a| a == caller);
    match input["operation"].as_str() {
        Some("status") => json!({ "name": "Private Investigator", "operations": ["status", "review_start", "review_step"], "version": env!("CARGO_PKG_VERSION") }),
        Some("review_start") if !may_open => refused("not allowed"),
        Some("review_start") => match (input["repo"].as_str(), input["pr"].as_u64()) {
            (Some(repo), Some(pr)) => {
                let job = host.run.job_id();
                let opened = host.github.by_name(0, repo).and_then(|forge| job::start(host.store, forge.as_ref(), host.run, &job, 0, repo, pr, &settings(caller, input["dry"] == true, input["passes"].as_u64())));
                answer(&job, opened)
            }
            _ => refused("bad input"),
        },
        Some("review_step") => match input["job"].as_str() {
            Some(id) => step(id, caller, host),
            None => refused("bad input"),
        },
        Some(_) => refused("unknown operation"),
        None if input.get("event").is_some() && !may_open => refused("not allowed"),
        None if input.get("event").is_some() => event(&input["event"], caller, host),
        None => match input["step"].as_str() {
            Some(id) => step(id, caller, host),
            None => refused("bad input"),
        },
    }
}

/// A review a GitHub event asks for, read from GitHub by its ids (never from
/// the event, which the relay could alter).
fn event(event: &Value, caller: &str, host: &Host) -> Value {
    let (Some(installation), Some(repo_id), Some(pr)) = (event["installation"].as_u64(), event["repo_id"].as_u64(), event["pr"].as_u64()) else {
        return refused("bad event");
    };
    let job = host.run.job_id();
    // A later push: no review unless asked, and the check on its commit says how.
    if event["push"] == true {
        let noted = host.github.by_id(installation, repo_id).and_then(|(_, forge)| job::note_unreviewed(forge.as_ref(), pr));
        return answer(&job, noted.map(|step| (job.clone(), step)));
    }
    let opened = host.github.by_id(installation, repo_id).and_then(|(name, forge)| {
        // A `/review` comment starts a review only for someone who can write to the repository.
        if let Some(comment) = event["comment"].as_u64() {
            if !forge.may_review(pr, comment)? {
                return Ok((job.clone(), Step::plain(Outcome::Skipped)));
            }
        }
        let trigger = event["comment"].as_u64().map(|c| format!("comment:{c}")).or_else(|| event["rerun"].as_u64().map(|r| format!("rerun:{r}")));
        // App installations review on the author's NEAR AI key, within the free tier.
        let owner = name.split('/').next().unwrap_or("");
        let caps = if UNCAPPED.iter().any(|u| u.eq_ignore_ascii_case(owner)) { None } else { Some(job::FREE_TIER) };
        let settings = Settings { caps, trigger, ..settings(caller, false, None) };
        job::start(host.store, forge.as_ref(), host.run, &job, installation, &name, pr, &settings)
    });
    answer(&job, opened)
}

/// One run of a job, for the caller who opened it.
fn step(id: &str, caller: &str, host: &Host) -> Value {
    match job::owner(host.store, id) {
        Ok(Some(owner)) if owner.caller != caller => failed(id, "not your job"),
        Ok(Some(owner)) => match host.github.by_name(owner.installation, &owner.repo) {
            Ok(forge) => job::run_step(host.store, forge.as_ref(), host.model, host.run, id).to_json(id),
            Err(e) => failed(id, Failure::of(&e).category()),
        },
        Ok(None) => failed(id, Failure::UnknownJob.category()),
        Err(e) => failed(id, Failure::of(&e).category()),
    }
}

fn answer(job: &str, opened: Result<(String, Step)>) -> Value {
    match opened {
        Ok((id, step)) => step.to_json(&id),
        Err(e) => failed(job, Failure::of(&e).category()),
    }
}
