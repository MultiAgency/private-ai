//! One review as a job of short runs, for a host that stops every few minutes
//! (OutLayer: 180 s). `start` opens it from an event; each `step` loads the
//! sealed state, does what fits, saves, and says whether more remains. The
//! last step posts the review and publishes the receipt.
//!
//! Every run returns, besides the job id and whether to call again, what it
//! attests: the attestation nonce it fetched evidence under, the hashes of the
//! signed turns it took, and at the end the receipt's hash and the subject
//! commitment. OutLayer's attestation of each run binds that output to our
//! build, so the receipt (which lists every run) proves our code did the work.
//!
//! Errors that leave a run carry only a fixed category and the opaque job id:
//! repository names, paths and code stay in the sealed state and in GitHub.
use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::agent::{Agent, Finish, Next};
use crate::attest::{Attestation, Summary};
use crate::receipt::{proven_claims, receipt_v2, subject_commitment, turn_hash, Evidence};
use crate::failure::{Failure, Mark};
use crate::repo::Repo;
use crate::review::{check_submission, commentable_lines, is_our_review, merge_findings, own_findings, render_review, spec, system_prompt, user_prompt};
use crate::store::{put, remove, take, Store};

/// The largest reply a hosted turn may take: about 150 s at measured speeds,
/// so one turn always fits in a run.
pub const HOSTED_REPLY_CAP: u64 = 4_096;
/// Another turn starts only this early in a run.
pub const NEW_TURN_BEFORE_SECS: u64 = 30;
/// A step whose run was killed (out of memory, or past the run's time limit)
/// is retried this many times before the job fails.
pub const STEP_RETRIES: u64 = 2;

/// GitHub as one installation sees one repository.
pub trait Forge {
    fn pull(&self, number: u64) -> Result<Value>;
    fn files(&self, number: u64) -> Result<Vec<Value>>;
    fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>>;
    fn tarball(&self, sha: &str) -> Result<Vec<u8>>;
    fn reviews(&self, number: u64) -> Result<Vec<Value>>;
    fn review_comments(&self, number: u64) -> Result<Vec<Value>>;
    fn review(&self, number: u64, body: &Value) -> Result<()>;
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64>;
    /// Whether `comment` is a `/review` on this pull request by someone who can write to the repository.
    fn may_review(&self, number: u64, comment: u64) -> Result<bool>;
}

impl<F: Forge + ?Sized> Forge for &F {
    fn pull(&self, number: u64) -> Result<Value> {
        (**self).pull(number)
    }
    fn files(&self, number: u64) -> Result<Vec<Value>> {
        (**self).files(number)
    }
    fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>> {
        (**self).text(path, git_ref)
    }
    fn tarball(&self, sha: &str) -> Result<Vec<u8>> {
        (**self).tarball(sha)
    }
    fn reviews(&self, number: u64) -> Result<Vec<Value>> {
        (**self).reviews(number)
    }
    fn review_comments(&self, number: u64) -> Result<Vec<Value>> {
        (**self).review_comments(number)
    }
    fn review(&self, number: u64, body: &Value) -> Result<()> {
        (**self).review(number, body)
    }
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        (**self).check_run(id, body)
    }
    fn may_review(&self, number: u64, comment: u64) -> Result<bool> {
        (**self).may_review(number, comment)
    }
}

/// NEAR AI Cloud: attestation, and one signed turn of an agent.
pub trait Model {
    fn attest(&self, model: &str, allow_unpatched_model: bool) -> Result<(Evidence, Attestation)>;
    fn turn(&self, agent: &mut Agent, model: &str, public_key: &str, tools: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next>;
}

/// The run this is: its clock, and what OutLayer says about it.
pub trait Run {
    /// Seconds since the run began.
    fn elapsed(&self) -> u64;
    /// Wall clock: seconds and milliseconds.
    fn now(&self) -> (u64, u32);
    /// OutLayer's id for this call (HTTPS calls), which finds its attestation.
    fn call_id(&self) -> Option<String>;
    /// The project this runs as (`owner/name`), where its receipts are published.
    fn project(&self) -> Option<String>;
    /// The memory the run may use, when the host sets a limit.
    fn memory_bytes(&self) -> Option<usize> {
        None
    }
    /// The secret that opens a receipt's subject commitment, carried only by the review's link.
    fn salt(&self) -> [u8; 16] {
        crate::random()
    }
    /// A new job's id.
    fn job_id(&self) -> String {
        hex::encode(crate::random::<16>())
    }
}

/// What the caller learns.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    More,
    Done,
    Skipped,
    Failed(Failure),
}

/// A run's outcome and what it attests.
#[derive(Debug)]
pub struct Step {
    pub outcome: Outcome,
    pub attests: Map<String, Value>,
}

impl Step {
    pub(crate) fn plain(outcome: Outcome) -> Self {
        Self { outcome, attests: Map::new() }
    }

    /// The run's output, keys sorted: OutLayer hashes it as a JSON value with
    /// sorted keys, and receipts check that hash.
    pub fn to_json(&self, job: &str) -> Value {
        let mut out = self.attests.clone();
        out.insert("job".into(), json!(job));
        out.insert("more".into(), json!(self.outcome == Outcome::More));
        match self.outcome {
            Outcome::Skipped => {
                out.insert("skipped".into(), json!(true));
            }
            Outcome::Failed(failure) => {
                out.insert("failed".into(), json!(failure.category()));
            }
            _ => {}
        }
        crate::sorted(&Value::Object(out))
    }
}

pub struct Settings {
    pub model: String,
    pub passes: u64,
    pub max_turns: u64,
    pub allow_unpatched_model: bool,
    /// Review without writing to GitHub: no check run, no posted review.
    pub dry: bool,
    /// Who opened the job (the caller OutLayer names); only they may step it.
    pub caller: String,
    /// Free reviews on our NEAR AI key, per calendar month (App installations only).
    pub caps: Option<Caps>,
    /// What asked for this review beyond the pull request itself: a `/review`
    /// comment or a Re-run (`comment:<id>`, `rerun:<id>`). A deliberate request
    /// always runs; a repeat of the same automatic event does not.
    pub trigger: Option<String>,
}

/// A repeat of a review request within this long after its review finished is
/// a duplicate delivery (a retried webhook), not a new request.
pub const DUPLICATE_WINDOW_SECS: u64 = 600;

/// The free tier's monthly limits (owner, 2026-10-05: 10 per installation, $20
/// a month). The enclave does not see prices, so the budget is a count: a
/// 3-pass review is about 3 cents of inference plus about 10 OutLayer steps,
/// ~10 cents in all, so $20 is about 200 reviews.
pub struct Caps {
    pub per_installation: u64,
    pub global: u64,
}

pub const FREE_TIER: Caps = Caps { per_installation: 10, global: 200 };

fn count(store: &dyn Store, key: &str) -> Result<u64> {
    Ok(store.get(key)?.and_then(|v| String::from_utf8(v).ok()).and_then(|v| v.parse().ok()).unwrap_or(0))
}

fn key(job: &str) -> String {
    format!("job:{job}")
}


/// A job as sealed storage keeps it between runs. Its phase is `review`:
/// none before the first step has gathered and attested, then the passes, each
/// done once it has a result.
#[derive(serde::Serialize, serde::Deserialize)]
struct Job {
    installation: u64,
    repo: String,
    number: u64,
    pr: Value,
    check_run: Option<u64>,
    model: String,
    passes: u64,
    max_turns: u64,
    allow_unpatched_model: bool,
    dry: bool,
    caller: String,
    salt: String,
    marker: String,
    /// Runs since the last progress that never answered (killed). A run
    /// counts itself in as it starts; progress counts it out.
    in_flight: u64,
    /// Every run that answered: its call id and its output, for the receipt.
    runs: Vec<Value>,
    review: Option<Passes>,
}

/// What the first step sets up: the passes, and the attestation they rely on.
#[derive(serde::Serialize, serde::Deserialize)]
struct Passes {
    commentable: Vec<String>,
    agents: Vec<Value>,
    results: Vec<Option<Value>>,
    evidence: Evidence,
    gateway: Summary,
    model: Summary,
    public_key: String,
}

impl Passes {
    fn next(&self) -> Option<usize> {
        self.results.iter().position(Option::is_none)
    }
}

impl Job {
    fn load(store: &dyn Store, job: &str) -> Result<Option<Self>> {
        Ok(match take(store, &key(job))? {
            Some(state) => Some(serde_json::from_value(state)?),
            None => None,
        })
    }

    fn save(&self, store: &dyn Store, job: &str) -> Result<()> {
        put(store, &key(job), &serde_json::to_value(self)?)
    }

    /// Notes a run that answered, and its progress: it is no longer in flight.
    fn answered(&mut self, run: &dyn Run, job: &str, step: &Step) {
        self.in_flight = 0;
        self.runs.push(json!({ "call_id": run.call_id(), "output": step.to_json(job) }));
    }
}

/// Opens a job for a pull request, after reading it from GitHub (never from
/// the event, which the relay could alter). Drafts and closed pull requests are skipped.
/// Returns the job id the request belongs to (a new one, or the job already
/// handling this exact request) with the run's outcome.
pub fn start(store: &dyn Store, forge: &dyn Forge, run: &dyn Run, job: &str, installation: u64, repo: &str, number: u64, settings: &Settings) -> Result<(String, Step)> {
    let pr = forge.pull(number)?;
    if pr["state"] != "open" || pr["draft"] == true {
        return Ok((job.to_string(), Step::plain(Outcome::Skipped)));
    }
    let head = pr["head"]["sha"].as_str().ok_or_else(|| anyhow!("pull request has no head"))?.to_string();

    // One review per request: a retried or repeated delivery continues the job
    // already running, or is dropped if that job has just finished. The marker's
    // key is a hash, so storage keys name no repository.
    let marker = format!("request:{}", crate::sign::sha256(format!("{installation}:{repo}:{number}:{head}:{}", settings.trigger.as_deref().unwrap_or("")).as_bytes()));
    if let Some(previous) = store.get(&marker)?.and_then(|v| serde_json::from_slice::<Value>(&v).ok()) {
        let previous_job = previous["job"].as_str().unwrap_or("").to_string();
        if store.get(&key(&previous_job))?.is_some() {
            return Ok((previous_job, Step::plain(Outcome::More)));
        }
        if run.now().0.saturating_sub(previous["at"].as_u64().unwrap_or(0)) < DUPLICATE_WINDOW_SECS {
            let mut step = Step::plain(Outcome::Skipped);
            step.attests.insert("duplicate".into(), json!(true));
            return Ok((previous_job, step));
        }
    }
    if let (Some(caps), true) = (&settings.caps, installation > 0) {
        let month = &crate::iso_time(run.now().0, 0)[..7];
        let (mine, all) = (format!("cap:{month}:installation:{installation}"), format!("cap:{month}:all"));
        let (used, used_all) = (count(store, &mine)?, count(store, &all)?);
        if used >= caps.per_installation || used_all >= caps.global {
            let summary = if used >= caps.per_installation {
                format!("This installation has used its {} free reviews this month. Reviews resume on the 1st.", caps.per_installation)
            } else {
                "The free tier is at capacity this month. Reviews resume on the 1st.".to_string()
            };
            forge.check_run(None, &json!({ "name": spec()["name"], "head_sha": head, "status": "completed", "conclusion": "neutral", "output": { "title": "Monthly free reviews used", "summary": summary } }))?;
            let mut step = Step::plain(Outcome::Skipped);
            step.attests.insert("capped".into(), json!(true));
            return Ok((job.to_string(), step));
        }
        store.set(&mine, (used + 1).to_string().as_bytes())?;
        store.set(&all, (used_all + 1).to_string().as_bytes())?;
    }
    let check = if settings.dry { None } else { Some(forge.check_run(None, &json!({ "name": spec()["name"], "head_sha": head, "status": "queued", "output": { "title": "On the case", "summary": "Queued for a private review." } }))?) };
    let step = Step::plain(Outcome::More);
    let mut state = Job {
        installation,
        repo: repo.to_string(),
        number,
        pr,
        check_run: check,
        model: settings.model.clone(),
        passes: settings.passes,
        max_turns: settings.max_turns,
        allow_unpatched_model: settings.allow_unpatched_model,
        dry: settings.dry,
        caller: settings.caller.clone(),
        salt: hex::encode(run.salt()),
        marker: marker.clone(),
        in_flight: 0,
        runs: vec![],
        review: None,
    };
    state.answered(run, job, &step);
    state.save(store, job)?;
    store.set(&marker, json!({ "job": job, "at": run.now().0 }).to_string().as_bytes())?;
    Ok((job.to_string(), step))
}

/// The earlier inline findings of this reviewer on the pull request.
fn earlier_findings(forge: &dyn Forge, number: u64) -> Result<Vec<Value>> {
    let reviews = forge.reviews(number)?;
    Ok(if reviews.iter().any(is_our_review) { own_findings(&reviews, &forge.review_comments(number)?) } else { vec![] })
}

/// The installation and repository a stored job belongs to, so the caller can
/// build its GitHub client before the step.
pub struct Owner {
    pub installation: u64,
    pub repo: String,
    pub caller: String,
}

pub fn owner(store: &dyn Store, job: &str) -> Result<Option<Owner>> {
    Ok(Job::load(store, job)?.map(|s| Owner { installation: s.installation, repo: s.repo, caller: s.caller }))
}

/// Where a published receipt is read, and the link a review gives to check it:
/// the fragment carries the salt and subject, which never reach a server.
pub fn check_link(project: &str, sha: &str, salt: &str, subject: &Value) -> String {
    let checker = spec()["checker_url"].as_str().unwrap_or("");
    let subject = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::canonical(subject));
    format!("{checker}&receipt={sha}&project={project}&salt={salt}&subject={subject}")
}

/// One run's worth of the job: the phase it is in, then the run noted.
pub fn step(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str) -> Result<Step> {
    let Some(mut state) = Job::load(store, job)? else { return Err(Failure::UnknownJob.into()) };
    // A run killed before it answered leaves its count behind, wherever it
    // stopped: fetching, attesting, or mid-turn.
    if state.in_flight > STEP_RETRIES {
        return Err(Failure::RunCutOff.into());
    }
    state.in_flight += 1;
    state.save(store, job)?;

    let passes = match state.review.take() {
        None => return gather(store, forge, model, run, job, state),
        Some(passes) => passes,
    };
    let (passes, taken) = if passes.next().is_some() { take_turns(store, forge, model, run, job, &mut state, passes)? } else { (passes, vec![]) };
    if passes.next().is_some() {
        let mut step = Step::plain(Outcome::More);
        step.attests.insert("turns".into(), Value::Array(taken));
        state.review = Some(passes);
        state.answered(run, job, &step);
        state.save(store, job)?;
        return Ok(step);
    }
    finish(store, forge, run, job, state, passes)
}

/// The first step: gather the pull request, attest the model, set up the passes.
fn gather(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str, mut state: Job) -> Result<Step> {
    let base = state.pr["base"]["sha"].as_str().unwrap_or("").to_string();
    let files = forge.files(state.number)?;
    let mut rubric = Vec::new();
    for path in crate::review::defaults().rubric {
        if let Some(text) = forge.text(&path, &base)? {
            rubric.push(format!("## {path}\n\n{text}"));
        }
    }
    let rubric = if rubric.is_empty() { spec()["default_rubric"].as_str().unwrap_or("").to_string() } else { rubric.join("\n\n") };
    let earlier = earlier_findings(forge, state.number)?;
    let (evidence, attestation) = model.attest(&state.model, state.allow_unpatched_model).mark(Failure::Attestation)?;
    let agents: Vec<Value> = (0..state.passes)
        .map(|_| Agent::new(&system_prompt(&rubric), &user_prompt(&state.pr, &files, &earlier), state.max_turns).with_reply_cap(HOSTED_REPLY_CAP).to_json())
        .collect();
    if let Some(check) = state.check_run {
        forge.check_run(Some(check), &json!({ "status": "in_progress", "output": { "title": "Following leads", "summary": "Reviewing inside an attested enclave." } }))?;
    }
    // The nonce this run generated binds the evidence in the receipt to this run.
    let mut step = Step::plain(Outcome::More);
    step.attests.insert("nonce".into(), json!(evidence.nonce));
    state.review = Some(Passes {
        commentable: commentable_lines(&files),
        results: vec![None; agents.len()],
        agents,
        evidence,
        gateway: attestation.gateway,
        model: attestation.model.summary,
        public_key: attestation.model.public_key,
    });
    state.answered(run, job, &step);
    state.save(store, job)?;
    Ok(step)
}

/// Review steps: turns while the run is young. Each turn is saved as it is
/// taken; the hashes of those this run took come back for it to attest.
fn take_turns(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str, state: &mut Job, mut passes: Passes) -> Result<(Passes, Vec<Value>)> {
    // The tree shares the run's memory with its tarball, the job's state and the model's replies.
    let budget = run.memory_bytes().map_or(usize::MAX, |m| m / 4);
    let tarball = forge.tarball(state.pr["head"]["sha"].as_str().unwrap_or(""))?;
    let tree = Repo::from_tarball(&tarball, budget)?;
    drop(tarball);
    let submit = spec()["submit_tool"].clone();
    let check = |args: &Value| check_submission(args);
    let finish = Finish { tool: &submit, check: &check };
    let mut taken = Vec::new();
    let mut first = true;
    while first || run.elapsed() < NEW_TURN_BEFORE_SECS {
        let Some(i) = passes.next() else { break };
        let mut agent = Agent::from_json(&passes.agents[i])?;
        let before = agent.turns.len();
        let next = model.turn(&mut agent, &state.model, &passes.public_key, &Repo::definitions(), &finish, &mut |name, args| tree.call(name, args))?;
        taken.extend(agent.turns[before..].iter().map(|t| json!(turn_hash(t))));
        passes.agents[i] = agent.to_json();
        if let Next::Finished(result) = next {
            passes.results[i] = Some(result);
        }
        // A turn done: this run counts again only if it dies before the next.
        state.in_flight = 1;
        state.review = Some(passes);
        state.save(store, job)?;
        passes = state.review.take().expect("just set");
        first = false;
    }
    Ok((passes, taken))
}

/// The last step: the receipt, then the review.
fn finish(store: &dyn Store, forge: &dyn Forge, run: &dyn Run, job: &str, state: Job, passes: Passes) -> Result<Step> {
    let results: Vec<Value> = passes.results.into_iter().flatten().collect();
    let findings: Vec<Value> = results.iter().map(|r| r["findings"].clone()).collect();
    let review = json!({ "summary": results.first().map(|r| r["summary"].clone()).unwrap_or(Value::Null), "findings": merge_findings(&findings) });
    // New findings only: earlier ones still open are counted in the review, not here.
    let tally = review["findings"].as_array().map_or(0, |f| f.iter().filter(|f| f["earlier"] != true).count());
    // Passes run one after another, so pass order is the order the runs took the turns in.
    let all_turns: Vec<Value> = passes.agents.iter().flat_map(|a| a["turns"].as_array().cloned().unwrap_or_default()).collect();
    let pr = &state.pr;
    let subject = json!({ "pull_request": format!("{}#{}", state.repo, state.number), "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"] });
    let commitment = subject_commitment(&state.salt, &subject);
    let project = run.project().unwrap_or_default();
    let mut runs = state.runs.clone();
    runs.push(json!({ "call_id": run.call_id() }));
    let outlayer = json!({ "project": project, "runs": runs, "findings": tally });
    let (secs, millis) = run.now();
    let (text, sha) = receipt_v2(&commitment, &state.model, &passes.evidence, &all_turns, &crate::iso_time(secs, millis), &outlayer);
    store.publish(&format!("receipt:{sha}"), text.as_bytes())?;

    // The last run attests every turn no recorded run did: its own, and any
    // taken by a run that was cut off before it could answer (a turn saved,
    // then the run killed). Each still carries the model enclave's signature.
    // Counted, not deduplicated: each attested turn accounts for one receipt turn.
    let mut attested: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for hash in state.runs.iter().flat_map(|r| r["output"]["turns"].as_array().cloned().unwrap_or_default()) {
        if let Some(hash) = hash.as_str() {
            *attested.entry(hash.to_string()).or_default() += 1;
        }
    }
    let rest: Vec<Value> = all_turns
        .iter()
        .map(turn_hash)
        .filter(|h| match attested.get_mut(h) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .map(Value::String)
        .collect();
    let mut step = Step::plain(Outcome::Done);
    step.attests.insert("receipt_sha256".into(), json!(sha));
    step.attests.insert("subject_sha256".into(), json!(commitment));
    step.attests.insert("turns".into(), Value::Array(rest));
    step.attests.insert("findings".into(), json!(tally));
    if state.dry {
        remove(store, &key(job))?;
        return Ok(step);
    }

    let mut proof = vec![(
        "Reader".to_string(),
        "Fetched from GitHub and read only by Private Investigator's published build, in attested OutLayer enclaves. The receipt lists every run's attestation, which names the exact build.".to_string(),
    )];
    proof.extend(proven_claims(&state.model, &passes.model, &passes.gateway, all_turns.len()));
    let link = check_link(&project, &sha, &state.salt, &subject);
    let posted = render_review(&review, &proof, &sha, None, Some(&link), &passes.commentable);
    // The check run closes first and the review is the last write: if posting
    // fails, the job fails (and says so on the check run) with no review out,
    // so a retried request reviews again; once posted, nothing is left to fail.
    forge.check_run(state.check_run, &json!({
        "status": "completed", "conclusion": "neutral",
        "output": { "title": if tally == 0 { "Case closed: nothing to report".to_string() } else { format!("Case closed: {tally} lead{}", if tally == 1 { "" } else { "s" }) }, "summary": format!("Receipt sha256 `{sha}`: [check it]({link}).") },
    }))?;
    forge.review(state.number, &json!({ "commit_id": pr["head"]["sha"], "event": "COMMENT", "body": posted["body"], "comments": posted["comments"] }))?;
    let _ = remove(store, &key(job));
    Ok(step)
}

/// Runs a step and turns any failure into its kind (failure.rs): the job is
/// marked failed and the check run says so, from inside the enclave.
pub fn run_step(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str) -> Step {
    match step(store, forge, model, run, job) {
        Ok(step) => step,
        Err(e) => {
            let failure = Failure::of(&e);
            if let Ok(Some(state)) = Job::load(store, job) {
                if let Some(check) = state.check_run {
                    let _ = forge.check_run(Some(check), &json!({ "status": "completed", "conclusion": "neutral", "output": { "title": "Review stopped", "summary": format!("{} ({failure})", failure.explanation()) } }));
                }
                // A failed review may be asked for again at once.
                let _ = store.delete(&state.marker);
                let _ = remove(store, &key(job));
            }
            Step::plain(Outcome::Failed(failure))
        }
    }
}
