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
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::agent::{Agent, Finish, Next};
use crate::attest::{Attestation, Summary};
use crate::receipt::{proven_claims, receipt_v2, subject_commitment, turn_hash, Evidence};
use crate::repo::Repo;
use crate::review::{check_submission, commentable_lines, merge_findings, render_review, spec, system_prompt, user_prompt};
use crate::store::{put, remove, take, Store};

/// The largest reply a hosted turn may take: about 150 s at measured speeds,
/// so one turn always fits in a run.
pub const HOSTED_REPLY_CAP: u64 = 4_096;
/// Another turn starts only this early in a run.
pub const NEW_TURN_BEFORE_SECS: u64 = 30;
/// A turn whose run was killed is retried this many times before the job fails.
pub const TURN_RETRIES: u64 = 2;

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
}

/// What the caller learns.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    More,
    Done,
    Skipped,
    Failed(&'static str),
}

/// A run's outcome and what it attests.
#[derive(Debug)]
pub struct Step {
    pub outcome: Outcome,
    pub attests: Map<String, Value>,
}

impl Step {
    fn plain(outcome: Outcome) -> Self {
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
            Outcome::Failed(category) => {
                out.insert("failed".into(), json!(category));
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

const CHECK: &str = "Private Investigator";

/// Notes a run in the job: its call id and its output, for the receipt.
fn record_run(state: &mut Value, run: &dyn Run, job: &str, step: &Step) {
    if !state["runs"].is_array() {
        state["runs"] = json!([]);
    }
    state["runs"].as_array_mut().expect("array").push(json!({ "call_id": run.call_id(), "output": step.to_json(job) }));
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
            forge.check_run(None, &json!({ "name": CHECK, "head_sha": head, "status": "completed", "conclusion": "neutral", "output": { "title": "Monthly free reviews used", "summary": summary } }))?;
            let mut step = Step::plain(Outcome::Skipped);
            step.attests.insert("capped".into(), json!(true));
            return Ok((job.to_string(), step));
        }
        store.set(&mine, (used + 1).to_string().as_bytes())?;
        store.set(&all, (used_all + 1).to_string().as_bytes())?;
    }
    let check = if settings.dry { None } else { Some(forge.check_run(None, &json!({ "name": CHECK, "head_sha": head, "status": "queued", "output": { "title": "On the case", "summary": "Queued for a private review." } }))?) };
    let step = Step::plain(Outcome::More);
    let mut state = json!({
        "installation": installation, "repo": repo, "number": number, "pr": pr, "check_run": check,
        "model": settings.model, "passes": settings.passes, "max_turns": settings.max_turns,
        "allow_unpatched_model": settings.allow_unpatched_model,
        "dry": settings.dry, "caller": settings.caller,
        "salt": hex::encode(crate::random::<16>()),
        "marker": marker,
        "in_flight": 0,
    });
    record_run(&mut state, run, job, &step);
    put(store, &key(job), &state)?;
    store.set(&marker, json!({ "job": job, "at": run.now().0 }).to_string().as_bytes())?;
    Ok((job.to_string(), step))
}

fn summary_json(s: &Summary) -> Value {
    json!({ "tcb": s.tcb, "advisories": s.advisories, "signer": s.signer, "compose_hash": s.compose_hash })
}

fn summary_from(v: &Value) -> Summary {
    let text = |k: &str| v[k].as_str().unwrap_or("").to_string();
    Summary { tcb: text("tcb"), advisories: v["advisories"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect(), signer: text("signer"), compose_hash: text("compose_hash") }
}

/// The earlier inline findings of this reviewer on the pull request.
fn earlier_findings(forge: &dyn Forge, number: u64) -> Result<Vec<Value>> {
    let headings: Vec<String> = std::iter::once(format!("**{}**", spec()["name"].as_str().unwrap_or("")))
        .chain(spec()["legacy_headings"].as_array().into_iter().flatten().filter_map(|h| h.as_str().map(String::from)))
        .collect();
    let ours: Vec<u64> = forge
        .reviews(number)?
        .iter()
        .filter(|r| r["body"].as_str().is_some_and(|b| headings.iter().any(|h| b.starts_with(h.as_str()))))
        .filter_map(|r| r["id"].as_u64())
        .collect();
    if ours.is_empty() {
        return Ok(vec![]);
    }
    let mut seen = std::collections::HashSet::new();
    Ok(forge
        .review_comments(number)?
        .into_iter()
        .filter(|c| c["pull_request_review_id"].as_u64().is_some_and(|id| ours.contains(&id)))
        .map(|c| json!({ "path": c["path"], "body": c["body"] }))
        .filter(|f| seen.insert(format!("{}\n{}", f["path"], f["body"])))
        .collect())
}

/// The installation and repository a stored job belongs to, so the caller can
/// build its GitHub client before the step.
pub struct Owner {
    pub installation: u64,
    pub repo: String,
    pub caller: String,
}

pub fn owner(store: &dyn Store, job: &str) -> Result<Option<Owner>> {
    Ok(take(store, &key(job))?.map(|s| Owner {
        installation: s["installation"].as_u64().unwrap_or(0),
        repo: s["repo"].as_str().unwrap_or("").to_string(),
        caller: s["caller"].as_str().unwrap_or("").to_string(),
    }))
}

/// Where a published receipt is read, and the link a review gives to check it:
/// the fragment carries the salt and subject, which never reach a server.
pub fn check_link(project: &str, sha: &str, salt: &str, subject: &Value) -> String {
    let checker = spec()["checker_url"].as_str().unwrap_or("");
    let subject = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::canonical(subject));
    format!("{checker}&receipt={sha}&project={project}&salt={salt}&subject={subject}")
}

/// One run's worth of the job.
pub fn step(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str) -> Result<Step> {
    let Some(mut state) = take(store, &key(job))? else { bail!("unknown job") };
    let number = state["number"].as_u64().unwrap_or(0);

    // First step: gather, attest, set up the passes.
    if state["attestation"].is_null() {
        let pr = &state["pr"];
        let base = pr["base"]["sha"].as_str().unwrap_or("").to_string();
        let files = forge.files(number)?;
        let mut rubric = Vec::new();
        for path in ["REVIEW.md", "AGENTS.md"] {
            if let Some(text) = forge.text(path, &base)? {
                rubric.push(format!("## {path}\n\n{text}"));
            }
        }
        let rubric = if rubric.is_empty() { spec()["default_rubric"].as_str().unwrap_or("").to_string() } else { rubric.join("\n\n") };
        let earlier = earlier_findings(forge, number)?;
        let model_name = state["model"].as_str().unwrap_or("").to_string();
        let (evidence, attestation) = model.attest(&model_name, state["allow_unpatched_model"] == true).map_err(|_| anyhow!("attestation"))?;
        let agents: Vec<Value> = (0..state["passes"].as_u64().unwrap_or(1))
            .map(|_| Agent::new(&system_prompt(&rubric), &user_prompt(pr, &files, &earlier), state["max_turns"].as_u64().unwrap_or(30)).with_reply_cap(HOSTED_REPLY_CAP).to_json())
            .collect();
        state["commentable"] = json!(commentable_lines(&files));
        state["agents"] = Value::Array(agents.clone());
        state["results"] = Value::Array(vec![Value::Null; agents.len()]);
        state["evidence"] = json!({ "nonce": evidence.nonce, "report": evidence.report, "gpu_token": evidence.gpu_token, "allow_unpatched_model": evidence.allow_unpatched_model });
        state["attestation"] = json!({ "gateway": summary_json(&attestation.gateway), "model": summary_json(&attestation.model.summary), "public_key": attestation.model.public_key });
        if let Some(check) = state["check_run"].as_u64() {
            forge.check_run(Some(check), &json!({ "status": "in_progress", "output": { "title": "Following leads", "summary": "Reviewing inside an attested enclave." } }))?;
        }
        // The nonce this run generated binds the evidence in the receipt to this run.
        let mut step = Step::plain(Outcome::More);
        step.attests.insert("nonce".into(), json!(evidence.nonce));
        record_run(&mut state, run, job, &step);
        put(store, &key(job), &state)?;
        return Ok(step);
    }

    // Review steps: turns while the run is young.
    let mut taken: Vec<Value> = Vec::new();
    if state["results"].as_array().is_some_and(|r| r.iter().any(Value::is_null)) {
        let tree = Repo::from_tarball(&forge.tarball(state["pr"]["head"]["sha"].as_str().unwrap_or(""))?).map_err(|_| anyhow!("the head commit could not be read"))?;
        let submit = spec()["submit_tool"].clone();
        let check = |args: &Value| check_submission(args);
        let finish = Finish { tool: &submit, check: &check };
        let model_name = state["model"].as_str().unwrap_or("").to_string();
        let public_key = state["attestation"]["public_key"].as_str().unwrap_or("").to_string();
        let mut first = true;
        while first || run.elapsed() < NEW_TURN_BEFORE_SECS {
            let Some(i) = state["results"].as_array().and_then(|r| r.iter().position(Value::is_null)) else { break };
            // A run killed mid-turn leaves this mark behind; the turn is retried, a few times.
            let strikes = state["in_flight"].as_u64().unwrap_or(0);
            if strikes > TURN_RETRIES {
                bail!("a model turn did not finish within a run");
            }
            state["in_flight"] = json!(strikes + 1);
            put(store, &key(job), &state)?;

            let mut agent = Agent::from_json(&state["agents"][i])?;
            let before = agent.turns.len();
            let next = model.turn(&mut agent, &model_name, &public_key, &Repo::definitions(), &finish, &mut |name, args| tree.call(name, args))?;
            taken.extend(agent.turns[before..].iter().map(|t| json!(turn_hash(t))));
            state["agents"][i] = agent.to_json();
            if let Next::Finished(result) = next {
                state["results"][i] = result;
            }
            state["in_flight"] = json!(0);
            put(store, &key(job), &state)?;
            first = false;
        }
        if state["results"].as_array().is_some_and(|r| r.iter().any(Value::is_null)) {
            let mut step = Step::plain(Outcome::More);
            step.attests.insert("turns".into(), Value::Array(taken));
            record_run(&mut state, run, job, &step);
            put(store, &key(job), &state)?;
            return Ok(step);
        }
    }

    // Last step: the receipt, then the review.
    let results = state["results"].as_array().cloned().unwrap_or_default();
    let findings: Vec<Value> = results.iter().map(|r| r["findings"].clone()).collect();
    let review = json!({ "summary": results.first().map(|r| r["summary"].clone()).unwrap_or(Value::Null), "findings": merge_findings(&findings) });
    // New findings only: earlier ones still open are counted in the review, not here.
    let tally = review["findings"].as_array().map_or(0, |f| f.iter().filter(|f| f["earlier"] != true).count());
    // Passes run one after another, so pass order is the order the runs took the turns in.
    let all_turns: Vec<Value> = state["agents"].as_array().into_iter().flatten().flat_map(|a| a["turns"].as_array().cloned().unwrap_or_default()).collect();
    let e = &state["evidence"];
    let evidence = Evidence {
        nonce: e["nonce"].as_str().unwrap_or("").into(),
        report: e["report"].clone(),
        gpu_token: e["gpu_token"].as_str().unwrap_or("").into(),
        allow_unpatched_model: e["allow_unpatched_model"] == true,
    };
    let pr = &state["pr"];
    let subject = json!({ "pull_request": format!("{}#{number}", state["repo"].as_str().unwrap_or("")), "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"] });
    let salt = state["salt"].as_str().unwrap_or("").to_string();
    let commitment = subject_commitment(&salt, &subject);
    let project = run.project().unwrap_or_default();
    let mut runs = state["runs"].as_array().cloned().unwrap_or_default();
    runs.push(json!({ "call_id": run.call_id() }));
    let outlayer = json!({ "project": project, "runs": runs, "findings": tally });
    let (secs, millis) = run.now();
    let model_name = state["model"].as_str().unwrap_or("").to_string();
    let (text, sha) = receipt_v2(&commitment, &model_name, &evidence, &all_turns, &crate::iso_time(secs, millis), &outlayer);
    store.publish(&format!("receipt:{sha}"), text.as_bytes())?;

    // The last run attests every turn no recorded run did: its own, and any
    // taken by a run that was cut off before it could answer (a turn saved,
    // then the run killed). Each still carries the model enclave's signature.
    // Counted, not deduplicated: each attested turn accounts for one receipt turn.
    let mut attested: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for hash in state["runs"].as_array().into_iter().flatten().flat_map(|r| r["output"]["turns"].as_array().cloned().unwrap_or_default()) {
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
    if state["dry"] == true {
        remove(store, &key(job))?;
        return Ok(step);
    }

    let a = &state["attestation"];
    let mut proof = vec![(
        "Reader".to_string(),
        "Fetched from GitHub and read only by Private Investigator's published build, in attested OutLayer enclaves. The receipt lists every run's attestation, which names the exact build.".to_string(),
    )];
    proof.extend(proven_claims(&model_name, &summary_from(&a["model"]), &summary_from(&a["gateway"]), all_turns.len()));
    let commentable: Vec<String> = state["commentable"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(String::from)).collect();
    let link = check_link(&project, &sha, &salt, &subject);
    let posted = render_review(&review, &proof, &sha, None, Some(&link), &commentable);
    forge.review(number, &json!({ "commit_id": pr["head"]["sha"], "event": "COMMENT", "body": posted["body"], "comments": posted["comments"] }))?;
    forge.check_run(state["check_run"].as_u64(), &json!({
        "status": "completed", "conclusion": "neutral",
        "output": { "title": if tally == 0 { "Case closed: nothing to report".to_string() } else { format!("Case closed: {tally} lead{}", if tally == 1 { "" } else { "s" }) }, "summary": format!("Receipt sha256 `{sha}`: [check it]({link}).") },
    }))?;
    remove(store, &key(job))?;
    Ok(step)
}

/// Runs a step and turns any failure into a fixed category: the job is marked
/// failed and the check run says so, from inside the enclave.
pub fn run_step(store: &dyn Store, forge: &dyn Forge, model: &dyn Model, run: &dyn Run, job: &str) -> Step {
    match step(store, forge, model, run, job) {
        Ok(step) => step,
        Err(e) => {
            let category: &'static str = match e.to_string().as_str() {
                "unknown job" => "unknown job",
                "attestation" => "attestation",
                m if m.starts_with("GitHub") => "github",
                m if m.starts_with("NEAR AI") || m.contains("signature") || m.contains("signed") => "model",
                m if m.starts_with("nothing submitted") => "no submission",
                m if m.contains("did not finish within a run") => "turn too long",
                _ => "internal",
            };
            if let Ok(Some(state)) = take(store, &key(job)) {
                let text = match category {
                    "attestation" => "Attestation failed, so no code was sent to the model.",
                    _ => "The review stopped before it finished. No code left the enclave.",
                };
                if let Some(check) = state["check_run"].as_u64() {
                    let _ = forge.check_run(Some(check), &json!({ "status": "completed", "conclusion": "neutral", "output": { "title": "Review stopped", "summary": format!("{text} ({category})") } }));
                }
                // A failed review may be asked for again at once.
                if let Some(marker) = state["marker"].as_str() {
                    let _ = store.delete(marker);
                }
                let _ = remove(store, &key(job));
            }
            Step::plain(Outcome::Failed(category))
        }
    }
}
