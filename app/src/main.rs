//! Private Investigator's entry point.
//!
//! In OutLayer (the default build): one run of a review job, through either door.
//! - The GitHub App's relay: `{"event": {"installation": N, "repo_id": N, "pr": N, "comment": N?, "rerun": N?, "nonce": "..."}}`,
//!   then `{"step": "<job id>"}`, with the App's key (GITHUB_APP_ID, GITHUB_APP_KEY).
//! - Operations, as a connector is called: `{"operation": "status"}`,
//!   `{"operation": "review_start", "repo": "owner/name", "pr": N, "dry": bool?, "passes": N?}`,
//!   then `{"operation": "review_step", "job": "<id>"}`, with the caller's own
//!   GITHUB_TOKEN, or none for a dry run on a public repository.
//! Only the author (manifest.json `author_secrets.owner`) may open a review,
//! through either door, since reviews run on the author's NEAR AI key; only the
//! job's caller may step it. Output is only the job id, whether to call
//! again, and on failure a category (a dry run ends with counts and the receipt
//! hash): never a repository name, a path or code. NEARAI_API_KEY is the
//! author's secret (manifest.json).
//!
//! Built with --no-default-features: a dry run of one pull request under plain
//! wasmtime, printing the findings and writing the receipt. Input:
//! `{"repo": "owner/name", "pr": N, "head": "sha"?, "base": "sha"?, "description": "..."?,
//! "max_turns": 30?, "reply_cap": N?, "passes": N?, "receipt": "/out/receipt.json"?}`
//! with NEARAI_API_KEY and GITHUB_TOKEN.

/// What this build may reach and whose secret it reads, embedded in the wasm
/// so OutLayer enforces it and the on-chain hash covers it.
#[cfg(all(target_arch = "wasm32", feature = "outlayer"))]
#[used]
#[link_section = "outlayer.manifest"]
static MANIFEST: [u8; include_bytes!("../manifest.json").len()] = *include_bytes!("../manifest.json");

#[cfg(all(target_arch = "wasm32", feature = "outlayer"))]
fn main() {
    use private_investigator::{github, host, job, net};
    use serde_json::{json, Value};

    fn env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    }
    fn failed(job: &str, category: &str) -> Value {
        json!({ "failed": category, "job": job, "more": false })
    }
    fn new_job() -> String {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("system randomness");
        hex::encode(id)
    }

    let clock = host::RunClock::start();
    let mut input = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
    let input: Value = serde_json::from_str(&input).unwrap_or(Value::Null);
    let Some(nearai) = env("NEARAI_API_KEY") else {
        println!("{}", json!({ "failed": "configuration", "more": false }));
        return;
    };
    let model = net::NearAi::new(nearai);
    let store = host::Sealed;
    // OutLayer names the caller: the payment key's owner, or the transaction's signer.
    let caller = env("NEAR_SENDER_ID").unwrap_or_default();
    // Reviews run on the author's NEAR AI key, so only the author opens them:
    // the relay calls with the author's payment key. Anyone may step their own job.
    let may_open = private_investigator::secret_owner(&MANIFEST).is_some_and(|owner| owner == caller);
    // A GitHub token for a job: the App's for an installation, else the caller's own (if any).
    let token = |installation: u64| -> anyhow::Result<String> {
        if installation == 0 {
            return Ok(env("GITHUB_TOKEN").unwrap_or_default());
        }
        let (Some(app), Some(key)) = (env("GITHUB_APP_ID"), env("GITHUB_APP_KEY")) else { anyhow::bail!("no App credential") };
        github::installation_token(&app, &key, installation, net::now_seconds())
    };
    let settings = |dry: bool, passes: Option<u64>| job::Settings {
        model: "z-ai/glm-5.3-flash".into(),
        passes: passes.unwrap_or(3).clamp(1, 5),
        max_turns: 30,
        allow_unpatched_model: false,
        dry,
        caller: caller.clone(),
        caps: None,
        trigger: None,
    };
    let step = |id: &str| match job::owner(&store, id) {
        Ok(Some(owner)) if owner.caller != caller => failed(id, "not your job"),
        Ok(Some(owner)) => match token(owner.installation) {
            Ok(t) => job::run_step(&store, &github::Repo::new(t, owner.repo), &model, &clock, id).to_json(id),
            Err(_) => failed(id, "github"),
        },
        Ok(None) => failed(id, "unknown job"),
        Err(_) => failed(id, "storage"),
    };

    let output = match input["operation"].as_str() {
        // Connector-style operations: the caller brings a GitHub token (or none, for a dry run on a public repository).
        Some("status") => json!({ "name": "Private Investigator", "operations": ["status", "review_start", "review_step"], "version": env!("CARGO_PKG_VERSION") }),
        Some("review_start") if !may_open => json!({ "failed": "not allowed", "more": false }),
        Some("review_start") => {
            let job = new_job();
            match (input["repo"].as_str(), input["pr"].as_u64()) {
                (Some(repo), Some(pr)) => {
                    let opened = token(0).and_then(|t| job::start(&store, &github::Repo::new(t, repo), &clock, &job, 0, repo, pr, &settings(input["dry"] == true, input["passes"].as_u64())));
                    opened.map(|(id, s)| s.to_json(&id)).unwrap_or_else(|_| failed(&job, "github"))
                }
                _ => json!({ "failed": "bad input", "more": false }),
            }
        }
        Some("review_step") => match input["job"].as_str() {
            Some(id) => step(id),
            None => json!({ "failed": "bad input", "more": false }),
        },
        Some(_) => json!({ "failed": "unknown operation", "more": false }),
        // The App's relay: ids from a GitHub event, then steps.
        None => {
            if input.get("event").is_some() && !may_open {
                json!({ "failed": "not allowed", "more": false })
            } else if let Some(event) = input.get("event") {
                let job = new_job();
                match (event["installation"].as_u64(), event["repo_id"].as_u64(), event["pr"].as_u64()) {
                    (Some(installation), Some(repo_id), Some(pr)) => {
                        let opened = token(installation).and_then(|t| {
                            let name = github::repo_name(&t, repo_id)?;
                            let repo = github::Repo::new(t, name.clone());
                            // A `/review` comment starts a review only for someone who can write to the repository.
                            if let Some(comment) = event["comment"].as_u64() {
                                if !repo.comment_author_may_review(comment)? {
                                    return Ok((job.clone(), job::Step { outcome: job::Outcome::Skipped, attests: Default::default() }));
                                }
                            }
                            let trigger = event["comment"].as_u64().map(|c| format!("comment:{c}")).or_else(|| event["rerun"].as_u64().map(|r| format!("rerun:{r}")));
                            // App installations review on our NEAR AI key, within the free tier.
                            job::start(&store, &repo, &clock, &job, installation, &name, pr, &job::Settings { caps: Some(job::FREE_TIER), trigger, ..settings(false, None) })
                        });
                        opened.map(|(id, s)| s.to_json(&id)).unwrap_or_else(|_| failed(&job, "github"))
                    }
                    _ => json!({ "failed": "bad event", "more": false }),
                }
            } else if let Some(id) = input["step"].as_str() {
                step(id)
            } else {
                json!({ "failed": "bad input", "more": false })
            }
        }
    };
    println!("{output}");
}

#[cfg(all(target_arch = "wasm32", not(feature = "outlayer")))]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use private_investigator::agent::{Agent, Finish, Next};
    use private_investigator::{github, iso_time, job::HOSTED_REPLY_CAP, net, receipt::receipt, repo::Repo, review};
    use serde_json::{json, Value};

    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let input: Value = serde_json::from_str(&input).context("input is not JSON")?;
    let (repo_name, number) = (input["repo"].as_str().context("repo")?, input["pr"].as_u64().context("pr")?);
    let model = std::env::var("MODEL").unwrap_or_else(|_| "z-ai/glm-5.3-flash".into());
    let gh = github::Repo::new(std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN")?, repo_name);
    let client = net::NearAi::new(std::env::var("NEARAI_API_KEY").context("NEARAI_API_KEY")?);

    let mut pr = gh.pull(number)?;
    // An earlier head is reviewed as it was then: its diff from the merge base.
    if let Some(description) = input["description"].as_str() {
        pr["body"] = json!(description);
    }
    let files = match input["head"].as_str() {
        Some(head) => {
            let from = input["base"].as_str().or(pr["base"]["ref"].as_str()).context("base")?.to_string();
            let commits = gh.compare(&from, head)?;
            pr["base"]["sha"] = commits["merge_base_commit"]["sha"].clone();
            pr["head"]["sha"] = json!(head);
            commits["files"].as_array().cloned().unwrap_or_default()
        }
        None => gh.files(number)?,
    };
    let head = pr["head"]["sha"].as_str().context("head sha")?.to_string();
    let base = pr["base"]["sha"].as_str().context("base sha")?.to_string();
    let mut rubric = Vec::new();
    for path in ["REVIEW.md", "AGENTS.md"] {
        if let Some(text) = gh.text(path, &base)? {
            rubric.push(format!("## {path}\n\n{text}"));
        }
    }
    let rubric = if rubric.is_empty() { review::spec()["default_rubric"].as_str().unwrap_or("").to_string() } else { rubric.join("\n\n") };
    let tree = Repo::from_tarball(&gh.tarball(&head)?, usize::MAX).map_err(|_| anyhow::anyhow!("the head commit could not be read"))?;
    eprintln!("#{number}: {} files changed, {} files in the head commit", files.len(), tree.file_count());

    let (evidence, attestation) = client.attest(&model, false).context("attestation failed, so no code was sent")?;
    let key = attestation.model.public_key.clone();
    eprintln!("attested: model {}, gateway {}", attestation.model.summary.tcb, attestation.gateway.tcb);

    let submit = review::spec()["submit_tool"].clone();
    let check = |args: &Value| review::check_submission(args);
    let finish = Finish { tool: &submit, check: &check };
    // As the hosted App runs, so the eval measures what it ships.
    let reply_cap = input["reply_cap"].as_u64().unwrap_or(HOSTED_REPLY_CAP);
    // Passes one after another, merged as the hosted job merges them.
    let mut results = Vec::new();
    let mut turns = Vec::new();
    for pass in 1..=input["passes"].as_u64().unwrap_or(1).clamp(1, 5) {
        let mut agent = Agent::new(&review::system_prompt(&rubric), &review::user_prompt(&pr, &files, &[]), input["max_turns"].as_u64().unwrap_or(30)).with_reply_cap(reply_cap);
        let result = loop {
            let started = net::now_seconds();
            match client.agent_turn(&mut agent, &model, &key, &Repo::definitions(), &finish, &mut |name, args| tree.call(name, args))? {
                Next::Finished(result) => break result,
                Next::Continue => eprintln!("pass {pass}, turn {}: {}s", agent.turn, net::now_seconds() - started),
            }
        };
        turns.extend(agent.turns);
        results.push(result);
    }
    let findings: Vec<Value> = results.iter().map(|r| r["findings"].clone()).collect();
    let result = json!({ "summary": results[0]["summary"], "findings": review::merge_findings(&findings) });
    eprintln!("reviewed: {} findings in {} signed turns", result["findings"].as_array().map_or(0, Vec::len), turns.len());

    let now = wasip2::clocks::wall_clock::now();
    let subject = json!({ "pull_request": format!("{repo_name}#{number}"), "base_sha": base, "head_sha": head });
    let (text, sha) = receipt(&subject, &model, &evidence, &turns, &iso_time(now.seconds, now.nanoseconds / 1_000_000));
    if let Some(path) = input["receipt"].as_str() {
        std::fs::write(path, &text).context("writing the receipt")?;
    }
    println!("{}", serde_json::to_string_pretty(&json!({ "review": result, "receipt_sha256": sha, "turns": turns.len() }))?);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("build for wasm32-wasip2: cargo build --release --target wasm32-wasip2");
}
