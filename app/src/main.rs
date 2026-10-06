//! Private Investigator's entry point.
//!
//! In OutLayer (the default build): one run of a review job. `doors.rs` takes
//! the input (the App's relay events and steps, or connector-style operations)
//! and decides who may do what; this reads the environment OutLayer gives it
//! (the caller, the author's secrets) and prints the answer.
//!
//! Built with --no-default-features: a rehearsal of one pull request under
//! plain wasmtime (the eval's App runner): the hosted job itself, run after run,
//! with GitHub's writes kept rather than sent. It prints the review it would
//! have posted and writes the receipt. Input:
//! `{"repo": "owner/name", "pr": N, "head": "sha"?, "base": "sha"?, "description": "..."?,
//! "max_turns": 30?, "passes": N?, "receipt": "/out/receipt.json"?}`
//! with NEARAI_API_KEY and GITHUB_TOKEN (and MODEL, optionally).

/// What this build may reach and whose secret it reads, embedded in the wasm
/// so OutLayer enforces it and the on-chain hash covers it.
#[cfg(all(target_arch = "wasm32", feature = "outlayer"))]
#[used]
#[link_section = "outlayer.manifest"]
static MANIFEST: [u8; include_bytes!("../manifest.json").len()] = *include_bytes!("../manifest.json");

#[cfg(all(target_arch = "wasm32", feature = "outlayer"))]
fn main() {
    use private_investigator::doors::{dispatch, Host};
    use private_investigator::{host, net, secret_owner};
    use serde_json::{json, Value};

    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let mut input = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
    let input: Value = serde_json::from_str(&input).unwrap_or(Value::Null);
    let Some(nearai) = env("NEARAI_API_KEY") else {
        println!("{}", json!({ "failed": "configuration", "more": false }));
        return;
    };
    let github = host::GitHubApp { app: env("GITHUB_APP_ID").zip(env("GITHUB_APP_KEY")), author_token: env("GITHUB_TOKEN") };
    let host = Host { store: &host::Sealed, model: &net::NearAi::new(nearai), run: &host::RunClock::start(), github: &github };
    // OutLayer names the caller: the payment key's owner, or the transaction's signer.
    let caller = env("NEAR_SENDER_ID").unwrap_or_default();
    println!("{}", dispatch(&input, &caller, secret_owner(&MANIFEST).as_deref(), &host));
}

#[cfg(all(target_arch = "wasm32", not(feature = "outlayer")))]
fn main() -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    use private_investigator::failure::Failure;
    use private_investigator::host::{Rehearsal, RunClock};
    use private_investigator::job::{self, Outcome, Settings};
    use private_investigator::store::{Memory, Store};
    use private_investigator::{github, net};
    use serde_json::{json, Value};

    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let input: Value = serde_json::from_str(&input).context("input is not JSON")?;
    let (repo, number) = (input["repo"].as_str().context("repo")?, input["pr"].as_u64().context("pr")?);
    let gh = github::Repo::new(std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN")?, repo);
    let forge = Rehearsal::new(gh, number, input["head"].as_str(), input["base"].as_str(), input["description"].as_str())?;
    let model = net::NearAi::new(std::env::var("NEARAI_API_KEY").context("NEARAI_API_KEY")?);
    let store = Memory::default();
    let defaults = private_investigator::review::defaults();
    let settings = Settings {
        model: std::env::var("MODEL").unwrap_or(defaults.model),
        passes: input["passes"].as_u64().unwrap_or(defaults.passes).clamp(1, 5),
        max_turns: input["max_turns"].as_u64().unwrap_or(defaults.max_turns),
        allow_unpatched_model: false,
        dry: false,
        caller: String::new(),
        caps: None,
        trigger: None,
    };

    // The hosted job itself, run after run as OutLayer runs it, with GitHub's
    // writes kept by the rehearsal: the eval measures what the App ships.
    job::start(&store, &forge, &RunClock::start(), "rehearsal", 0, repo, number, &settings)?;
    for run in 1.. {
        let started = net::now_seconds();
        let step = job::run_step(&store, &forge, &model, &RunClock::start(), "rehearsal");
        eprintln!("run {run}: {}s", net::now_seconds() - started);
        match step.outcome {
            Outcome::More => continue,
            Outcome::Done => break,
            Outcome::Failed(failure) => bail!("the review stopped: {failure}"),
            Outcome::Skipped => bail!("the pull request is closed or a draft"),
        }
    }
    let key = store.keys().into_iter().find(|k| k.starts_with("public:receipt:")).ok_or(Failure::Internal)?;
    let text = String::from_utf8(store.get(&key)?.unwrap_or_default())?;
    let receipt: Value = serde_json::from_str(&text)?;
    if let Some(path) = input["receipt"].as_str() {
        std::fs::write(path, &text).context("writing the receipt")?;
    }
    let posted = forge.posted.borrow().first().cloned().context("no review posted")?;
    println!("{}", serde_json::to_string_pretty(&json!({
        "review": { "body": posted["body"], "comments": posted["comments"] },
        "findings": receipt["outlayer"]["findings"],
        "turns": receipt["turns"].as_array().map_or(0, Vec::len),
        "receipt_sha256": &key["public:receipt:".len()..],
    }))?);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("build for wasm32-wasip2: cargo build --release --target wasm32-wasip2");
}
