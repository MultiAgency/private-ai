//! The job's world inside the enclave: OutLayer's sealed storage, GitHub as an
//! installation sees it, NEAR AI Cloud, and the run's clock.
use anyhow::Result;
use serde_json::Value;

use crate::agent::{Agent, Finish, Next};
use crate::attest::Attestation;
use crate::doors::Installations;
use crate::failure::{Failure, Mark};
use crate::github;
use crate::job::{Forge, Model, Run};
use crate::net::NearAi;
use crate::receipt::Evidence;

#[cfg(feature = "outlayer")]
pub struct Sealed;

#[cfg(feature = "outlayer")]
impl crate::store::Store for Sealed {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        outlayer::storage::get(key).map_err(|_| Failure::Storage.into())
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        outlayer::storage::set(key, value).map_err(|_| Failure::Storage.into())
    }
    fn delete(&self, key: &str) -> Result<()> {
        outlayer::storage::delete(key).map(|_| ()).map_err(|_| Failure::Storage.into())
    }
    fn publish(&self, key: &str, value: &[u8]) -> Result<()> {
        outlayer::storage::set_worker_with_options(key, value, Some(false)).map_err(|_| Failure::Storage.into())
    }
}

impl Forge for github::Repo {
    fn pull(&self, number: u64) -> Result<Value> {
        github::Repo::pull(self, number).mark(Failure::GitHub)
    }
    fn files(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::files(self, number).mark(Failure::GitHub)
    }
    fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>> {
        github::Repo::text(self, path, git_ref).mark(Failure::GitHub)
    }
    fn tarball(&self, sha: &str) -> Result<Vec<u8>> {
        github::Repo::tarball(self, sha).mark(Failure::GitHub)
    }
    fn reviews(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::reviews(self, number).mark(Failure::GitHub)
    }
    fn review_comments(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::review_comments(self, number).mark(Failure::GitHub)
    }
    fn review(&self, number: u64, body: &Value) -> Result<()> {
        github::Repo::review(self, number, body).mark(Failure::GitHub)
    }
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        github::Repo::check_run(self, id, body).mark(Failure::GitHub)
    }
    fn may_review(&self, number: u64, comment: u64) -> Result<bool> {
        github::Repo::may_review(self, number, comment).mark(Failure::GitHub)
    }
}

/// GitHub as the App's installations see it, with the App's key; installation
/// 0 is the author's own token (or none, for a public repository).
pub struct GitHubApp {
    /// The App's id and private key (PEM).
    pub app: Option<(String, String)>,
    pub author_token: Option<String>,
}

impl GitHubApp {
    fn token(&self, installation: u64) -> Result<String> {
        if installation == 0 {
            return Ok(self.author_token.clone().unwrap_or_default());
        }
        let Some((app, key)) = &self.app else { return Err(Failure::GitHub.into()) };
        github::installation_token(app, key, installation, crate::net::now_seconds()).mark(Failure::GitHub)
    }
}

impl Installations for GitHubApp {
    fn by_id(&self, installation: u64, repo_id: u64) -> Result<(String, Box<dyn Forge + '_>)> {
        let token = self.token(installation)?;
        let name = github::repo_name(&token, repo_id).mark(Failure::GitHub)?;
        Ok((name.clone(), Box::new(github::Repo::new(token, name))))
    }
    fn by_name(&self, installation: u64, repo: &str) -> Result<Box<dyn Forge + '_>> {
        Ok(Box::new(github::Repo::new(self.token(installation)?, repo)))
    }
}

/// GitHub for a rehearsal (the eval's dry run): one pull request as it stood
/// at a pinned commit, with that commit's description and no earlier reviews.
/// What the job would write to GitHub is kept here instead of sent.
pub struct Rehearsal {
    repo: github::Repo,
    pr: Value,
    files: Vec<Value>,
    pub posted: std::cell::RefCell<Vec<Value>>,
}

impl Rehearsal {
    /// The pull request now, or (with `head`) as it was at that commit: its
    /// diff from the merge base with `base` (default: its base branch).
    pub fn new(repo: github::Repo, number: u64, head: Option<&str>, base: Option<&str>, description: Option<&str>) -> Result<Self> {
        let mut pr = repo.pull(number)?;
        if let Some(description) = description {
            pr["body"] = serde_json::json!(description);
        }
        let files = match head {
            Some(head) => {
                let from = base.or(pr["base"]["ref"].as_str()).ok_or_else(|| anyhow::anyhow!("no base"))?.to_string();
                let commits = repo.compare(&from, head)?;
                pr["base"]["sha"] = commits["merge_base_commit"]["sha"].clone();
                pr["head"]["sha"] = serde_json::json!(head);
                commits["files"].as_array().cloned().unwrap_or_default()
            }
            None => repo.files(number)?,
        };
        Ok(Self { repo, pr, files, posted: Default::default() })
    }
}

impl Forge for Rehearsal {
    fn pull(&self, _: u64) -> Result<Value> {
        Ok(self.pr.clone())
    }
    fn files(&self, _: u64) -> Result<Vec<Value>> {
        Ok(self.files.clone())
    }
    fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>> {
        self.repo.text(path, git_ref).mark(Failure::GitHub)
    }
    fn tarball(&self, sha: &str) -> Result<Vec<u8>> {
        self.repo.tarball(sha).mark(Failure::GitHub)
    }
    fn reviews(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![])
    }
    fn review_comments(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![])
    }
    fn review(&self, _: u64, body: &Value) -> Result<()> {
        self.posted.borrow_mut().push(body.clone());
        Ok(())
    }
    fn check_run(&self, id: Option<u64>, _: &Value) -> Result<u64> {
        Ok(id.unwrap_or(1))
    }
    fn may_review(&self, _: u64, _: u64) -> Result<bool> {
        Ok(false)
    }
}

impl Model for NearAi {
    fn attest(&self, model: &str, allow_unpatched_model: bool) -> Result<(Evidence, Attestation)> {
        NearAi::attest(self, model, allow_unpatched_model)
    }
    fn turn(&self, agent: &mut Agent, model: &str, public_key: &str, tools: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        self.agent_turn(agent, model, public_key, tools, finish, call).mark(Failure::Model)
    }
}

/// This run: the monotonic clock since it began, and what OutLayer tells it.
pub struct RunClock(u64);

impl RunClock {
    pub fn start() -> Self {
        Self(wasip2::clocks::monotonic_clock::now())
    }
}

impl Run for RunClock {
    fn elapsed(&self) -> u64 {
        (wasip2::clocks::monotonic_clock::now() - self.0) / 1_000_000_000
    }
    fn now(&self) -> (u64, u32) {
        let now = wasip2::clocks::wall_clock::now();
        (now.seconds, now.nanoseconds / 1_000_000)
    }
    fn call_id(&self) -> Option<String> {
        std::env::var("OUTLAYER_CALL_ID").ok().filter(|v| !v.is_empty())
    }
    fn project(&self) -> Option<String> {
        std::env::var("OUTLAYER_PROJECT_ID").ok().filter(|v| !v.is_empty())
    }
    fn memory_bytes(&self) -> Option<usize> {
        std::env::var("NEAR_MAX_MEMORY_MB").ok()?.parse::<usize>().ok().map(|mb| mb << 20)
    }
}
