//! The job's world inside the enclave: OutLayer's sealed storage, GitHub as an
//! installation sees it, NEAR AI Cloud, and the run's clock.
use anyhow::Result;
use serde_json::Value;

use crate::agent::{Agent, Finish, Next};
use crate::attest::Attestation;
use crate::github;
use crate::job::{Forge, Model, Run};
use crate::net::NearAi;
use crate::receipt::Evidence;

#[cfg(feature = "outlayer")]
pub struct Sealed;

#[cfg(feature = "outlayer")]
impl crate::store::Store for Sealed {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        outlayer::storage::get(key).map_err(|_| anyhow::anyhow!("storage read failed"))
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        outlayer::storage::set(key, value).map_err(|_| anyhow::anyhow!("storage write failed"))
    }
    fn delete(&self, key: &str) -> Result<()> {
        outlayer::storage::delete(key).map(|_| ()).map_err(|_| anyhow::anyhow!("storage delete failed"))
    }
    fn publish(&self, key: &str, value: &[u8]) -> Result<()> {
        outlayer::storage::set_worker_with_options(key, value, Some(false)).map_err(|_| anyhow::anyhow!("storage publish failed"))
    }
}

impl Forge for github::Repo {
    fn pull(&self, number: u64) -> Result<Value> {
        github::Repo::pull(self, number)
    }
    fn files(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::files(self, number)
    }
    fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>> {
        github::Repo::text(self, path, git_ref)
    }
    fn tarball(&self, sha: &str) -> Result<Vec<u8>> {
        github::Repo::tarball(self, sha)
    }
    fn reviews(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::reviews(self, number)
    }
    fn review_comments(&self, number: u64) -> Result<Vec<Value>> {
        github::Repo::review_comments(self, number)
    }
    fn review(&self, number: u64, body: &Value) -> Result<()> {
        github::Repo::review(self, number, body)
    }
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        github::Repo::check_run(self, id, body)
    }
}

impl Model for NearAi {
    fn attest(&self, model: &str, allow_unpatched_model: bool) -> Result<(Evidence, Attestation)> {
        NearAi::attest(self, model, allow_unpatched_model)
    }
    fn turn(&self, agent: &mut Agent, model: &str, public_key: &str, tools: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        self.agent_turn(agent, model, public_key, tools, finish, call)
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
