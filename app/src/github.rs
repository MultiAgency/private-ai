//! The GitHub calls a review makes, from inside the enclave. Port of
//! `review/github.mjs`, with one rule the Action does not need: an error names
//! the operation and the status, never a path, since paths carry repository
//! names and errors leave the enclave.
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use wasip2::http::types::Method;

use crate::net::{request, Response};

const API: &str = "https://api.github.com";
const CODELOAD: &str = "https://codeload.github.com/";

/// An installation token for the App, valid for an hour.
pub fn installation_token(issuer: &str, private_key_pem: &str, installation_id: u64, now: u64) -> Result<String> {
    let jwt = crate::jwt::app_token(issuer, private_key_pem, now)?;
    let response = send(&jwt, Method::Post, &format!("{API}/app/installations/{installation_id}/access_tokens"), None, "application/vnd.github+json", "installation token")?;
    let body: Value = serde_json::from_slice(&response.body)?;
    body["token"].as_str().map(String::from).ok_or_else(|| anyhow!("GitHub installation token: no token returned"))
}

/// A repository's full name from its id, as the installation sees it. The
/// relay sends ids only, so the name is learned here, inside the enclave.
pub fn repo_name(token: &str, repo_id: u64) -> Result<String> {
    let response = send(token, Method::Get, &format!("{API}/repositories/{repo_id}"), None, "application/vnd.github+json", "repository")?;
    let repo: Value = serde_json::from_slice(&response.body)?;
    repo["full_name"].as_str().map(String::from).ok_or_else(|| anyhow!("GitHub repository: no name returned"))
}

fn send(token: &str, method: Method, url: &str, body: Option<&Value>, accept: &str, operation: &str) -> Result<Response> {
    let mut headers = vec![
        ("accept", accept.to_string()),
        ("x-github-api-version", "2022-11-28".to_string()),
        ("user-agent", "private-investigator".to_string()),
        ("content-type", "application/json".to_string()),
    ];
    // No token reads public repositories anonymously (a dry run's test path).
    if !token.is_empty() {
        headers.push(("authorization", format!("Bearer {token}")));
    }
    let bytes = body.map(|b| serde_json::to_vec(b)).transpose()?;
    let response = request(method, url, &headers, bytes.as_deref()).map_err(|_| anyhow!("GitHub {operation}: request failed"))?;
    if !(200..400).contains(&response.status) {
        bail!("GitHub {operation}: {}", response.status);
    }
    Ok(response)
}

/// One repository, as one installation token sees it.
pub struct Repo {
    token: String,
    repo: String,
}

impl Repo {
    pub fn new(token: impl Into<String>, repo: impl Into<String>) -> Self {
        Self { token: token.into(), repo: repo.into() }
    }

    fn get(&self, path: &str, operation: &str) -> Result<Value> {
        let response = send(&self.token, Method::Get, &format!("{API}/repos/{}{path}", self.repo), None, "application/vnd.github+json", operation)?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    fn all(&self, path: &str, operation: &str) -> Result<Vec<Value>> {
        let mut items = Vec::new();
        for page in 1.. {
            let batch = self.get(&format!("{path}?per_page=100&page={page}"), operation)?;
            let batch = batch.as_array().cloned().unwrap_or_default();
            let full = batch.len() == 100;
            items.extend(batch);
            if !full || page >= 30 {
                break;
            }
        }
        Ok(items)
    }

    pub fn pull(&self, number: u64) -> Result<Value> {
        self.get(&format!("/pulls/{number}"), "pull request")
    }

    /// The diff between two refs, with the merge base: how an earlier head of a
    /// pull request is reviewed as it was then.
    pub fn compare(&self, base: &str, head: &str) -> Result<Value> {
        self.get(&format!("/compare/{base}...{head}"), "compare")
    }

    pub fn files(&self, number: u64) -> Result<Vec<Value>> {
        self.all(&format!("/pulls/{number}/files"), "files")
    }

    pub fn reviews(&self, number: u64) -> Result<Vec<Value>> {
        self.all(&format!("/pulls/{number}/reviews"), "reviews")
    }

    pub fn review_comments(&self, number: u64) -> Result<Vec<Value>> {
        self.all(&format!("/pulls/{number}/comments"), "review comments")
    }

    /// A file's text at a commit, or `None` when it does not exist there.
    pub fn text(&self, path: &str, git_ref: &str) -> Result<Option<String>> {
        let encoded: Vec<String> = path.split('/').map(encode).collect();
        let url = format!("{API}/repos/{}/contents/{}?ref={git_ref}", self.repo, encoded.join("/"));
        match send(&self.token, Method::Get, &url, None, "application/vnd.github.raw+json", "file") {
            Ok(response) => Ok(Some(String::from_utf8_lossy(&response.body).into_owned())),
            Err(e) if e.to_string().ends_with(": 404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The commit's tarball. GitHub redirects to codeload, which is followed
    /// only there, with the token left behind.
    pub fn tarball(&self, sha: &str) -> Result<Vec<u8>> {
        let response = send(&self.token, Method::Get, &format!("{API}/repos/{}/tarball/{sha}", self.repo), None, "application/vnd.github+json", "tarball")?;
        if response.status == 200 {
            return Ok(response.body);
        }
        let location = response.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone());
        let Some(location) = location.filter(|l| l.starts_with(CODELOAD)) else {
            bail!("GitHub tarball: unexpected redirect");
        };
        let download = request(Method::Get, &location, &[("user-agent", "private-investigator".to_string())], None).map_err(|_| anyhow!("GitHub tarball: download failed"))?;
        if download.status != 200 {
            bail!("GitHub tarball: {}", download.status);
        }
        Ok(download.body)
    }

    pub fn review(&self, number: u64, body: &Value) -> Result<()> {
        send(&self.token, Method::Post, &format!("{API}/repos/{}/pulls/{number}/reviews", self.repo), Some(body), "application/vnd.github+json", "post review")?;
        Ok(())
    }

    /// Whether a comment is a `/review` on this pull request whose author may
    /// start a review: write access or more, as the Action's gate requires
    /// (review/gate.mjs). The relay passes only the comment's id, so all of it
    /// is read here.
    pub fn may_review(&self, number: u64, comment: u64) -> Result<bool> {
        let comment = self.get(&format!("/issues/comments/{comment}"), "comment")?;
        let on_this = comment["issue_url"].as_str().is_some_and(|u| u.ends_with(&format!("/repos/{}/issues/{number}", self.repo)));
        let asks = comment["body"].as_str().is_some_and(|b| b.trim_start().starts_with("/review"));
        let Some(login) = comment["user"]["login"].as_str().filter(|_| on_this && asks) else { return Ok(false) };
        let permission = match self.get(&format!("/collaborators/{}/permission", encode(login)), "permission") {
            Ok(p) => p,
            Err(e) if e.to_string().ends_with(": 404") => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(matches!(permission["role_name"].as_str(), Some("admin" | "maintain" | "write")))
    }

    /// Creates a check run on the head commit, or updates one by id.
    pub fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        let (method, url) = match id {
            Some(id) => (Method::Patch, format!("{API}/repos/{}/check-runs/{id}", self.repo)),
            None => (Method::Post, format!("{API}/repos/{}/check-runs", self.repo)),
        };
        let response = send(&self.token, method, &url, Some(body), "application/vnd.github+json", "check run")?;
        let run: Value = serde_json::from_slice(&response.body)?;
        run["id"].as_u64().ok_or_else(|| anyhow!("GitHub check run: no id returned"))
    }
}

/// `encodeURIComponent` for one path segment.
fn encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
