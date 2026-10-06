//! The fakes the job and the doors are tested against: GitHub as one
//! installation sees one repository, a scripted model, and a run's clock.
#![allow(dead_code)]
use anyhow::{bail, Result};
use private_investigator::agent::{Agent, Finish, Next};
use private_investigator::attest::{Attestation, Model as Attested, Summary};
use private_investigator::failure::Failure;
use private_investigator::job::{Forge, Model, Run, Settings};
use private_investigator::receipt::Evidence;
use private_investigator::store::{Memory, Store};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};

#[derive(Default)]
pub struct Hub {
    pub draft: bool,
    pub checks: RefCell<Vec<Value>>,
    pub reviews: RefCell<Vec<Value>>,
    /// Runs killed while fetching the head commit (out of memory, say).
    pub die_on_tarball: Cell<u32>,
    /// Posting a review fails (a GitHub outage).
    pub fail_review: Cell<bool>,
    /// Reviews already on the pull request, and their inline comments.
    pub earlier: (Vec<Value>, Vec<Value>),
    /// A `/review` comment's author can't write to the repository.
    pub refuse_comments: bool,
}

pub fn tarball() -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let data = b"export const pay = total => total >= 0 && send(total);\n";
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "o-r-abc/lib/pay.mjs", &data[..]).unwrap();
    b.into_inner().unwrap().finish().unwrap()
}

impl Forge for Hub {
    fn pull(&self, _: u64) -> Result<Value> {
        Ok(json!({ "number": 7, "title": "Pay", "body": "", "state": "open", "draft": self.draft, "base": { "ref": "main", "sha": "a".repeat(40) }, "head": { "ref": "pay", "sha": "b".repeat(40) } }))
    }
    fn files(&self, _: u64) -> Result<Vec<Value>> {
        Ok(vec![json!({ "filename": "lib/pay.mjs", "status": "modified", "additions": 1, "deletions": 1, "patch": "@@ -1,1 +1,1 @@\n-export const pay = total => total > 0 && send(total);\n+export const pay = total => total >= 0 && send(total);" })])
    }
    fn text(&self, _: &str, _: &str) -> Result<Option<String>> {
        Ok(None)
    }
    fn tarball(&self, _: &str) -> Result<Vec<u8>> {
        if self.die_on_tarball.get() > 0 {
            self.die_on_tarball.set(self.die_on_tarball.get() - 1);
            panic!("the run was killed fetching the head commit");
        }
        Ok(tarball())
    }
    fn reviews(&self, _: u64) -> Result<Vec<Value>> {
        Ok(self.earlier.0.clone())
    }
    fn review_comments(&self, _: u64) -> Result<Vec<Value>> {
        Ok(self.earlier.1.clone())
    }
    fn review(&self, _: u64, body: &Value) -> Result<()> {
        if self.fail_review.get() {
            // As the GitHub adapter marks its errors.
            return Err(Failure::GitHub.into());
        }
        self.reviews.borrow_mut().push(body.clone());
        Ok(())
    }
    fn check_run(&self, id: Option<u64>, body: &Value) -> Result<u64> {
        self.checks.borrow_mut().push(json!({ "id": id, "body": body }));
        Ok(id.unwrap_or(42))
    }
    fn may_review(&self, _: u64, _: u64) -> Result<bool> {
        Ok(!self.refuse_comments)
    }
}

/// Reads the file, then submits one finding, one turn each.
pub struct Scripted {
    pub fail_attestation: bool,
    pub die_on_turn: Cell<Option<u64>>,
    /// Its finding is one it posted before, still open.
    pub earlier: bool,
}

pub fn summary(tcb: &str) -> Summary {
    Summary { tcb: tcb.into(), advisories: vec![], signer: "5a".repeat(32), compose_hash: "94".repeat(32) }
}

impl Model for Scripted {
    fn attest(&self, _: &str, allow: bool) -> Result<(Evidence, Attestation)> {
        if self.fail_attestation {
            bail!("model: TCB status OutOfDate not accepted (repository owner/secret-repo)");
        }
        let evidence = Evidence { nonce: "00".repeat(32), report: json!({}), gpu_token: "t".into(), gpu_key: None, allow_unpatched_model: allow };
        Ok((evidence, Attestation { gateway: summary("OutOfDate"), model: Attested { summary: summary("UpToDate"), gpu_token: "t".into(), gpu_key: Value::Null, public_key: "5a".repeat(32) } }))
    }
    fn turn(&self, agent: &mut Agent, _: &str, _: &str, _: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        if self.die_on_turn.get() == Some(agent.turn + 1) {
            self.die_on_turn.set(None);
            panic!("the run was killed mid-turn");
        }
        let reply = if agent.turn == 0 {
            json!({ "content": "", "tool_calls": [{ "id": "c1", "type": "function", "function": { "name": "read_file", "arguments": "{\"path\":\"lib/pay.mjs\"}" } }] })
        } else {
            let read = agent.messages.iter().any(|m| m["role"] == "tool" && m["content"].as_str().unwrap_or("").contains(">= 0"));
            assert!(read, "the tool read the head commit");
            let submission = json!({ "summary": "Checked the payout guard.", "findings": [{ "path": "lib/pay.mjs", "line": 1, "pass": "Bugs", "severity": "Important", "body": "Zero totals are sent.", "earlier": self.earlier }] });
            json!({ "content": "", "tool_calls": [{ "id": "c2", "type": "function", "function": { "name": "submit_review", "arguments": submission.to_string() } }] })
        };
        let record = json!({ "id": format!("chat-{}", agent.turn + 1), "request_sha256": "", "response_sha256": "", "signature": {} });
        agent.apply(&reply, Some("tool_calls"), record, finish, call)
    }
}

/// A run at a given age; each run gets the next call id, and the same salt.
pub struct At(pub Cell<u64>, pub Cell<u64>);
impl Run for At {
    fn elapsed(&self) -> u64 {
        self.0.get()
    }
    fn now(&self) -> (u64, u32) {
        (1_791_103_153, 0)
    }
    fn call_id(&self) -> Option<String> {
        self.1.set(self.1.get() + 1);
        Some(format!("call-{}", self.1.get()))
    }
    fn project(&self) -> Option<String> {
        Some("hack.near/private-investigator".into())
    }
    fn salt(&self) -> [u8; 16] {
        [0xab; 16]
    }
}

pub fn at(age: u64) -> At {
    At(Cell::new(age), Cell::new(0))
}

pub fn settings(passes: u64) -> Settings {
    Settings { model: "z-ai/glm-5.3-flash".into(), passes, max_turns: 10, allow_unpatched_model: false, dry: false, caller: "alice.near".into(), caps: None, trigger: None }
}

pub fn model() -> Scripted {
    Scripted { fail_attestation: false, die_on_turn: Cell::new(None), earlier: false }
}

/// The published receipt (raw text) under `public:receipt:<sha>`.
pub fn published(store: &Memory) -> (String, Value) {
    let key = store.keys().into_iter().find(|k| k.starts_with("public:receipt:")).expect("a published receipt");
    let text = String::from_utf8(store.get(&key).unwrap().unwrap()).unwrap();
    (key["public:receipt:".len()..].to_string(), serde_json::from_str(&text).unwrap())
}

